/* See LICENSE file for copyright and license details. */
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <tox/tox.h>
#include <tox/toxav.h>
#include <tox/toxencryptsave.h>

#include "arg.h"
#include "queue.h"
#include "readpassphrase.h"
#include "util.h"

const char *reqerr[] = {
	[-TOX_FAERR_TOOLONG]      = "Message is too long",
	[-TOX_FAERR_NOMESSAGE]    = "Please add a message to your request",
	[-TOX_FAERR_OWNKEY]       = "That appears to be your own ID",
	[-TOX_FAERR_ALREADYSENT]  = "Friend request already sent",
	[-TOX_FAERR_UNKNOWN]      = "Unknown error while sending your request",
	[-TOX_FAERR_BADCHECKSUM]  = "Bad checksum while verifying address",
	[-TOX_FAERR_SETNEWNOSPAM] = "Friend already added but nospam doesn't match",
	[-TOX_FAERR_NOMEM]        = "Error increasing the friend list size"
};

struct node {
	char *addr4;
	char *addr6;
	uint16_t port;
	char *idstr;
};

#include "config.h"

struct file {
	int type;
	const char *name;
	int flags;
};

enum {
	NONE,
	FIFO,
	STATIC,
	FOLDER
};

enum {
	IN,
	OUT,
	ERR,
};

static struct file gfiles[] = {
	[IN]      = { .type = FIFO,   .name = "in",  .flags = O_RDONLY | O_NONBLOCK,       },
	[OUT]     = { .type = NONE,   .name = "out", .flags = O_WRONLY | O_TRUNC | O_CREAT },
	[ERR]     = { .type = STATIC, .name = "err", .flags = O_WRONLY | O_TRUNC | O_CREAT },
};

static int idfd = -1;

struct slot {
	const char *name;
	void (*cb)(void *);
	int outisfolder;
	int dirfd;
	int fd[LEN(gfiles)];
};

static void setname(void *);
static void setstatus(void *);
static void sendfriendreq(void *);
static void setnospam(void *);

enum {
	NAME,
	STATUS,
	REQUEST,
	NOSPAM
};

static struct slot gslots[] = {
	[NAME]    = { .name = "name",	 .cb = setname,	      .outisfolder = 0, .dirfd = -1, .fd = {-1, -1, -1} },
	[STATUS]  = { .name = "status",	 .cb = setstatus,     .outisfolder = 0, .dirfd = -1, .fd = {-1, -1, -1} },
	[REQUEST] = { .name = "request", .cb = sendfriendreq, .outisfolder = 1, .dirfd = -1, .fd = {-1, -1, -1} },
	[NOSPAM]  = { .name = "nospam",  .cb = setnospam,     .outisfolder = 0, .dirfd = -1, .fd = {-1, -1, -1} }
};

enum {
	FTEXT_IN,
	FFILE_IN,
	FFILE_OUT,
	FREMOVE,
	FONLINE,
	FNAME,
	FSTATUS,
	FTEXT_OUT,
	FFILE_PENDING,
	FCALL_OUT,
	FCALL_PENDING,
};

static struct file ffiles[] = {
	[FTEXT_IN]      = { .type = FIFO,   .name = "text_in",      .flags = O_RDONLY | O_NONBLOCK         },
	[FFILE_IN]      = { .type = FIFO,   .name = "file_in",      .flags = O_RDONLY | O_NONBLOCK         },
	[FFILE_OUT]     = { .type = FIFO,   .name = "file_out",     .flags = O_WRONLY | O_NONBLOCK         },
	[FREMOVE]       = { .type = FIFO,   .name = "remove",       .flags = O_RDONLY | O_NONBLOCK         },
	[FONLINE]       = { .type = STATIC, .name = "online",       .flags = O_WRONLY | O_TRUNC  | O_CREAT },
	[FNAME]         = { .type = STATIC, .name = "name",         .flags = O_WRONLY | O_TRUNC  | O_CREAT },
	[FSTATUS]       = { .type = STATIC, .name = "status",       .flags = O_WRONLY | O_TRUNC  | O_CREAT },
	[FTEXT_OUT]     = { .type = STATIC, .name = "text_out",     .flags = O_WRONLY | O_APPEND | O_CREAT },
	[FFILE_PENDING] = { .type = STATIC, .name = "file_pending", .flags = O_WRONLY | O_TRUNC  | O_CREAT },
	[FCALL_OUT]     = { .type = FIFO,   .name = "call_out",     .flags = O_WRONLY | O_NONBLOCK         },
	[FCALL_PENDING] = { .type = STATIC, .name = "call_pending", .flags = O_WRONLY | O_TRUNC  | O_CREAT },
};

enum {
	TRANSFER_NONE,
	TRANSFER_INITIATED,
	TRANSFER_INPROGRESS,
	TRANSFER_PAUSED,
};

struct transfer {
	uint8_t fnum;
	uint8_t *buf;
	int chunksz;
	ssize_t n;
	int pendingbuf;
	int state;
};

struct call {
	ToxAvCallState state;
	int num;
};

struct friend {
	char name[TOX_MAX_NAME_LENGTH + 1];
	int32_t num;
	uint8_t id[TOX_CLIENT_ID_SIZE];
	char idstr[2 * TOX_CLIENT_ID_SIZE + 1];
	int dirfd;
	int fd[LEN(ffiles)];
	struct transfer tx;
	int rxstate;
	struct call av;
	TAILQ_ENTRY(friend) entry;
};

struct request {
	uint8_t id[TOX_CLIENT_ID_SIZE];
	char idstr[2 * TOX_CLIENT_ID_SIZE + 1];
	char *msg;
	int fd;
	TAILQ_ENTRY(request) entry;
};

static TAILQ_HEAD(friendhead, friend) friendhead = TAILQ_HEAD_INITIALIZER(friendhead);
static TAILQ_HEAD(reqhead, request) reqhead = TAILQ_HEAD_INITIALIZER(reqhead);

static Tox *tox;
static ToxAv *toxav;
static ToxAvCSettings toxavconfig;
static Tox_Options toxopt;
static uint8_t *passphrase;
static uint32_t pplen;
static volatile sig_atomic_t running = 1;
static int ipv6;
static int tcpflag;
static int proxyflag;

static void printrat(void);
static void printout(const char *, ...);
static void fiforeset(int, int *, struct file);
static ssize_t fiforead(int, int *, struct file, void *, size_t);
static void cbcallstarted(void *, int32_t, void *);
static void cbcallcancelled(void *, int32_t, void *);
static void cbcallrejected(void *, int32_t, void *);
static void cbcallended(void *, int32_t, void *);
static void cbcallinvite(void *, int32_t, void *);
static void cbcallringing(void *, int32_t, void *);
static void cbcallstarting(void *, int32_t, void *);
static void cbcallending(void *, int32_t, void *);
static void cbreqtimeout(void *, int32_t, void *);
static void cbpeertimeout(void *, int32_t, void *);
static void cbcalltypechange(void *, int32_t, void *);
static void cbcalldata(ToxAv *, int32_t, int16_t *, int, void *);
static void cancelrxcall(struct friend *, char *);
static void cbconnstatus(Tox *, int32_t, uint8_t, void *);
static void cbfriendmessage(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cbfriendrequest(Tox *, const uint8_t *, const uint8_t *, uint16_t, void *);
static void cbnamechange(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cbstatusmessage(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cbuserstatus(Tox *, int32_t, uint8_t, void *);
static void cbfilecontrol(Tox *, int32_t, uint8_t, uint8_t, uint8_t, const uint8_t *, uint16_t, void *);
static void cbfilesendreq(Tox *, int32_t, uint8_t, uint64_t, const uint8_t *, uint16_t, void *);
static void cbfiledata(Tox *, int32_t, uint8_t, const uint8_t *, uint16_t, void *);
static void canceltxtransfer(struct friend *);
static void cancelrxtransfer(struct friend *);
static void sendfriendfile(struct friend *);
static void sendfriendtext(struct friend *);
static void removefriend(struct friend *);
static int readpass(const char *);
static void dataload(void);
static void datasave(void);
static int localinit(void);
static int toxinit(void);
static int toxconnect(void);
static void id2str(uint8_t *, char *);
static void str2id(char *, uint8_t *);
static struct friend *friendcreate(int32_t);
static void friendload(void);
static void frienddestroy(struct friend *);
static void loop(void);
static void initshutdown(int);
static void shutdown(void);
static void usage(void);

static void
printrat(void)
{
	printf(	"\033[31m"
		"                /y\\            /y\\\n"
		"               /ver\\          /"VERSION"\\\n"
		"               yyyyyy\\      /yyyyyy\n"
		"               \\yyyyyyyyyyyyyyyyyy/\n"
		"                yyyyyyyyyyyyyyyyyy\n"
		"                yyyyyyyyyyyyyyyyyy\n"
		"                yyy'yyyyyyyyyy'yyy\n"
		"                \\yy  yyyyyyyy  yy/\n"
		"                 \\yy.yyyyyyyy.yy/\n"
		"                  \\yyyyyyyyyyyy/\n"
		"                    \\yyyyyyyy/\n"
		"              -------yyyyyyyy-------\n"
		"                 ..---yyyyyy---..\n"
		"                   ..--yyyy--..\n"
		"\033[0m\n");
}

static void
printout(const char *fmt, ...)
{
	va_list ap;
	char buft[64];
	time_t t;

	va_start(ap, fmt);
	t = time(NULL);
	strftime(buft, sizeof(buft), "%F %R", localtime(&t));
	printf("%s ", buft);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

static void
fiforeset(int dirfd, int *fd, struct file f)
{
	ssize_t r;

	unlinkat(dirfd, f.name, 0);
	if (*fd != -1)
		close(*fd);
	r = mkfifoat(dirfd, f.name, 0666);
	if (r < 0 && errno != EEXIST)
		eprintf("mkfifoat %s:", f.name);
	r = openat(dirfd, f.name, f.flags);
	if (r < 0 && errno != ENXIO)
		eprintf("openat %s:", f.name);
	*fd = r;
}

static ssize_t
fiforead(int dirfd, int *fd, struct file f, void *buf, size_t sz)
{
	ssize_t r;

again:
	r = read(*fd, buf, sz);
	if (r == 0) {
		fiforeset(dirfd, fd, f);
		return 0;
	}
	if (r < 0) {
		if (errno == EINTR)
			goto again;
		if (errno == EWOULDBLOCK)
			return -1;
		eprintf("read %s:", f.name);
	}
	return r;
}

static void
cbcallinvite(void *av, int32_t cnum, void *udata)
{
	ToxAvCSettings avconfig;
	struct friend *f;
	int32_t fnum;
	int r;

	fnum = toxav_get_peer_id(toxav, cnum, 0);
	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->num == fnum)
			break;
	if (!f)
		return;

	f->av.num = cnum;
	r = toxav_get_peer_csettings(toxav, cnum, 0, &avconfig);
	if (r < 0) {
		weprintf("Failed to determine peer call type\n");
		return;
	}

	switch (avconfig.call_type) {
	case TypeVideo:
		printout(": %s : Rx AV > Inviting with video\n", f->name);
		break;
	case TypeAudio:
		printout(": %s : Rx AV > Inviting without video\n", f->name);
		break;
	}

	printout(": %s : Rx AV > Audio call settings: srate = %lu, channels = %lu\n",
		 f->name, avconfig.audio_sample_rate, avconfig.audio_channels);

	ftruncate(f->fd[FCALL_PENDING], 0);
	dprintf(f->fd[FCALL_PENDING], "1\n");

	f->av.state = av_CallStarting;
}

static void
cbcallstarted(void *av, int32_t cnum, void *udata)
{
	struct friend *f;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->av.num == cnum)
			break;
	if (!f)
		return;

	printout(": %s : Rx AV > Started\n", f->name);

	toxav_prepare_transmission(toxav, cnum, av_jbufdc, av_VADd, 0);

	f->av.state = av_CallActive;
}

static void
cbcallended(void *av, int32_t cnum, void *udata)
{
	struct friend *f;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->av.num == cnum)
			break;
	if (!f)
		return;

	cancelrxcall(f, "Ended");
}

static void
cbcallcancelled(void *av, int32_t cnum, void *udata)
{
	struct friend *f;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->av.num == cnum)
			break;
	if (!f)
		return;

	cancelrxcall(f, "Cancelled");
}

static void
cbcallrejected(void *av, int32_t cnum, void *udata)
{
	printf("Entered %s\n", __func__);
}

static void
cbcallringing(void *av, int32_t cnum, void *udata)
{
	printf("Entered %s\n", __func__);
}

static void
cbcallstarting(void *av, int32_t cnum, void *udata)
{
	printf("Entered %s\n", __func__);
}

static void
cbcallending(void *av, int32_t cnum, void *udata)
{
	struct friend *f;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->av.num == cnum)
			break;
	if (!f)
		return;

	cancelrxcall(f, "Ending");
}

static void
cbreqtimeout(void *av, int32_t cnum, void *udata)
{
	printf("Entered %s\n", __func__);
}

static void
cbpeertimeout(void *av, int32_t cnum, void *udata)
{
	printf("Entered %s\n", __func__);
}

static void
cbcalltypechange(void *av, int32_t cnum, void *udata)
{
	printf("Entered %s\n", __func__);
}

static void
cbcalldata(ToxAv *av, int32_t cnum, int16_t *data, int len, void *udata)
{
	struct friend *f;
	uint8_t *buf;
	int wrote = 0;
	ssize_t n;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->av.num == cnum)
			break;
	if (!f)
		return;

	buf = (uint8_t *)data;
	len *= 2;
	while (len > 0) {
		n = write(f->fd[FCALL_OUT], &buf[wrote], len);
		if (n < 0) {
			if (errno == EPIPE) {
				toxav_hangup(toxav, f->av.num);
				break;
			} else if (errno == EWOULDBLOCK) {
				continue;
			}
			break;
		} else if (n == 0) {
			break;
		}
		wrote += n;
		len -= n;
	}
}

static void
cancelrxcall(struct friend *f, char *action)
{
	printout(": %s : Rx AV > %s\n", f->name, action);
	f->av.state = av_CallNonExistant;
	f->av.num = -1;
	if (f->fd[FCALL_OUT] != -1) {
		close(f->fd[FCALL_OUT]);
		f->fd[FCALL_OUT] = -1;
	}
	ftruncate(f->fd[FCALL_PENDING], 0);
	dprintf(f->fd[FCALL_PENDING], "0\n");
}

static void
cbconnstatus(Tox *m, int32_t frnum, uint8_t status, void *udata)
{
	struct friend *f;
	char name[TOX_MAX_NAME_LENGTH + 1];
	int r;

	r = tox_get_name(tox, frnum, (uint8_t *)name);
	if (r < 0)
		eprintf("Failed to get name for friend number %ld\n",
			(long)frnum);

	if (r == 0)
		snprintf(name, sizeof(name), "Anonymous");
	else
		name[r] = '\0';

	printout(": %s > %s\n", name, status == 0 ? "Offline" : "Online");

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->num == frnum) {
			ftruncate(f->fd[FONLINE], 0);
			dprintf(f->fd[FONLINE], "%d\n", status);
			return;
		}
	}

	friendcreate(frnum);
}

static void
cbfriendmessage(Tox *m, int32_t frnum, const uint8_t *data, uint16_t len, void *udata)
{
	struct friend *f;
	uint8_t msg[len + 1];
	char buft[64];
	time_t t;

	memcpy(msg, data, len);
	msg[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->num == frnum) {
			t = time(NULL);
			strftime(buft, sizeof(buft), "%F %R", localtime(&t));
			dprintf(f->fd[FTEXT_OUT], "%s %s\n", buft, msg);
			printout(": %s > %s\n", f->name, msg);
			break;
		}
	}
}

static void
cbfriendrequest(Tox *m, const uint8_t *id, const uint8_t *data, uint16_t len, void *udata)
{
	struct request *req;
	struct file reqfifo;

	req = calloc(1, sizeof(*req));
	if (!req)
		eprintf("calloc:");
	req->fd = -1;

	memcpy(req->id, id, TOX_CLIENT_ID_SIZE);
	id2str(req->id, req->idstr);

	if (len > 0) {
		req->msg = malloc(len + 1);
		if (!req->msg)
			eprintf("malloc:");
		memcpy(req->msg, data, len);
		req->msg[len] = '\0';
	}

	reqfifo.name = req->idstr;
	reqfifo.flags = O_RDONLY | O_NONBLOCK;
	fiforeset(gslots[REQUEST].fd[OUT], &req->fd, reqfifo);

	TAILQ_INSERT_TAIL(&reqhead, req, entry);

	printout("Request : %s > %s\n",
		 req->idstr, req->msg);
}

static void
cbnamechange(Tox *m, int32_t frnum, const uint8_t *data, uint16_t len, void *user)
{
	struct friend *f;
	uint8_t name[len + 1];

	memcpy(name, data, len);
	name[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->num == frnum) {
			if (memcmp(f->name, name, len + 1) == 0)
				break;
			ftruncate(f->fd[FNAME], 0);
			dprintf(f->fd[FNAME], "%s\n", name);
			printout(": %s : Name > %s\n", f->name, name);
			memcpy(f->name, name, len + 1);
			break;
		}
	}
	datasave();
}

static void
cbstatusmessage(Tox *m, int32_t frnum, const uint8_t *data, uint16_t len, void *udata)
{
	struct friend *f;
	uint8_t status[len + 1];

	memcpy(status, data, len);
	status[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->num == frnum) {
			ftruncate(f->fd[FSTATUS], 0);
			dprintf(f->fd[FSTATUS], "%s\n", status);
			printout(": %s : Status > %s\n", f->name, status);
			break;
		}
	}
	datasave();
}

static void
cbuserstatus(Tox *m, int32_t frnum, uint8_t status, void *udata)
{
	struct friend *f;
	char *statusstr[] = { "none", "away", "busy" };

	if (status >= LEN(statusstr)) {
		weprintf("Received invalid user status: %d\n", status);
		return;
	}

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->num == frnum) {
			printout(": %s : State > %s\n", f->name, statusstr[status]);
			break;
		}
	}
}

static void
cbfilecontrol(Tox *m, int32_t frnum, uint8_t rec_sen, uint8_t fnum, uint8_t ctrltype,
	const uint8_t *data, uint16_t len, void *udata)
{
	struct friend *f;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->num == frnum)
			break;
	if (!f)
		return;

	switch (ctrltype) {
	case TOX_FILECONTROL_ACCEPT:
		if (rec_sen == 1) {
			if (f->tx.state == TRANSFER_PAUSED) {
				printout(": %s : Tx > Resumed\n", f->name);
				f->tx.state = TRANSFER_INPROGRESS;
			} else {
				f->tx.fnum = fnum;
				f->tx.chunksz = tox_file_data_size(tox, fnum);
				f->tx.buf = malloc(f->tx.chunksz);
				if (!f->tx.buf)
					eprintf("malloc:");
				f->tx.n = 0;
				f->tx.pendingbuf = 0;
				f->tx.state = TRANSFER_INPROGRESS;
				printout(": %s : Tx > In Progress\n", f->name);
			}
		}
		break;
	case TOX_FILECONTROL_PAUSE:
		if (rec_sen == 1) {
			if (f->tx.state == TRANSFER_INPROGRESS) {
				printout(": %s : Tx > Paused\n", f->name);
				f->tx.state = TRANSFER_PAUSED;
			}
		}
		break;
	case TOX_FILECONTROL_KILL:
		if (rec_sen == 1) {
			printout(": %s : Tx > Rejected\n", f->name);
			f->tx.state = TRANSFER_NONE;
			free(f->tx.buf);
			f->tx.buf = NULL;
			fiforeset(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN]);
		} else {
			printout(": %s : Rx > Cancelled by Sender\n", f->name);
			cancelrxtransfer(f);
		}
		break;
	case TOX_FILECONTROL_FINISHED:
		if (rec_sen == 1) {
			printout(": %s : Tx > Complete\n", f->name);
			f->tx.state = TRANSFER_NONE;
			free(f->tx.buf);
			f->tx.buf = NULL;
		} else {
			printout(": %s : Rx > Complete\n", f->name);
			if (tox_file_send_control(tox, f->num, 1, 0, TOX_FILECONTROL_FINISHED, NULL, 0) < 0)
				weprintf("Failed to signal file completion to the sender\n");
			if (f->fd[FFILE_OUT] != -1) {
				close(f->fd[FFILE_OUT]);
				f->fd[FFILE_OUT] = -1;
			}
			ftruncate(f->fd[FFILE_PENDING], 0);
			f->rxstate = TRANSFER_NONE;
		}
		break;
	default:
		weprintf("Unhandled file control type: %d\n", ctrltype);
		break;
	};
}

static void
cbfilesendreq(Tox *m, int32_t frnum, uint8_t fnum, uint64_t fsz,
	      const uint8_t *fname, uint16_t flen, void *udata)
{
	struct friend *f;
	uint8_t filename[flen + 1];

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->num == frnum)
			break;
	if (!f)
		return;

	memcpy(filename, fname, flen);
	filename[flen] = '\0';

	/* We only support a single transfer at a time */
	if (f->rxstate == TRANSFER_INPROGRESS) {
		printout(": %s : Rx > Rejected %s, already one in progress\n",
			 f->name, filename);
		if (tox_file_send_control(tox, f->num, 1, fnum, TOX_FILECONTROL_KILL, NULL, 0) < 0)
			weprintf("Failed to kill new Rx transfer\n");
		return;
	}

	ftruncate(f->fd[FFILE_PENDING], 0);
	dprintf(f->fd[FFILE_PENDING], "%s\n", filename);
	f->rxstate = TRANSFER_INPROGRESS;
	printout(": %s : Rx > Pending %s\n", f->name, filename);
}

static void
cbfiledata(Tox *m, int32_t frnum, uint8_t fnum, const uint8_t *data, uint16_t len, void *udata)
{
	struct friend *f;
	uint16_t wrote = 0;
	ssize_t n;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->num == frnum)
			break;
	if (!f)
		return;

	while (len > 0) {
		n = write(f->fd[FFILE_OUT], &data[wrote], len);
		if (n < 0) {
			if (errno == EPIPE) {
				cancelrxtransfer(f);
				break;
			} else if (errno == EWOULDBLOCK) {
				continue;
			}
			break;
		} else if (n == 0) {
			break;
		}
		wrote += n;
		len -= n;
	}
}

static void
canceltxtransfer(struct friend *f)
{
	if (f->tx.state != TRANSFER_NONE) {
		printout(": %s : Tx > Cancelling\n", f->name);
		if (tox_file_send_control(tox, f->num, 0, 0, TOX_FILECONTROL_KILL, NULL, 0) < 0)
			weprintf("Failed to kill Tx transfer\n");
		f->tx.state = TRANSFER_NONE;
		free(f->tx.buf);
		f->tx.buf = NULL;
		fiforeset(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN]);
	}
}

static void
cancelrxtransfer(struct friend *f)
{
	if (f->rxstate == TRANSFER_INPROGRESS) {
		printout(": %s : Rx > Cancelling\n", f->name);
		if (tox_file_send_control(tox, f->num, 1, 0, TOX_FILECONTROL_KILL, NULL, 0) < 0)
			weprintf("Failed to kill Rx transfer\n");
		if (f->fd[FFILE_OUT] != -1) {
			close(f->fd[FFILE_OUT]);
			f->fd[FFILE_OUT] = -1;
		}
		ftruncate(f->fd[FFILE_PENDING], 0);
		f->rxstate = TRANSFER_NONE;
	}
}

static void
sendfriendfile(struct friend *f)
{
	ssize_t n;

	while (1) {
		/* Attempt to transmit the pending buffer */
		if (f->tx.pendingbuf == 1) {
			if (tox_file_send_data(tox, f->num, f->tx.fnum, f->tx.buf, f->tx.n) == -1) {
				/* bad luck - we will try again later */
				break;
			}
			f->tx.pendingbuf = 0;
		}
		/* Grab another buffer from the FIFO */
		n = fiforead(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN], f->tx.buf,
			     f->tx.chunksz);
		if (n == 0) {
			/* Signal transfer completion to other end */
			if (tox_file_send_control(tox, f->num, 0, f->tx.fnum,
						  TOX_FILECONTROL_FINISHED, NULL, 0) < 0)
				weprintf("Failed to signal transfer completion to the receiver\n");
			f->tx.state = TRANSFER_NONE;
			break;
		}
		if (n == -1)
			break;
		/* Store transfer size in case we can't send it right now */
		f->tx.n = n;
		if (tox_file_send_data(tox, f->num, f->tx.fnum, f->tx.buf, f->tx.n) == -1) {
			f->tx.pendingbuf = 1;
			return;
		}
	}
}

static void
sendfriendtext(struct friend *f)
{
	uint8_t buf[TOX_MAX_MESSAGE_LENGTH];
	ssize_t n;

	n = fiforead(f->dirfd, &f->fd[FTEXT_IN], ffiles[FTEXT_IN], buf, sizeof(buf));
	if (n <= 0)
		return;
	if (buf[n - 1] == '\n')
		n--;
	tox_send_message(tox, f->num, buf, n);
}

static void
removefriend(struct friend *f)
{
	char c;

	if (fiforead(f->dirfd, &f->fd[FREMOVE], ffiles[FREMOVE], &c, 1) != 1)
		return;
	if (c != '1')
		return;
	tox_del_friend(tox, f->num);
	datasave();
	printout(": %s > Removed\n", f->name);
	frienddestroy(f);
}

static int
readpass(const char *prompt)
{
	char pass[BUFSIZ], *p;

	p = readpassphrase(prompt, pass, sizeof(pass), RPP_ECHO_OFF);
	if (!p)
		eprintf("readpassphrase:");
	if (p[0] == '\0')
		return -1;
	passphrase = realloc(passphrase, strlen(p)); /* not null-terminated */
	if (!passphrase)
		eprintf("malloc:");
	memcpy(passphrase, p, strlen(p));
	pplen = strlen(p);
	return 0;
}

static void
dataload(void)
{
	off_t sz;
	uint8_t *data;
	int fd;

	fd = open(DATAFILE, O_RDONLY);
	if (fd < 0) {
		if (encryptdatafile == 1)
			while (readpass("Data : New passphrase > ") == -1);
		return;
	}

	sz = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	if (sz == 0)
		eprintf("Data : %s > Empty\n", DATAFILE);

	data = malloc(sz);
	if (!data)
		eprintf("malloc:");

	if (read(fd, data, sz) != sz)
		eprintf("read %s:", DATAFILE);

	if (tox_is_data_encrypted(data) == 1) {
		if (encryptdatafile == 0)
			printout("Data : %s > Encrypted, but saving unencrypted\n", DATAFILE);
		while (readpass("Data : Passphrase > ") < 0 ||
		       tox_encrypted_load(tox, data, sz, passphrase, pplen) < 0);
	} else {
		if (tox_load(tox, data, sz) < 0)
			eprintf("Data : %s > Failed to load\n", DATAFILE);
		if (encryptdatafile == 1) {
			printout("Data : %s > Not encrypted, but saving encrypted\n", DATAFILE);
			while (readpass("Data : New passphrase > ") < 0);
		}
	}

	free(data);
	close(fd);
}

static void
datasave(void)
{
	off_t sz;
	uint8_t *data;
	int fd;

	fd = open(DATAFILE, O_WRONLY | O_TRUNC | O_CREAT , 0666);
	if (fd < 0)
		eprintf("open %s:", DATAFILE);

	sz = encryptdatafile == 1 ? tox_encrypted_size(tox) : tox_size(tox);
	data = malloc(sz);
	if (!data)
		eprintf("malloc:");

	if (encryptdatafile == 1)
		tox_encrypted_save(tox, data, passphrase, pplen);
	else
		tox_save(tox, data);
	if (write(fd, data, sz) != sz)
		eprintf("write %s:", DATAFILE);
	fsync(fd);

	free(data);
	close(fd);
}

static int
localinit(void)
{
	uint8_t name[TOX_MAX_NAME_LENGTH + 1];
	uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
	uint8_t status[TOX_MAX_STATUSMESSAGE_LENGTH + 1];
	DIR *d;
	int r;
	size_t i, m;

	for (i = 0; i < LEN(gslots); i++) {
		r = mkdir(gslots[i].name, 0777);
		if (r < 0 && errno != EEXIST)
			eprintf("mkdir %s:", gslots[i].name);
		d = opendir(gslots[i].name);
		if (!d)
			eprintf("opendir %s:", gslots[i].name);
		r = dirfd(d);
		if (r < 0)
			eprintf("dirfd %s:", gslots[i].name);
		gslots[i].dirfd = r;

		for (m = 0; m < LEN(gfiles); m++) {
			if (gfiles[m].type == FIFO) {
				fiforeset(gslots[i].dirfd, &gslots[i].fd[m], gfiles[m]);
			} else if (gfiles[m].type == STATIC || (gfiles[m].type == NONE && !gslots[i].outisfolder)) {
				r = openat(gslots[i].dirfd, gfiles[m].name, gfiles[m].flags, 0666);
				if (r < 0)
					eprintf("openat %s:", gfiles[m].name);
				gslots[i].fd[m] = r;
			} else if (gfiles[m].type == NONE && gslots[i].outisfolder) {
				r = mkdirat(gslots[i].dirfd, gfiles[m].name, 0777);
				if (r < 0 && errno != EEXIST)
					eprintf("mkdirat %s:", gfiles[m].name);

				r = openat(gslots[i].dirfd, gfiles[m].name, O_RDONLY | O_DIRECTORY);
				if (r < 0)
					eprintf("openat %s:", gfiles[m].name);
				gslots[i].fd[m] = r;
			}
		}
	}

	/* Dump current name */
	r = tox_get_self_name(tox, name);
	if (r > sizeof(name) - 1)
		r = sizeof(name) - 1;
	name[r] = '\0';
	ftruncate(gslots[NAME].fd[OUT], 0);
	dprintf(gslots[NAME].fd[OUT], "%s\n", name);

	/* Dump status message */
	r = tox_get_self_status_message(tox, status,
					sizeof(status) - 1);
	if (r > sizeof(status) - 1)
		r = sizeof(status) - 1;
	status[r] = '\0';
	ftruncate(gslots[STATUS].fd[OUT], 0);
	dprintf(gslots[STATUS].fd[OUT], "%s\n", status);

	/* Dump ID */
	idfd = open("id", O_WRONLY | O_CREAT, 0666);
	if (idfd < 0)
		eprintf("open %s:", "id");
	tox_get_address(tox, address);
	for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++)
		dprintf(idfd, "%02X", address[i]);
	dprintf(idfd, "\n");

	/* Dump Nospam */
	ftruncate(gslots[NOSPAM].fd[OUT], 0);
	dprintf(gslots[NOSPAM].fd[OUT], "%08X\n", tox_get_nospam(tox));

	return 0;
}

static int
toxinit(void)
{
	toxopt.ipv6enabled = ipv6;
	toxopt.udp_disabled = tcpflag;
	if (proxyflag == 1) {
		tcpflag = 1;
		toxopt.udp_disabled = tcpflag;
		printout("Net > Forcing TCP mode\n");
		snprintf(toxopt.proxy_address, sizeof(toxopt.proxy_address),
			 "%s", proxyaddr);
		toxopt.proxy_port = proxyport;
		toxopt.proxy_enabled = 1;
		printout("Net > Using proxy %s:%hu\n", proxyaddr, proxyport);
	}

	tox = tox_new(&toxopt);
	if (!tox)
		eprintf("Failed to initialize tox core\n");

	dataload();
	datasave();

	toxav = toxav_new(tox, MAXCALLS);
	if (!toxav)
		eprintf("Failed to initialize toxav\n");

	toxavconfig = av_DefaultSettings;

	tox_callback_connection_status(tox, cbconnstatus, NULL);
	tox_callback_friend_message(tox, cbfriendmessage, NULL);
	tox_callback_friend_request(tox, cbfriendrequest, NULL);
	tox_callback_name_change(tox, cbnamechange, NULL);
	tox_callback_status_message(tox, cbstatusmessage, NULL);
	tox_callback_user_status(tox, cbuserstatus, NULL);
	tox_callback_file_control(tox, cbfilecontrol, NULL);
	tox_callback_file_send_request(tox, cbfilesendreq, NULL);
	tox_callback_file_data(tox, cbfiledata, NULL);

	toxav_register_callstate_callback(toxav, cbcallinvite, av_OnInvite, NULL);
	toxav_register_callstate_callback(toxav, cbcallstarted, av_OnStart, NULL);
	toxav_register_callstate_callback(toxav, cbcallended, av_OnEnd, NULL);
	toxav_register_callstate_callback(toxav, cbcallcancelled, av_OnCancel, NULL);
	toxav_register_callstate_callback(toxav, cbcallrejected, av_OnReject, NULL);

	toxav_register_callstate_callback(toxav, cbcallringing, av_OnRinging, NULL);
	toxav_register_callstate_callback(toxav, cbcallstarting, av_OnStarting, NULL);
	toxav_register_callstate_callback(toxav, cbcallending, av_OnEnding, NULL);

	toxav_register_callstate_callback(toxav, cbreqtimeout, av_OnRequestTimeout, NULL);
	toxav_register_callstate_callback(toxav, cbpeertimeout, av_OnPeerTimeout, NULL);
	toxav_register_callstate_callback(toxav, cbcalltypechange, av_OnMediaChange, NULL);

	toxav_register_audio_recv_callback(toxav, cbcalldata, NULL);

	return 0;
}

static int
toxconnect(void)
{
	struct node *n;
	uint8_t id[TOX_CLIENT_ID_SIZE];
	size_t i;

	for (i = 0; i < LEN(nodes); i++) {
		n = &nodes[i];
		if (ipv6 == 1 && !n->addr6)
			continue;
		str2id(n->idstr, id);
		tox_bootstrap_from_address(tox, ipv6 == 1 ? n->addr6 : n->addr4, n->port, id);
	}
	return 0;
}

/* Caller has to ensure `idstr' is big enough */
static void
id2str(uint8_t *id, char *idstr)
{
	char hex[] = "0123456789ABCDEF";
	int i;

	for (i = 0; i < TOX_CLIENT_ID_SIZE; i++) {
		*idstr++ = hex[(id[i] >> 4) & 0xf];
		*idstr++ = hex[id[i] & 0xf];
	}
	*idstr = '\0';
}

/* Caller has to ensure that `id' is big enough */
static void
str2id(char *idstr, uint8_t *id)
{
	size_t i, len = strlen(idstr) / 2;
	char *p = idstr;

	for (i = 0; i < len; ++i, p += 2)
		sscanf(p, "%2hhx", &id[i]);
}

static struct friend *
friendcreate(int32_t frnum)
{
	struct friend *f;
	uint8_t status[TOX_MAX_STATUSMESSAGE_LENGTH + 1];
	size_t i;
	DIR *d;
	int r;

	f = calloc(1, sizeof(*f));
	if (!f)
		eprintf("calloc:");

	r = tox_get_name(tox, frnum, (uint8_t *)f->name);
	if (r < 0)
		eprintf("Failed to get name for friend number %ld\n",
			(long)frnum);
	if (r == 0)
		snprintf(f->name, sizeof(f->name), "Anonymous");
	else
		f->name[r] = '\0';

	f->num = frnum;
	tox_get_client_id(tox, f->num, f->id);
	id2str(f->id, f->idstr);

	r = mkdir(f->idstr, 0777);
	if (r < 0 && errno != EEXIST)
		eprintf("mkdir %s:", f->idstr);

	d = opendir(f->idstr);
	if (!d)
		eprintf("opendir %s:", f->idstr);

	r = dirfd(d);
	if (r < 0)
		eprintf("dirfd %s:", f->idstr);
	f->dirfd = r;

	for (i = 0; i < LEN(ffiles); i++) {
		f->fd[i] = -1;
		if (ffiles[i].type == FIFO) {
			fiforeset(f->dirfd, &f->fd[i], ffiles[i]);
		} else if (ffiles[i].type == STATIC) {
			r = openat(f->dirfd, ffiles[i].name, ffiles[i].flags, 0666);
			if (r < 0)
				eprintf("openat %s:", ffiles[i].name);
			f->fd[i] = r;
		}
	}

	ftruncate(f->fd[FNAME], 0);
	dprintf(f->fd[FNAME], "%s\n", f->name);

	ftruncate(f->fd[FONLINE], 0);
	dprintf(f->fd[FONLINE], "%d\n",
		tox_get_friend_connection_status(tox, frnum));

	r = tox_get_status_message(tox, frnum, status, sizeof(status) - 1);
	if (r > sizeof(status) - 1)
		r = sizeof(status) - 1;
	status[r] = '\0';
	ftruncate(f->fd[FSTATUS], 0);
	dprintf(f->fd[FSTATUS], "%s\n", status);

	ftruncate(f->fd[FFILE_PENDING], 0);

	ftruncate(f->fd[FCALL_PENDING], 0);
	dprintf(f->fd[FCALL_PENDING], "0\n");

	f->av.state = av_CallNonExistant;
	f->av.num = -1;

	TAILQ_INSERT_TAIL(&friendhead, f, entry);

	return f;
}

static void
frienddestroy(struct friend *f)
{
	int i;

	canceltxtransfer(f);
	cancelrxtransfer(f);
	if (f->av.state != av_CallNonExistant)
		toxav_kill_transmission(toxav, f->av.num);
	for (i = 0; i < LEN(ffiles); i++) {
		if (f->dirfd != -1) {
			unlinkat(f->dirfd, ffiles[i].name, 0);
			if (f->fd[i] != -1)
				close(f->fd[i]);
		}
	}
	rmdir(f->idstr);
	TAILQ_REMOVE(&friendhead, f, entry);
}

static void
friendload(void)
{
	int32_t *frnums;
	uint32_t sz;
	uint32_t i;

	sz = tox_count_friendlist(tox);
	frnums = malloc(sz);
	if (!frnums)
		eprintf("malloc:");

	tox_get_friendlist(tox, frnums, sz);

	for (i = 0; i < sz; i++)
		friendcreate(frnums[i]);

	free(frnums);
}

static void
setname(void *data)
{
	char name[TOX_MAX_NAME_LENGTH + 1];
	ssize_t n;

	n = fiforead(gslots[NAME].dirfd, &gslots[NAME].fd[IN],
		     gfiles[IN], name, sizeof(name) - 1);
	if (n <= 0)
		return;
	if (name[n - 1] == '\n')
		n--;
	name[n] = '\0';
	tox_set_name(tox, (uint8_t *)name, n);
	datasave();
	printout("Name > %s\n", name);
	ftruncate(gslots[NAME].fd[OUT], 0);
	dprintf(gslots[NAME].fd[OUT], "%s\n", name);
}

static void
setstatus(void *data)
{
	uint8_t status[TOX_MAX_STATUSMESSAGE_LENGTH + 1];
	ssize_t n;

	n = fiforead(gslots[STATUS].dirfd, &gslots[STATUS].fd[IN], gfiles[IN],
		     status, sizeof(status) - 1);
	if (n <= 0)
		return;
	if (status[n - 1] == '\n')
		n--;
	status[n] = '\0';
	tox_set_status_message(tox, status, n);
	datasave();
	printout("Status > %s\n", status);
	ftruncate(gslots[STATUS].fd[OUT], 0);
	dprintf(gslots[STATUS].fd[OUT], "%s\n", status);
}

static void
sendfriendreq(void *data)
{
	char buf[PIPE_BUF], *p;
	char *msg = "ratox is awesome!";
	uint8_t id[TOX_FRIEND_ADDRESS_SIZE];
	ssize_t n;
	int r;

	n = fiforead(gslots[REQUEST].dirfd, &gslots[REQUEST].fd[IN], gfiles[IN],
		     buf, sizeof(buf) - 1);
	if (n <= 0)
		return;
	buf[n] = '\0';

	for (p = buf; *p && isspace(*p) == 0; p++)
		;
	if (*p != '\0') {
		*p = '\0';
		while (isspace(*p++) != 0)
			;
		if (*p != '\0')
			msg = p;
		if (msg[strlen(msg) - 1] == '\n')
			msg[strlen(msg) - 1] = '\0';
	}
	str2id(buf, id);

	r = tox_add_friend(tox, id, (uint8_t *)buf, strlen(buf));
	ftruncate(gslots[REQUEST].fd[ERR], 0);

	if (r < 0) {
		dprintf(gslots[REQUEST].fd[ERR], "%s\n", reqerr[-r]);
		return;
	}
	datasave();
	printout("Request > Sent\n");
}

static void
setnospam(void *data)
{
	uint8_t nospam[2 * sizeof(uint32_t) + 1];
	uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
	uint32_t nsval;
	ssize_t n, i;

	n = fiforead(gslots[NOSPAM].dirfd, &gslots[NOSPAM].fd[IN], gfiles[IN],
	             nospam, sizeof(nospam) - 1);
	if (n <= 0)
		return;
	if (nospam[n - 1] == '\n')
		n--;
	nospam[n] = '\0';

	for (i = 0; i < n; i++) {
		if (nospam[i] < '0' || (nospam[i] > '9' && nospam[i] < 'A') || nospam[i] > 'F') {
			dprintf(gslots[NOSPAM].fd[ERR], "Input contains invalid characters ![0-9, A-F]\n");
			goto end;
		}
	}

	nsval = strtoul((char *)nospam, NULL, 16);
	tox_set_nospam(tox, nsval);
	datasave();
	printout("Nospam > %08X\n", nsval);
	ftruncate(gslots[NOSPAM].fd[OUT], 0);
	dprintf(gslots[NOSPAM].fd[OUT], "%08X\n", nsval);

	tox_get_address(tox, address);
	ftruncate(idfd, 0);
	for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++)
		dprintf(idfd, "%02X", address[i]);
	dprintf(idfd, "\n");
end:
	fiforeset(gslots[NOSPAM].dirfd, &gslots[NOSPAM].fd[IN], gfiles[IN]);
}

static void
loop(void)
{
	char tstamp[64];
	struct friend *f, *ftmp;
	struct request *req, *rtmp;
	time_t t0, t1, now;
	int connected = 0;
	int i, n, r;
	int fdmax;
	char c;
	fd_set rfds;
	struct timeval tv;

	t0 = time(NULL);
	printout("DHT > Connecting\n");
	toxconnect();
	while (running) {
		if (tox_isconnected(tox) == 1) {
			if (connected == 0) {
				printout("DHT > Connected\n");
				/* Cancel any pending transfers */
				TAILQ_FOREACH(f, &friendhead, entry) {
					canceltxtransfer(f);
					cancelrxtransfer(f);
				}
				connected = 1;
			}
		} else {
			if (connected == 1) {
				printout("DHT > Disconnected\n");
				connected = 0;
			}
			t1 = time(NULL);
			if (t1 > t0 + CONNECTDELAY) {
				t0 = time(NULL);
				printout("DHT > Connecting\n");
				toxconnect();
			}
		}
		tox_do(tox);

		FD_ZERO(&rfds);

		fdmax = -1;
		for (i = 0; i < LEN(gslots); i++) {
			FD_SET(gslots[i].fd[IN], &rfds);
			if (gslots[i].fd[IN] > fdmax)
				fdmax = gslots[i].fd[IN];
		}

		TAILQ_FOREACH(req, &reqhead, entry) {
			FD_SET(req->fd, &rfds);
			if(req->fd > fdmax)
				fdmax = req->fd;
		}

		TAILQ_FOREACH(f, &friendhead, entry) {
			/* Only monitor friends that are online */
			if (tox_get_friend_connection_status(tox, f->num) == 1) {
				FD_SET(f->fd[FTEXT_IN], &rfds);
				if (f->fd[FTEXT_IN] > fdmax)
					fdmax = f->fd[FTEXT_IN];
				if (f->tx.state == TRANSFER_INITIATED ||
				    f->tx.state == TRANSFER_PAUSED)
					continue;
				FD_SET(f->fd[FFILE_IN], &rfds);
				if (f->fd[FFILE_IN] > fdmax)
					fdmax = f->fd[FFILE_IN];
			}
			FD_SET(f->fd[FREMOVE], &rfds);
			if (f->fd[FREMOVE] > fdmax)
				fdmax = f->fd[FREMOVE];
		}

		tv.tv_sec = 0;
		tv.tv_usec = tox_do_interval(tox) * 1000;
		n = select(fdmax + 1, &rfds, NULL, NULL, &tv);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			eprintf("select:");
		}

		/* Check for broken transfers, i.e. the friend went offline
		 * in the middle of a transfer.
		 */
		TAILQ_FOREACH(f, &friendhead, entry) {
			if (tox_get_friend_connection_status(tox, f->num) == 0) {
				canceltxtransfer(f);
				cancelrxtransfer(f);
			}
		}

		/* If we hit the receiver too hard, we will run out of
		 * local buffer slots.  In that case tox_file_send_data()
		 * will return -1 and we will have to queue the buffer to
		 * send it later.  If this is the last buffer read from
		 * the FIFO, then select() won't make the fd readable again
		 * so we have to check if there's anything pending to be
		 * sent.
		 */
		TAILQ_FOREACH(f, &friendhead, entry) {
			if (tox_get_friend_connection_status(tox, f->num) == 0)
				continue;
			if (f->tx.state != TRANSFER_INPROGRESS)
				continue;
			if (f->tx.pendingbuf == 1)
				sendfriendfile(f);
			if (f->tx.state == TRANSFER_NONE)
				FD_CLR(f->fd[FFILE_IN], &rfds);
		}

		/* Accept pending transfers if any */
		TAILQ_FOREACH(f, &friendhead, entry) {
			if (tox_get_friend_connection_status(tox, f->num) == 0)
				continue;
			if (f->rxstate == TRANSFER_NONE)
				continue;
			if (f->fd[FFILE_OUT] == -1) {
				r = openat(f->dirfd, ffiles[FFILE_OUT].name,
					   ffiles[FFILE_OUT].flags, 0666);
				if (r < 0) {
					if (errno != ENXIO)
						eprintf("openat %s:", ffiles[FFILE_OUT].name);
				} else {
					f->fd[FFILE_OUT] = r;
					if (tox_file_send_control(tox, f->num, 1, 0,
							      TOX_FILECONTROL_ACCEPT, NULL, 0) < 0) {
						weprintf("Failed to accept transfer from receiver\n");
						cancelrxtransfer(f);
					} else {
						printout(": %s : Rx > Accepted\n", f->name);
					}
				}
			}
		}

		/* Answer pending calls */
		TAILQ_FOREACH(f, &friendhead, entry) {
			if (tox_get_friend_connection_status(tox, f->num) == 0)
				continue;
			if (f->av.state != av_CallStarting)
				continue;
			if (f->fd[FCALL_OUT] == -1) {
				r = openat(f->dirfd, ffiles[FCALL_OUT].name,
					   ffiles[FCALL_OUT].flags, 0666);
				if (r < 0) {
					if (errno != ENXIO)
						eprintf("openat %s:", ffiles[FCALL_OUT].name);
				} else {
					f->fd[FCALL_OUT] = r;
					toxav_answer(toxav, f->av.num, &toxavconfig);
				}
			}
		}

		if (n == 0)
			continue;

		for (i = 0; i < LEN(gslots); i++) {
			if (FD_ISSET(gslots[i].fd[IN], &rfds) == 0)
				continue;
			(*gslots[i].cb)(NULL);
		}

		for (req = TAILQ_FIRST(&reqhead); req; req = rtmp) {
			rtmp = TAILQ_NEXT(req, entry);
			if (FD_ISSET(req->fd, &rfds) == 0)
				continue;
			if (read(req->fd, &c, 1) != 1)
				continue;
			if (c != '0' && c != '1')
				continue;
			if (c == '1') {
				tox_add_friend_norequest(tox, req->id);
				printout("Request : %s > Accepted\n", req->idstr);
				datasave();
			} else {
				printout("Request : %s > Rejected\n", req->idstr);
			}
			unlinkat(gslots[REQUEST].fd[OUT], req->idstr, 0);
			close(req->fd);
			TAILQ_REMOVE(&reqhead, req, entry);
			free(req->msg);
			free(req);
		}

		for (f = TAILQ_FIRST(&friendhead); f; f = ftmp) {
			ftmp = TAILQ_NEXT(f, entry);
			if (FD_ISSET(f->fd[FTEXT_IN], &rfds))
				sendfriendtext(f);
			if (FD_ISSET(f->fd[FFILE_IN], &rfds)) {
				switch (f->tx.state) {
				case TRANSFER_NONE:
					/* Prepare a new transfer */
					now = time(NULL);
					snprintf(tstamp, sizeof(tstamp), "%lu", (unsigned long)now);
					if (tox_new_file_sender(tox, f->num,
						0, (uint8_t *)tstamp, strlen(tstamp)) < 0) {
						weprintf("Failed to initiate new transfer\n");
						fiforeset(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN]);
					} else {
						f->tx.state = TRANSFER_INITIATED;
						printout(": %s : Tx > Initiated\n", f->name);
					}
					break;
				case TRANSFER_INPROGRESS:
					sendfriendfile(f);
					break;
				}
			}
			if (FD_ISSET(f->fd[FREMOVE], &rfds))
				removefriend(f);
		}
	}
}

static void
initshutdown(int sig)
{
	running = 0;
}

static void
shutdown(void)
{
	int i, m;
	struct friend *f, *ftmp;
	struct request *r, *rtmp;

	printout("Shutdown\n");

	/* Friends */
	for (f = TAILQ_FIRST(&friendhead); f; f = ftmp) {
		ftmp = TAILQ_NEXT(f, entry);
		frienddestroy(f);
	}

	/* Requests */
	for (r = TAILQ_FIRST(&reqhead); r; r = rtmp) {
		rtmp = TAILQ_NEXT(r, entry);

		if (gslots[REQUEST].fd[OUT] != -1) {
			unlinkat(gslots[REQUEST].fd[OUT], r->idstr, 0);
			if (r->fd != -1)
				close(r->fd);
		}
		TAILQ_REMOVE(&reqhead, r, entry);
		free(r->msg);
		free(r);
	}

	/* Global files and slots */
	for (i = 0; i < LEN(gslots); i++) {
		for (m = 0; m < LEN(gfiles); m++) {
			if (gslots[i].dirfd != -1) {
				unlinkat(gslots[i].dirfd, gfiles[m].name,
					 (gslots[i].outisfolder && m == OUT)
					 ? AT_REMOVEDIR : 0);
				if (gslots[i].fd[m] != -1)
					close(gslots[i].fd[m]);
			}
		}
		rmdir(gslots[i].name);
	}
	unlink("id");
	if (idfd != -1)
		close(idfd);

	toxav_kill(toxav);
	tox_kill(tox);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-4|-6] [-t] [-p]\n", argv0);
	fprintf(stderr, " -4\tIPv4 only\n");
	fprintf(stderr, " -6\tIPv6 only\n");
	fprintf(stderr, " -t\tEnable TCP mode (UDP by default)\n");
	fprintf(stderr, " -p\tEnable TCP socks5 proxy\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	ARGBEGIN {
	case '4':
		break;
	case '6':
		ipv6 = 1;
		break;
	case 't':
		tcpflag = 1;
		break;
	case 'p':
		proxyflag = 1;
		break;
	default:
		usage();
	} ARGEND;

	setbuf(stdout, NULL);

	signal(SIGHUP, initshutdown);
	signal(SIGINT, initshutdown);
	signal(SIGQUIT, initshutdown);
	signal(SIGABRT, initshutdown);
	signal(SIGTERM, initshutdown);
	signal(SIGPIPE, SIG_IGN);

	printrat();
	toxinit();
	localinit();
	friendload();
	loop();
	shutdown();
	return 0;
}
