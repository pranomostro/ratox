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
#include <tox/toxencryptsave.h>

#include "arg.h"
#include "queue.h"
#include "readpassphrase.h"

#define LEN(x) (sizeof (x) / sizeof *(x))
#define DATAFILE ".ratox.data"

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

enum {
	NAME,
	STATUS,
	REQUEST
};

static struct slot gslots[] = {
	[NAME]    = { .name = "name",	 .cb = setname,	      .outisfolder = 0, .dirfd = -1 },
	[STATUS]  = { .name = "status",	 .cb = setstatus,     .outisfolder = 0, .dirfd = -1 },
	[REQUEST] = { .name = "request", .cb = sendfriendreq, .outisfolder = 1, .dirfd = -1 },
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
};

enum {
	TRANSFER_NONE,
	TRANSFER_INITIATED,
	TRANSFER_INPROGRESS,
	TRANSFER_PAUSED,
	TRANSFER_DONE
};

struct transfer {
	uint8_t fnum;
	uint8_t *buf;
	int chunksz;
	ssize_t n;
	int pending;
	int state;
};

struct friend {
	/* null terminated name */
	char namestr[TOX_MAX_NAME_LENGTH + 1];
	int fid;
	uint8_t id[TOX_CLIENT_ID_SIZE];
	/* null terminated id */
	char idstr[2 * TOX_CLIENT_ID_SIZE + 1];
	int dirfd;
	int fd[LEN(ffiles)];
	int recvfileactive;
	struct transfer t;
	TAILQ_ENTRY(friend) entry;
};

struct request {
	uint8_t id[TOX_CLIENT_ID_SIZE];
	/* null terminated id */
	char idstr[2 * TOX_CLIENT_ID_SIZE + 1];
	/* null terminated friend request message */
	char *msgstr;
	int fd;
	TAILQ_ENTRY(request) entry;
};

char *argv0;

static TAILQ_HEAD(friendhead, friend) friendhead = TAILQ_HEAD_INITIALIZER(friendhead);
static TAILQ_HEAD(reqhead, request) reqhead = TAILQ_HEAD_INITIALIZER(reqhead);

static Tox *tox;
static Tox_Options toxopt;
static uint8_t *passphrase;
static uint32_t pplen;
static uint8_t toilet[BUFSIZ];
static int running = 1;
static int ipv6;
static int tcpflag;
static int proxyflag;

static void printrat(void);
static void printout(const char *, ...);
static ssize_t fiforead(int, int *, struct file, void *, size_t);
static void cbconnstatus(Tox *, int32_t, uint8_t, void *);
static void cbfriendmessage(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cbfriendrequest(Tox *, const uint8_t *, const uint8_t *, uint16_t, void *);
static void cbnamechange(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cbstatusmessage(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cbuserstatus(Tox *, int32_t, uint8_t, void *);
static void cbfilecontrol(Tox *, int32_t, uint8_t, uint8_t, uint8_t, const uint8_t *, uint16_t, void *);
static void cbfilesendreq(Tox *, int32_t, uint8_t, uint64_t, const uint8_t *, uint16_t, void *);
static void cbfiledata(Tox *, int32_t, uint8_t, const uint8_t *, uint16_t, void *);
static void canceltransfer(struct friend *);
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
	printf("\033[31m");
	printf("                       ,     .\n");
	printf("                       (\\,;,/)\n");
	printf("                        (o o)\\//,\n");
	printf("                         \\ /     \\,\n");
	printf("                         `+'(  (   \\    )\n");
	printf("                            //  \\   |_./\n");
	printf("                          '~' '~----'\tratox v"VERSION"\n");
	printf("\033[0m");
	putchar('\n');
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

static ssize_t
fiforead(int dirfd, int *fd, struct file f, void *buf, size_t sz)
{
	ssize_t r;

again:
	r = read(*fd, buf, sz);
	if (r == 0) {
		close(*fd);
		r = openat(dirfd, f.name, f.flags, 0644);
		if (r < 0) {
			perror("openat");
			exit(EXIT_FAILURE);
		}
		*fd = r;
		return 0;
	}
	if (r < 0) {
		if (errno == EINTR)
			goto again;
		if (errno == EWOULDBLOCK)
			return -1;
		perror("read");
		exit(EXIT_FAILURE);
	}
	return r;
}

static void
cbconnstatus(Tox *m, int32_t fid, uint8_t status, void *udata)
{
	struct friend *f;
	uint8_t name[TOX_MAX_NAME_LENGTH + 1];
	int r;

	r = tox_get_name(tox, fid, name);
	if (r < 0) {
		fprintf(stderr, "tox_get_name() on fid %d failed\n", fid);
		exit(EXIT_FAILURE);
	}
	name[r] = '\0';

	printout("%s %s\n", r == 0 ? (uint8_t *)"Anonymous" : name,
		 status == 0 ? "went offline" : "came online");

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			ftruncate(f->fd[FONLINE], 0);
			dprintf(f->fd[FONLINE], status == 0 ? "0\n" : "1\n");
			return;
		}
	}

	friendcreate(fid);
}

static void
cbfriendmessage(Tox *m, int32_t fid, const uint8_t *data, uint16_t len, void *udata)
{
	struct friend *f;
	uint8_t msg[len + 1];
	char buft[64];
	time_t t;

	memcpy(msg, data, len);
	msg[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			t = time(NULL);
			strftime(buft, sizeof(buft), "%F %R", localtime(&t));
			dprintf(f->fd[FTEXT_OUT], "%s %s\n", buft, msg);
			printout("%s %s\n",
				 f->namestr[0] == '\0' ? "Anonymous" : f->namestr, msg);
			break;
		}
	}
}

static void
cbfriendrequest(Tox *m, const uint8_t *id, const uint8_t *data, uint16_t len, void *udata)
{
	struct request *req;
	int r;

	req = calloc(1, sizeof(*req));
	if (!req) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}
	memcpy(req->id, id, TOX_CLIENT_ID_SIZE);
	id2str(req->id, req->idstr);

	if (len > 0) {
		req->msgstr = malloc(len + 1);
		if (!req->msgstr) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		memcpy(req->msgstr, data, len);
		req->msgstr[len] = '\0';
	}

	r = mkfifoat(gslots[REQUEST].fd[OUT], req->idstr, 0644);
	if (r < 0 && errno != EEXIST) {
		perror("mkfifoat");
		exit(EXIT_FAILURE);
	}
	r = openat(gslots[REQUEST].fd[OUT], req->idstr, O_RDWR | O_NONBLOCK);
	if (r < 0) {
		perror("openat");
		exit(EXIT_FAILURE);
	}
	req->fd = r;

	TAILQ_INSERT_TAIL(&reqhead, req, entry);

	printout("Pending request from %s with message: %s\n",
		 req->idstr, req->msgstr);
}

static void
cbnamechange(Tox *m, int32_t fid, const uint8_t *data, uint16_t len, void *user)
{
	struct friend *f;
	uint8_t name[len + 1];

	memcpy(name, data, len);
	name[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			ftruncate(f->fd[FNAME], 0);
			dprintf(f->fd[FNAME], "%s\n", name);
			if (memcmp(f->namestr, name, len + 1) == 0)
				break;
			printout("%s -> %s\n", f->namestr[0] == '\0' ?
				 "Anonymous" : f->namestr, name);
			memcpy(f->namestr, name, len + 1);
			break;
		}
	}
	datasave();
}

static void
cbstatusmessage(Tox *m, int32_t fid, const uint8_t *data, uint16_t len, void *udata)
{
	struct friend *f;
	uint8_t status[len + 1];

	memcpy(status, data, len);
	status[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			ftruncate(f->fd[FSTATUS], 0);
			dprintf(f->fd[FSTATUS], "%s\n", status);
			printout("%s changed status: %s\n",
				 f->namestr[0] == '\0' ? "Anonymous" : f->namestr, status);
			break;
		}
	}
	datasave();
}

static void
cbuserstatus(Tox *m, int32_t fid, uint8_t status, void *udata)
{
	struct friend *f;
	char *statusstr[] = { "none", "away", "busy" };

	if (status >= LEN(statusstr)) {
		fprintf(stderr, "received invalid user status: %d\n", status);
		return;
	}

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			printout("%s changed user status: %s\n",
				 f->namestr[0] == '\0' ? "Anonymous" : f->namestr,
			         statusstr[status]);
			break;
		}
	}
}

static void
cbfilecontrol(Tox *m, int32_t fid, uint8_t rec_sen, uint8_t fnum, uint8_t ctrltype,
	const uint8_t *data, uint16_t len, void *udata)
{
	struct friend *f;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->fid == fid)
			break;
	if (!f)
		return;

	switch (ctrltype) {
	case TOX_FILECONTROL_ACCEPT:
		if (rec_sen == 1) {
			if (f->t.state == TRANSFER_PAUSED) {
				printout("Receiver resumed transfer\n");
				f->t.state = TRANSFER_INPROGRESS;
			} else {
				f->t.fnum = fnum;
				f->t.chunksz = tox_file_data_size(tox, fnum);
				f->t.buf = malloc(f->t.chunksz);
				if (!f->t.buf) {
					perror("malloc");
					exit(EXIT_FAILURE);
				}
				f->t.n = 0;
				f->t.pending = 0;
				f->t.state = TRANSFER_INPROGRESS;
				printout("Transfer is in progress\n");
			}
		}
		break;
	case TOX_FILECONTROL_PAUSE:
		if (rec_sen == 1) {
			if (f->t.state == TRANSFER_INPROGRESS) {
				printout("Receiver paused transfer\n");
				f->t.state = TRANSFER_PAUSED;
			}
		}
		break;
	case TOX_FILECONTROL_KILL:
		if (rec_sen == 1) {
			printout("Transfer rejected by receiver\n");
			f->t.state = TRANSFER_NONE;
			free(f->t.buf);
			f->t.buf = NULL;

			/* Flush the FIFO */
			while (fiforead(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN],
			                toilet, sizeof(toilet)));
		}
		break;
	case TOX_FILECONTROL_FINISHED:
		if (rec_sen == 1) {
			/* Sending completed */
			printout("Transfer complete\n");
			f->t.state = TRANSFER_NONE;
			free(f->t.buf);
			f->t.buf = NULL;
		} else {
			/* Receiving completed */
			printout("Transfer complete\n");
			tox_file_send_control(tox, f->fid, 1, 0, TOX_FILECONTROL_FINISHED, NULL, 0);
			ftruncate(f->fd[FFILE_PENDING], 0);
			dprintf(f->fd[FFILE_PENDING], "%d\n", 0);
			f->recvfileactive = 0;
			if (f->fd[FFILE_OUT] != -1) {
				close(f->fd[FFILE_OUT]);
				f->fd[FFILE_OUT] = -1;
			}
		}
		break;
	default:
		fprintf(stderr, "Unhandled file control type: %d\n", ctrltype);
		break;
	};
}

static void
cbfilesendreq(Tox *m, int32_t fid, uint8_t fnum, uint64_t fsz,
	      const uint8_t *fname, uint16_t flen, void *udata)
{
	struct friend *f;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->fid == fid)
			break;
	if (!f)
		return;

	/* We only support a single transfer at a time */
	if (fnum != 0) {
		tox_file_send_control(tox, f->fid, 1, 0, TOX_FILECONTROL_KILL, NULL, 0);
		return;
	}

	ftruncate(f->fd[FFILE_PENDING], 0);
	dprintf(f->fd[FFILE_PENDING], "%d\n", 1);
	f->recvfileactive = 1;
	printout("Pending file transfer request from %s\n",
		 f->namestr[0] == '\0' ? "Anonymous" : f->namestr);
}

static void
cbfiledata(Tox *m, int32_t fid, uint8_t fnum, const uint8_t *data, uint16_t len, void *udata)
{
	struct friend *f;
	ssize_t n;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->fid == fid)
			break;
	if (!f)
		return;

	n = write(f->fd[FFILE_OUT], data, len);
	if (n < 0) {
		tox_file_send_control(tox, f->fid, 1, 0, TOX_FILECONTROL_KILL, NULL, 0);
		if (f->fd[FFILE_OUT] != -1) {
			close(f->fd[FFILE_OUT]);
			f->fd[FFILE_OUT] = -1;
		}
	}
}

/* T0D0: Might want to break this function into two separate ones for
 * TX and RX to minimize code duplication when cancelling transfers */
static void
canceltransfer(struct friend *f)
{
	/* Cancel TX transfers */
	if (f->t.state != TRANSFER_NONE) {
		printout("Cancelling transfer to %s\n",
			 f->namestr[0] == '\0' ? "Anonymous" : f->namestr);
		tox_file_send_control(tox, f->fid, 0, 0, TOX_FILECONTROL_KILL, NULL, 0);
		f->t.state = TRANSFER_NONE;
		free(f->t.buf);
		f->t.buf = NULL;
		/* Flush the FIFO */
		while (fiforead(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN],
				toilet, sizeof(toilet)));
	}
	/* Cancel RX transfers */
	if (f->recvfileactive == 1) {
		tox_file_send_control(tox, f->fid, 1, 0, TOX_FILECONTROL_KILL, NULL, 0);
		if (f->fd[FFILE_OUT] != -1) {
			close(f->fd[FFILE_OUT]);
			f->fd[FFILE_OUT] = -1;
		}
	}
}

static void
sendfriendfile(struct friend *f)
{
	ssize_t n;

	while (1) {
		/* Attempt to transmit the pending buffer */
		if (f->t.pending == 1) {
			if (tox_file_send_data(tox, f->fid, f->t.fnum, f->t.buf, f->t.n) == -1) {
				/* bad luck - we will try again later */
				break;
			}
			f->t.pending = 0;
		}
		/* Grab another buffer from the FIFO */
		n = fiforead(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN], f->t.buf,
			     f->t.chunksz);
		if (n == 0) {
			/* Signal transfer completion to other end */
			tox_file_send_control(tox, f->fid, 0, f->t.fnum,
					      TOX_FILECONTROL_FINISHED, NULL, 0);
			break;
		}
		if (n == -1)
			break;
		/* Store transfer size in case we can't send it right now */
		f->t.n = n;
		if (tox_file_send_data(tox, f->fid, f->t.fnum, f->t.buf, f->t.n) == -1) {
			f->t.pending = 1;
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
	tox_send_message(tox, f->fid, buf, n);
}

static void
removefriend(struct friend *f)
{
	char c;

	if (fiforead(f->dirfd, &f->fd[FREMOVE], ffiles[FREMOVE], &c, 1) != 1)
		return;
	if (c != '1')
		return;
	tox_del_friend(tox, f->fid);
	datasave();
	printout("Removed friend %s\n",
	         f->namestr[0] == '\0' ? "Anonymous" : f->namestr);
	frienddestroy(f);
}

static int
readpass(const char *prompt)
{
	char pass[BUFSIZ], *p;

	p = readpassphrase(prompt, pass, sizeof(pass), RPP_ECHO_OFF);
	if (!p) {
		perror("readpassphrase");
		exit(EXIT_FAILURE);
	}
	if (p[0] == '\0')
		return -1;
	passphrase = realloc(passphrase, strlen(p)); /* not null-terminated */
	if (!passphrase) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
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
			while (readpass("New passphrase: ") == -1);
		return;
	}

	sz = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	if (sz == 0) {
		fprintf(stderr, "%s seems to be corrupt\n",
			DATAFILE);
		exit(EXIT_FAILURE);
	}

	data = malloc(sz);
	if (!data) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	if (read(fd, data, sz) != sz) {
		perror("read");
		exit(EXIT_FAILURE);
	}

	if (tox_is_data_encrypted(data) == 1) {
		if (encryptdatafile == 0)
			printout("%s is encrypted, but saving in plain format\n", DATAFILE);
		while (readpass("Passphrase: ") < 0 ||
		       tox_encrypted_load(tox, data, sz, passphrase, pplen) < 0);
	} else {
		if (tox_load(tox, data, sz) < 0) {
			fprintf(stderr, "tox_load() failed\n");
			exit(EXIT_FAILURE);
		}
		if (encryptdatafile == 1) {
			printout("%s is not encrypted, but saving in encrypted format\n", DATAFILE);
			while (readpass("New passphrase: ") < 0);
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

	fd = open(DATAFILE, O_WRONLY | O_TRUNC | O_CREAT , 0644);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	sz = encryptdatafile == 1 ? tox_encrypted_size(tox) : tox_size(tox);
	data = malloc(sz);
	if (!data) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	if (encryptdatafile == 1)
		tox_encrypted_save(tox, data, passphrase, pplen);
	else
		tox_save(tox, data);
	if (write(fd, data, sz) != sz) {
		perror("write");
		exit(EXIT_FAILURE);
	}
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
	int r, fd;
	size_t i, m;

	for (i = 0; i < LEN(gslots); i++) {
		r = mkdir(gslots[i].name, 0755);
		if (r < 0 && errno != EEXIST) {
			perror("mkdir");
			exit(EXIT_FAILURE);
		}
		d = opendir(gslots[i].name);
		if (!d) {
			perror("opendir");
			exit(EXIT_FAILURE);
		}
		r = dirfd(d);
		if (r < 0) {
			perror("dirfd");
			exit(EXIT_FAILURE);
		}
		gslots[i].dirfd = r;
		for (m = 0; m < LEN(gfiles); m++) {
			if (gfiles[m].type == FIFO) {
				r = mkfifoat(gslots[i].dirfd, gfiles[m].name, 0644);
				if (r < 0 && errno != EEXIST) {
					perror("mkfifo");
					exit(EXIT_FAILURE);
				}
				r = openat(gslots[i].dirfd, gfiles[m].name, gfiles[m].flags, 0644);
				if (r < 0) {
					perror("openat");
					exit(EXIT_FAILURE);
				}
				gslots[i].fd[m] = r;
			} else if (gfiles[m].type == STATIC || (gfiles[m].type == NONE && !gslots[i].outisfolder)) {
				r = openat(gslots[i].dirfd, gfiles[m].name, gfiles[m].flags, 0644);
				if (r < 0) {
					perror("openat");
					exit(EXIT_FAILURE);
				}
				gslots[i].fd[m] = r;
			} else if (gfiles[m].type == NONE && gslots[i].outisfolder) {
				r = mkdirat(gslots[i].dirfd, gfiles[m].name, 0777);
				if (r < 0 && errno != EEXIST) {
					perror("mkdir");
					exit(EXIT_FAILURE);
				}
				r = openat(gslots[i].dirfd, gfiles[m].name, O_RDONLY | O_DIRECTORY);
				if (r < 0) {
					perror("openat");
					exit(EXIT_FAILURE);
				}
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
	fd = open("id", O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}
	tox_get_address(tox, address);
	for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++)
		dprintf(fd, "%02X", address[i]);
	dprintf(fd, "\n");
	close(fd);

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
		printout("Forcing TCP mode\n");
		snprintf(toxopt.proxy_address, sizeof(toxopt.proxy_address),
			 "%s", proxyaddr);
		toxopt.proxy_port = proxyport;
		toxopt.proxy_enabled = 1;
		printout("Using proxy %s:%hu\n", proxyaddr, proxyport);
	}
	tox = tox_new(&toxopt);
	dataload();
	datasave();
	tox_callback_connection_status(tox, cbconnstatus, NULL);
	tox_callback_friend_message(tox, cbfriendmessage, NULL);
	tox_callback_friend_request(tox, cbfriendrequest, NULL);
	tox_callback_name_change(tox, cbnamechange, NULL);
	tox_callback_status_message(tox, cbstatusmessage, NULL);
	tox_callback_user_status(tox, cbuserstatus, NULL);
	tox_callback_file_control(tox, cbfilecontrol, NULL);
	tox_callback_file_send_request(tox, cbfilesendreq, NULL);
	tox_callback_file_data(tox, cbfiledata, NULL);
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

static void
str2id(char *idstr, uint8_t *id)
{
	size_t i, len = strlen(idstr) / 2;
	char *p = idstr;

	for (i = 0; i < len; ++i, p += 2)
		sscanf(p, "%2hhx", &id[i]);
}

static struct friend *
friendcreate(int32_t fid)
{
	struct friend *f;
	uint8_t status[TOX_MAX_STATUSMESSAGE_LENGTH + 1];
	size_t i;
	DIR *d;
	int r;

	f = calloc(1, sizeof(*f));
	if (!f) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}

	r = tox_get_name(tox, fid, (uint8_t *)f->namestr);
	if (r < 0) {
		fprintf(stderr, "tox_get_name() on fid %d failed\n", fid);
		exit(EXIT_FAILURE);
	}
	f->namestr[r] = '\0';

	f->fid = fid;
	tox_get_client_id(tox, f->fid, f->id);
	id2str(f->id, f->idstr);

	r = mkdir(f->idstr, 0755);
	if (r < 0 && errno != EEXIST) {
		perror("mkdir");
		exit(EXIT_FAILURE);
	}

	d = opendir(f->idstr);
	if (!d) {
		perror("opendir");
		exit(EXIT_FAILURE);
	}
	r = dirfd(d);
	if (r < 0) {
		perror("dirfd");
		exit(EXIT_FAILURE);
	}
	f->dirfd = r;

	for (i = 0; i < LEN(ffiles); i++) {
		if (ffiles[i].type == FIFO) {
			r = mkfifoat(f->dirfd, ffiles[i].name, 0644);
			if (r < 0 && errno != EEXIST) {
				perror("mkfifo");
				exit(EXIT_FAILURE);
			}
			r = openat(f->dirfd, ffiles[i].name, ffiles[i].flags, 0644);
			if (r < 0) {
				if (errno != ENXIO) {
					perror("openat");
					exit(EXIT_FAILURE);
				}
			}
		} else if (ffiles[i].type == STATIC) {
			r = openat(f->dirfd, ffiles[i].name, ffiles[i].flags, 0644);
			if (r < 0) {
				perror("openat");
				exit(EXIT_FAILURE);
			}
		}
		f->fd[i] = r;
	}

	ftruncate(f->fd[FNAME], 0);
	dprintf(f->fd[FNAME], "%s\n", f->namestr);

	ftruncate(f->fd[FONLINE], 0);
	dprintf(f->fd[FONLINE], "%s\n",
		tox_get_friend_connection_status(tox, fid) == 0 ? "0" : "1");

	r = tox_get_status_message_size(tox, fid);
	if (r > sizeof(status) - 1)
		r = sizeof(status) - 1;
	status[r] = '\0';
	ftruncate(f->fd[FSTATUS], 0);
	dprintf(f->fd[FSTATUS], "%s\n", status);

	ftruncate(f->fd[FFILE_PENDING], 0);
	dprintf(f->fd[FFILE_PENDING], "%d\n", 0);

	TAILQ_INSERT_TAIL(&friendhead, f, entry);

	return f;
}

static void
frienddestroy(struct friend *f)
{
	int i;

	canceltransfer(f);
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
	int32_t *fids;
	uint32_t sz;
	uint32_t i;

	sz = tox_count_friendlist(tox);
	fids = malloc(sz);
	if (!fids) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	tox_get_friendlist(tox, fids, sz);

	for (i = 0; i < sz; i++)
		friendcreate(fids[i]);

	free(fids);
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
	printout("Changed name to %s\n", name);
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
	printout("Changed status message to %s\n", status);
	ftruncate(gslots[STATUS].fd[OUT], 0);
	dprintf(gslots[STATUS].fd[OUT], "%s\n", status);
}

static void
sendfriendreq(void *data)
{
	char buf[BUFSIZ], *p;
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
	printout("Friend request sent\n");
	datasave();
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
	printout("Connecting to DHT...\n");
	toxconnect();
	while (running) {
		if (tox_isconnected(tox) == 1) {
			if (connected == 0) {
				printout("Connected to DHT\n");
				connected = 1;
			}
		} else {
			connected = 0;
			t1 = time(NULL);
			if (t1 > t0 + 5) {
				t0 = time(NULL);
				printout("Connecting to DHT...\n");
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
			if (tox_get_friend_connection_status(tox, f->fid) == 1) {
				FD_SET(f->fd[FTEXT_IN], &rfds);
				if (f->fd[FTEXT_IN] > fdmax)
					fdmax = f->fd[FTEXT_IN];
				if (f->t.state == TRANSFER_INITIATED ||
				    f->t.state == TRANSFER_PAUSED)
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
			perror("select");
			exit(EXIT_FAILURE);
		}

		/* Check for broken transfers, i.e. the friend went offline
		 * in the middle of a transfer.
		 */
		TAILQ_FOREACH(f, &friendhead, entry)
			if (tox_get_friend_connection_status(tox, f->fid) == 0)
				canceltransfer(f);

		/* If we hit the receiver too hard, we will run out of
		 * local buffer slots.  In that case tox_file_send_data()
		 * will return -1 and we will have to queue the buffer to
		 * send it later.  If this is the last buffer read from
		 * the FIFO, then select() won't make the fd readable again
		 * so we have to check if there's anything pending to be
		 * sent.
		 */
		TAILQ_FOREACH(f, &friendhead, entry) {
			if (tox_get_friend_connection_status(tox, f->fid) == 0)
				continue;
			if (f->t.state != TRANSFER_INPROGRESS)
				continue;
			if (f->t.pending == 1)
				sendfriendfile(f);
		}

		/* Accept pending transfers if any */
		TAILQ_FOREACH(f, &friendhead, entry) {
			if (tox_get_friend_connection_status(tox, f->fid) == 0)
				continue;
			if (f->recvfileactive == 0)
				continue;
			if (f->fd[FFILE_OUT] == -1) {
				r = openat(f->dirfd, ffiles[FFILE_OUT].name,
					   ffiles[FFILE_OUT].flags, 0644);
				if (r < 0) {
					if (errno != ENXIO) {
						perror("openat");
						exit(EXIT_FAILURE);
					}
				} else {
					f->fd[FFILE_OUT] = r;
					tox_file_send_control(tox, f->fid, 1, 0,
							      TOX_FILECONTROL_ACCEPT, NULL, 0);
					printout("Accepted transfer from %s\n",
						 f->namestr[0] == '\0' ? "Anonymous" : f->namestr);
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
				printout("Accepted friend request for %s\n", req->idstr);
				datasave();
			} else {
				printout("Rejected friend request for %s\n", req->idstr);
			}
			unlinkat(gslots[REQUEST].fd[OUT], req->idstr, 0);
			close(req->fd);
			TAILQ_REMOVE(&reqhead, req, entry);
			free(req->msgstr);
			free(req);
		}

		for (f = TAILQ_FIRST(&friendhead); f; f = ftmp) {
			ftmp = TAILQ_NEXT(f, entry);
			for (i = 0; i < LEN(ffiles); i++) {
				if (FD_ISSET(f->fd[i], &rfds) == 0)
					continue;
				switch (i) {
				case FTEXT_IN:
					sendfriendtext(f);
					break;
				case FFILE_IN:
					switch (f->t.state) {
					case TRANSFER_NONE:
						/* Prepare a new transfer */
						f->t.state = TRANSFER_INITIATED;
						now = time(NULL);
						snprintf(tstamp, sizeof(tstamp), "%lu", (unsigned long)now);
						tox_new_file_sender(tox, f->fid,
							0, (uint8_t *)tstamp, strlen(tstamp));
						printout("Initiated transfer to %s\n",
							 f->namestr[0] == '\0' ? "Anonymous" : f->namestr);
						break;
					case TRANSFER_INPROGRESS:
						sendfriendfile(f);
						break;
					}
					break;
				case FREMOVE:
					removefriend(f);
					break;
				default:
					fprintf(stderr, "Unhandled FIFO read\n");
				}
			}
		}
	}
}

static void
initshutdown(int sig)
{
	printout("Shutting down...\n");
	running = 0;
}

static void
shutdown(void)
{
	int i, m;
	struct friend *f, *ftmp;
	struct request *r, *rtmp;

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
		free(r->msgstr);
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
	exit(EXIT_FAILURE);
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

	signal(SIGHUP, initshutdown);
	signal(SIGINT, initshutdown);
	signal(SIGQUIT, initshutdown);
	signal(SIGABRT, initshutdown);
	signal(SIGTERM, initshutdown);

	printrat();
	toxinit();
	localinit();
	friendload();
	loop();
	shutdown();
	return EXIT_SUCCESS;
}
