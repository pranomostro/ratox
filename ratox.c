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
	[TOX_ERR_FRIEND_ADD_NULL]           = "One required argument is missing",
	[TOX_ERR_FRIEND_ADD_TOO_LONG]       = "Message is too long",
	[TOX_ERR_FRIEND_ADD_NO_MESSAGE]     = "Please add a message to your request",
	[TOX_ERR_FRIEND_ADD_OWN_KEY]        = "That appears to be your own ID",
	[TOX_ERR_FRIEND_ADD_ALREADY_SENT]   = "Friend request already sent",
	[TOX_ERR_FRIEND_ADD_BAD_CHECKSUM]   = "Bad checksum while verifying address",
	[TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM] = "Friend already added but invalid nospam",
	[TOX_ERR_FRIEND_ADD_MALLOC]         = "Error increasing the friend list size"
};

const char *callerr[] = {
	[TOXAV_ERR_SEND_FRAME_NULL]                  = "Samples pointer is NULL",
	[TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND]      = "No friend matching this ID",
	[TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL]    = "Currently not in a call",
	[TOXAV_ERR_SEND_FRAME_SYNC]                  = "Synchronization error occurred",
	[TOXAV_ERR_SEND_FRAME_INVALID]               = "One of the frame parameters was invalid",
	[TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED] = "Either friend turned off audio receiving or we turned off sending for the said payload.",
	[TOXAV_ERR_SEND_FRAME_RTP_FAILED]            = "Failed to push frame through rtp interface"
};

struct node {
	char    *addr4;
	char    *addr6;
	uint16_t udp_port;
	uint16_t tcp_port;
	char    *idstr;
};

#include "config.h"

struct file {
	int         type;
	const char *name;
	int         flags;
};

enum { NONE, FIFO, STATIC };
enum { IN, OUT, ERR };

static struct file gfiles[] = {
	[IN]  = { .type = FIFO,	  .name = "in",	 .flags = O_RDONLY | O_NONBLOCK	       },
	[OUT] = { .type = NONE,	  .name = "out", .flags = O_WRONLY | O_TRUNC | O_CREAT },
	[ERR] = { .type = STATIC, .name = "err", .flags = O_WRONLY | O_TRUNC | O_CREAT },
};

static int idfd = -1;

struct slot {
	const char *name;
	void      (*cb)(void *);
	int         outisfolder;
	int         dirfd;
	int         fd[LEN(gfiles)];
};

static void setname(void *);
static void setstatus(void *);
static void setuserstate(void *);
static void sendfriendreq(void *);
static void setnospam(void *);
static void newconf(void *);

enum { NAME, STATUS, STATE, REQUEST, NOSPAM, CONF };

static struct slot gslots[] = {
	[NAME]    = { .name = "name",	 .cb = setname,	      .outisfolder = 0, .dirfd = -1, .fd = {-1, -1, -1} },
	[STATUS]  = { .name = "status",	 .cb = setstatus,     .outisfolder = 0, .dirfd = -1, .fd = {-1, -1, -1} },
	[STATE]   = { .name = "state",	 .cb = setuserstate,  .outisfolder = 0, .dirfd = -1, .fd = {-1, -1, -1} },
	[REQUEST] = { .name = "request", .cb = sendfriendreq, .outisfolder = 1, .dirfd = -1, .fd = {-1, -1, -1} },
	[NOSPAM]  = { .name = "nospam",	 .cb = setnospam,     .outisfolder = 0, .dirfd = -1, .fd = {-1, -1, -1} },
	[CONF]    = { .name = "conf",    .cb = newconf,       .outisfolder = 1, .dirfd = -1, .fd = {-1, -1, -1} },
};

enum { FTEXT_IN, FFILE_IN, FCALL_IN, FTEXT_OUT, FFILE_OUT, FCALL_OUT,
       FREMOVE, FONLINE, FNAME, FSTATUS, FSTATE, FFILE_STATE, FCALL_STATE };

static struct file ffiles[] = {
	[FTEXT_IN]    = { .type = FIFO,	  .name = "text_in",	  .flags = O_RDONLY | O_NONBLOCK	 },
	[FFILE_IN]    = { .type = FIFO,	  .name = "file_in",	  .flags = O_RDONLY | O_NONBLOCK	 },
	[FCALL_IN]    = { .type = FIFO,	  .name = "call_in",	  .flags = O_RDONLY | O_NONBLOCK	 },
	[FTEXT_OUT]   = { .type = STATIC, .name = "text_out",	  .flags = O_WRONLY | O_APPEND | O_CREAT },
	[FFILE_OUT]   = { .type = FIFO,	  .name = "file_out",	  .flags = O_WRONLY | O_NONBLOCK	 },
	[FCALL_OUT]   = { .type = FIFO,	  .name = "call_out",	  .flags = O_WRONLY | O_NONBLOCK	 },
	[FREMOVE]     = { .type = FIFO,	  .name = "remove",	  .flags = O_RDONLY | O_NONBLOCK	 },
	[FONLINE]     = { .type = STATIC, .name = "online",	  .flags = O_WRONLY | O_TRUNC  | O_CREAT },
	[FNAME]	      = { .type = STATIC, .name = "name",	  .flags = O_WRONLY | O_TRUNC  | O_CREAT },
	[FSTATUS]     = { .type = STATIC, .name = "status",	  .flags = O_WRONLY | O_TRUNC  | O_CREAT },
	[FSTATE]      = { .type = STATIC, .name = "state",	  .flags = O_WRONLY | O_TRUNC  | O_CREAT },
	[FFILE_STATE] = { .type = STATIC, .name = "file_pending", .flags = O_WRONLY | O_TRUNC  | O_CREAT },
	[FCALL_STATE] = { .type = STATIC, .name = "call_state",	  .flags = O_WRONLY | O_TRUNC  | O_CREAT },
};

enum { CMEMBERS, CINVITE, CLEAVE, CTITLE_IN, CTITLE_OUT, CTEXT_IN, CTEXT_OUT };

static struct file cfiles[] = {
	[CMEMBERS]    = { .type = STATIC, .name = "members",      .flags = O_WRONLY | O_TRUNC  | O_CREAT },
	[CINVITE]     = { .type = FIFO,	  .name = "invite",	  .flags = O_RDONLY | O_NONBLOCK	 },
	[CLEAVE]      = { .type = FIFO,   .name = "leave",	  .flags = O_RDONLY | O_NONBLOCK	 },
	[CTITLE_IN]   = { .type = FIFO,   .name = "title_in",	  .flags = O_RDONLY | O_NONBLOCK	 },
	[CTITLE_OUT]  = { .type = STATIC, .name = "title_out",	  .flags = O_WRONLY | O_TRUNC  | O_CREAT },
	[CTEXT_IN]    = { .type = FIFO,	  .name = "text_in",	  .flags = O_RDONLY | O_NONBLOCK	 },
	[CTEXT_OUT]   = { .type = STATIC, .name = "text_out",	  .flags = O_WRONLY | O_APPEND | O_CREAT },
};

static char *ustate[] = {
	[TOX_USER_STATUS_NONE]    = "available",
	[TOX_USER_STATUS_AWAY]    = "away",
	[TOX_USER_STATUS_BUSY]    = "busy"
};

enum { TRANSFER_NONE, TRANSFER_INITIATED, TRANSFER_PENDING, TRANSFER_INPROGRESS, TRANSFER_PAUSED };

struct transfer {
	uint32_t fnum;
	uint8_t *buf;
	ssize_t  n;
	int      pendingbuf;
	int      state;
};

enum {
	OUTGOING     = 1 << 0,
	INCOMING     = 1 << 1,
	TRANSMITTING = 1 << 2,
	INCOMPLETE   = 1 << 3,
	RINGING      = 1 << 4,
};

struct call {
	int      state;
	uint8_t *frame;
	ssize_t  n;
	struct   timespec lastsent;
};

struct friend {
	char    name[TOX_MAX_NAME_LENGTH + 1];
	uint32_t num;
	uint8_t id[TOX_PUBLIC_KEY_SIZE];
	char    idstr[2 * TOX_PUBLIC_KEY_SIZE + 1];
	int     dirfd;
	int     fd[LEN(ffiles)];
	struct  transfer tx;
	int     rxstate;
	struct  call av;
	TAILQ_ENTRY(friend) entry;
};

struct conference {
	uint32_t num;
	char     numstr[2 * sizeof(uint32_t) + 1];
	int      dirfd;
	int      fd[LEN(cfiles)];
	TAILQ_ENTRY(conference) entry;
};

struct request {
	uint8_t id[TOX_PUBLIC_KEY_SIZE];
	char    idstr[2 * TOX_PUBLIC_KEY_SIZE + 1];
	char   *msg;
	int     fd;
	TAILQ_ENTRY(request) entry;
};

struct invite {
	char 	*fifoname;
	uint8_t	*cookie;
	size_t	 cookielen;
	uint32_t inviter;
	int	 fd;
	TAILQ_ENTRY(invite) entry;
};

static TAILQ_HEAD(friendhead, friend) friendhead = TAILQ_HEAD_INITIALIZER(friendhead);
static TAILQ_HEAD(confhead, conference) confhead = TAILQ_HEAD_INITIALIZER(confhead);
static TAILQ_HEAD(reqhead, request) reqhead = TAILQ_HEAD_INITIALIZER(reqhead);
static TAILQ_HEAD(invhead, invite) invhead = TAILQ_HEAD_INITIALIZER(invhead);

static Tox *tox;
static ToxAV *toxav;

static int    framesize;

static uint8_t *passphrase;
static uint32_t pplen;

static volatile sig_atomic_t running = 1;

static struct timespec timediff(struct timespec, struct timespec);
static void printrat(void);
static void logmsg(const char *, ...);
static int fifoopen(int, struct file);
static void fiforeset(int, int *, struct file);
static ssize_t fiforead(int, int *, struct file, void *, size_t);
static uint32_t interval(Tox *, struct ToxAV*);

static void cbcallinvite(ToxAV *, uint32_t, bool, bool, void *);
static void cbcallstate(ToxAV *, uint32_t, uint32_t, void *);
static void cbcalldata(ToxAV *, uint32_t, const int16_t *, size_t, uint8_t, uint32_t, void *);

static void cancelcall(struct friend *, char *);
static void sendfriendcalldata(struct friend *);
static void writemembers(struct conference *);

static void cbconnstatus(Tox *, uint32_t, TOX_CONNECTION, void *);
static void cbfriendmessage(Tox *, uint32_t, TOX_MESSAGE_TYPE, const uint8_t *, size_t, void *);
static void cbfriendrequest(Tox *, const uint8_t *, const uint8_t *, size_t, void *);
static void cbnamechange(Tox *, uint32_t, const uint8_t *, size_t, void *);
static void cbstatusmessage(Tox *, uint32_t, const uint8_t *, size_t, void *);
static void cbfriendstate(Tox *, uint32_t, TOX_USER_STATUS, void *);
static void cbfilecontrol(Tox *, uint32_t, uint32_t, TOX_FILE_CONTROL, void *);
static void cbfilesendreq(Tox *, uint32_t, uint32_t, uint32_t, uint64_t, const uint8_t *, size_t, void *);
static void cbfiledata(Tox *, uint32_t, uint32_t, uint64_t, const uint8_t *, size_t, void *);

static void cbconfinvite(Tox *, uint32_t, TOX_CONFERENCE_TYPE, const uint8_t *, size_t, void *);
static void cbconfmessage(Tox *, uint32_t, uint32_t, TOX_MESSAGE_TYPE, const uint8_t *, size_t, void *);
static void cbconftitle(Tox *, uint32_t, uint32_t, const uint8_t *, size_t, void *);
static void cbconfmembers(Tox *, uint32_t, uint32_t, TOX_CONFERENCE_STATE_CHANGE, void *);

static void canceltxtransfer(struct friend *);
static void cancelrxtransfer(struct friend *);
static void sendfriendtext(struct friend *);
static void removefriend(struct friend *);
static void invitefriend(struct conference *);
static void sendconftext(struct conference *);
static void updatetitle(struct conference *);
static int readpass(const char *, uint8_t **, uint32_t *);
static void dataload(struct Tox_Options *);
static void datasave(void);
static int localinit(void);
static int toxinit(void);
static int toxconnect(void);
static void id2str(uint8_t *, char *);
static void str2id(char *, uint8_t *);
static void friendcreate(uint32_t);
static void confcreate(uint32_t);
static void friendload(void);
static void frienddestroy(struct friend *);
static void confdestroy(struct conference *);
static void loop(void);
static void initshutdown(int);
static void toxshutdown(void);
static void usage(void);

#define FD_APPEND(fd) do {	\
	FD_SET((fd), &rfds);	\
	if ((fd) > fdmax)	\
		fdmax = (fd);	\
} while (0)

#undef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))

static struct timespec
timediff(struct timespec t1, struct timespec t2)
{
	struct timespec tmp;

	tmp.tv_sec = t2.tv_sec - t1.tv_sec;

	if ((t2.tv_nsec - t1.tv_nsec) > 0) {
		tmp.tv_nsec = (t2.tv_nsec - t1.tv_nsec);
	} else {
		tmp.tv_nsec = 1E9 - (t1.tv_nsec - t2.tv_nsec);
		tmp.tv_sec--;
	}

	return tmp;
}

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
logmsg(const char *fmt, ...)
{
	time_t  t;
	va_list ap;
	char    buft[64];

	va_start(ap, fmt);
	t = time(NULL);
	strftime(buft, sizeof(buft), "%F %R", localtime(&t));
	printf("%s ", buft);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

static int
fifoopen(int dirfd, struct file f)
{
	int fd;

	fd = openat(dirfd, f.name, f.flags, 0666);
	if (fd < 0 && errno != ENXIO)
		eprintf("openat %s:", f.name);
	return fd;
}

static void
fiforeset(int dirfd, int *fd, struct file f)
{
	ssize_t r;

	r = unlinkat(dirfd, f.name, 0);
	if (r < 0 && errno != ENOENT)
		eprintf("unlinkat %s:", f.name);
	if (*fd != -1)
		close(*fd);
	r = mkfifoat(dirfd, f.name, 0666);
	if (r < 0 && errno != EEXIST)
		eprintf("mkfifoat %s:", f.name);
	*fd = fifoopen(dirfd, f);
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
	} else if (r < 0) {
		if (errno == EINTR)
			goto again;
		if (errno == EWOULDBLOCK)
			return -1;
		eprintf("read %s:", f.name);
	}
	return r;
}

static uint32_t
interval(Tox *m, struct ToxAV *av)
{
	return MIN(tox_iteration_interval(m), toxav_iteration_interval(av));
}

static void
cbcallinvite(ToxAV *av, uint32_t fnum, bool audio, bool video, void *udata)
{
	struct  friend *f;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->num == fnum)
			break;
	if (!f)
		return;

	if (!audio) {
		if (!toxav_call_control(toxav, f->num, TOXAV_CALL_CONTROL_CANCEL, NULL))
			weprintf("Failed to reject call\n");
		logmsg(": %s : Audio > Rejected (no audio)\n", f->name);
		return;
	}

	f->av.state |= RINGING;
	ftruncate(f->fd[FCALL_STATE], 0);
	lseek(f->fd[FCALL_STATE], 0, SEEK_SET);
	dprintf(f->fd[FCALL_STATE], "pending\n");

	logmsg(": %s : Audio > Ringing\n", f->name);
}

static void
cbcallstate(ToxAV *av, uint32_t fnum, uint32_t state, void *udata)
{
	struct friend *f;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->num == fnum)
			break;
	if (!f)
		return;

	if ((state & TOXAV_FRIEND_CALL_STATE_ERROR)
	    || (state & TOXAV_FRIEND_CALL_STATE_FINISHED)) {
		f->av.state &= ~TRANSMITTING;
		cancelcall(f, "Finished");
		return;
	}

	/*
	 * If we've are ringing a friend, and he sends a control that's
	 * not FINISHED, it means he accepted the call, so we can start
	 * transmitting audio frames
	 */
	if (f->av.state & RINGING) {
		f->av.state &= ~RINGING;
		f->av.state |= TRANSMITTING;
		logmsg(": %s : Audio > Transmitting\n", f->name);
	}
}

static void
cbcalldata(ToxAV *av, uint32_t fnum, const int16_t *data, size_t len,
           uint8_t channels, uint32_t rate, void *udata)
{
	struct   friend *f;
	ssize_t  n, wrote;
	int      fd;
	uint8_t *buf;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->num == fnum)
			break;
	if (!f)
		return;
	if (!(f->av.state & INCOMING)) {
		/* try to open call_out for writing */
		fd = fifoopen(f->dirfd, ffiles[FCALL_OUT]);
		if (fd < 0) {
			close (fd);
			return;
		}
		if (f->fd[FCALL_OUT] < 0) {
			f->fd[FCALL_OUT] = fd;
			f->av.state |= INCOMING;
		}
	}

	buf = (uint8_t *)data;
	len *= 2;
	wrote = 0;
	while (len > 0) {
		n = write(f->fd[FCALL_OUT], &buf[wrote], len);
		if (n < 0) {
			if (errno == EPIPE)
				f->av.state &= ~INCOMING;
			break;
		} else if (n == 0) {
			break;
		}
		wrote += n;
		len -= n;
	}
}

static void
cbconfinvite(Tox *m, uint32_t frnum, TOX_CONFERENCE_TYPE type, const uint8_t *cookie, size_t clen, void * udata)
{
	size_t i, j, namelen;
	struct file invfifo;
	struct invite *inv;
	uint8_t id[TOX_PUBLIC_KEY_SIZE];

	if(type != TOX_CONFERENCE_TYPE_TEXT) {
		weprintf("Only text conferences supported at the moment\n");
		return;
	}

	if (!tox_friend_get_public_key(tox, frnum, id, NULL)) {
		weprintf("Failed to get key by friend %i for invite\n", frnum);
		return;
	}

	inv = calloc(1, sizeof(*inv));
	if (!inv)
		eprintf("calloc:");
	inv->fd = -1;

	inv->inviter = frnum;
	inv->cookielen = clen;
	inv->cookie = malloc(inv->cookielen);
	if (!inv->cookie)
		eprintf("malloc:");

	memcpy(inv->cookie, cookie, clen);

	namelen = 2 * TOX_PUBLIC_KEY_SIZE + 1 + 2 * clen + 2;
	inv->fifoname = malloc(namelen);
	if (!inv->fifoname)
		eprintf("malloc:");

	i = 0;
	id2str(id, inv->fifoname);
	i += 2 * TOX_PUBLIC_KEY_SIZE;
	inv->fifoname[i] = '_';
	i++;
	for(j = 0; j < clen; i+=2, j++)
		sprintf(inv->fifoname + i, "%02X", cookie[j]);
	i++;
	inv->fifoname[i] = '\0';

	invfifo.name = inv->fifoname;
	invfifo.flags = O_RDONLY | O_NONBLOCK;
	fiforeset(gslots[CONF].fd[OUT], &inv->fd, invfifo);

	TAILQ_INSERT_TAIL(&invhead, inv, entry);

	logmsg("Invite > %s\n", inv->fifoname);
}

static void
cbconfmessage(Tox *m, uint32_t cnum, uint32_t pnum, TOX_MESSAGE_TYPE type, const uint8_t *data, size_t len, void *udata)
{
	struct  conference *c;
	time_t  t;
	uint8_t msg[len + 1], namt[TOX_MAX_NAME_LENGTH + 1];
	char    buft[64];

	memcpy(msg, data, len);
	msg[len] = '\0';

	TAILQ_FOREACH(c, &confhead, entry) {
		if (c->num == cnum) {
			t = time(NULL);
			strftime(buft, sizeof(buft), "%F %R", localtime(&t));
			if (!tox_conference_peer_get_name(tox, c->num, pnum, namt, NULL)) {
				weprintf("Unable to obtain name for peer %d in conference %s\n", pnum, c->numstr);
				return;
			}
			namt[tox_conference_peer_get_name_size(tox, c->num, pnum, NULL)] = '\0';
			dprintf(c->fd[CTEXT_OUT], "%s <%s> %s\n", buft, namt, msg);
			if (confmsg_log)
				logmsg("%s : %s <%s> %s\n", c->numstr, buft, namt, msg);
			break;
		}
	}
}

static void
cbconftitle(Tox *m, uint32_t cnum, uint32_t pnum, const uint8_t *data, size_t len, void * udata)
{
	struct  conference *c;
	char    title[TOX_MAX_NAME_LENGTH + 1];

	memcpy(title, data, len);
	title[len] = '\0';

	TAILQ_FOREACH(c, &confhead, entry) {
		if (c->num == cnum) {
			ftruncate(c->fd[CTITLE_OUT], 0);
			lseek(c->fd[CTITLE_OUT], 0, SEEK_SET);
			dprintf(c->fd[CTITLE_OUT], "%s\n", title);
			logmsg(": %s : Title > %s\n", c->numstr, title);
			break;
		}
	}
}

static void
cbconfmembers(Tox *m, uint32_t cnum, uint32_t pnum, TOX_CONFERENCE_STATE_CHANGE type, void *udata)
{
	struct  conference *c;

	TAILQ_FOREACH(c, &confhead, entry) {
		if (c->num == cnum) {
			writemembers(c);
			break;
		}
	}
}

static void
cancelcall(struct friend *f, char *action)
{
	logmsg(": %s : Audio > %s\n", f->name, action);

	if (f->av.state & TRANSMITTING || f->av.state & RINGING) {
		if (!toxav_call_control(toxav, f->num, TOXAV_CALL_CONTROL_CANCEL, NULL))
			weprintf("Failed to terminate call\n");
	}
	f->av.state = 0;

	/* Cancel Rx side of the call */
	if (f->fd[FCALL_OUT] != -1) {
		close(f->fd[FCALL_OUT]);
		f->fd[FCALL_OUT] = -1;
	}
	ftruncate(f->fd[FCALL_STATE], 0);
	lseek(f->fd[FCALL_STATE], 0, SEEK_SET);
	dprintf(f->fd[FCALL_STATE], "none\n");

	/* Cancel Tx side of the call */
	free(f->av.frame);
	f->av.frame = NULL;
	fiforeset(f->dirfd, &f->fd[FCALL_IN], ffiles[FCALL_IN]);
}

static void
sendfriendcalldata(struct friend *f)
{
	struct   timespec now, diff;
	ssize_t  n;
	TOXAV_ERR_SEND_FRAME err;

	n = fiforead(f->dirfd, &f->fd[FCALL_IN], ffiles[FCALL_IN],
		     f->av.frame + (f->av.state & INCOMPLETE ? f->av.n : 0),
		     framesize * sizeof(int16_t) - (f->av.state & INCOMPLETE ? f->av.n : 0));
	if (n == 0) {
		f->av.state &= ~OUTGOING;
		f->av.state &= ~INCOMPLETE;
		return;
	} else if (n < 0 || f->av.state & RINGING) {
		/* discard data as long as the call is not established */
		return;
	} else if (n == (framesize * sizeof(int16_t) - (f->av.state & INCOMPLETE ? f->av.n : 0))) {
		f->av.state &= ~INCOMPLETE;
		f->av.n = 0;
	} else {
		f->av.state |= INCOMPLETE;
		f->av.n += n;
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &now);
	diff = timediff(f->av.lastsent, now);
	if (diff.tv_sec == 0 && diff.tv_nsec < (AUDIOFRAME - 1) * 1E6) {
		diff.tv_nsec = (AUDIOFRAME - 1) * 1E6 - diff.tv_nsec;
		nanosleep(&diff, NULL);
	}
	clock_gettime(CLOCK_MONOTONIC, &f->av.lastsent);
	if (!toxav_audio_send_frame(toxav, f->num, (int16_t *)f->av.frame,
	                            framesize, AUDIOCHANNELS, AUDIOSAMPLERATE, &err))
		weprintf("Failed to send audio frame: %s\n", callerr[err]);
}

static void
writemembers(struct conference *c)
{
	size_t i;
	uint32_t peers, pnum;
	uint8_t name[TOX_MAX_NAME_LENGTH + 1];
	TOX_ERR_CONFERENCE_PEER_QUERY err;

	/*The peer list is written when we invite the members by the callback*/
	ftruncate(c->fd[CMEMBERS], 0);
	peers = tox_conference_peer_count(tox, c->num, &err);

	if (err != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
		weprintf("Unable to obtain peer count for conference %d\n", c->num);
		return;
	}
	for (pnum = 0; pnum < peers; pnum++) {
		if (!tox_conference_peer_get_name(tox, c->num, pnum, name, NULL)) {
			weprintf("Unable to obtain the name for peer %d\n", pnum);
		} else {
			i = tox_conference_peer_get_name_size(tox, c->num, pnum, NULL);
			name[i] = '\0';
			dprintf(c->fd[CMEMBERS], "%s\n", name);
		}
	}
}

static void
cbconnstatus(Tox *m, uint32_t frnum, TOX_CONNECTION status, void *udata)
{
	struct friend *f;
	struct request *req, *rtmp;
	size_t r;
	char   name[TOX_MAX_NAME_LENGTH + 1];
	TOX_ERR_FRIEND_QUERY err;

	r = tox_friend_get_name_size(tox, frnum, &err);
	if (err != TOX_ERR_FRIEND_QUERY_OK) {
		weprintf("Failed to get name for friend number %ld\n", (long)frnum);
		return;
	} else if (r == 0) {
		snprintf(name, sizeof(name), "Anonymous");
	} else {
		tox_friend_get_name(tox, frnum, (uint8_t *)name, NULL);
		name[r] = '\0';
	}

	logmsg(": %s : Connection > %s\n", name, status == TOX_CONNECTION_NONE ? "Offline" : "Online");

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->num == frnum) {
			ftruncate(f->fd[FONLINE], 0);
			lseek(f->fd[FONLINE], 0, SEEK_SET);
			dprintf(f->fd[FONLINE], "%d\n", status);
			break;
		}
	}

	/* Remove the pending request-FIFO if it exists */
	for (req = TAILQ_FIRST(&reqhead); req; req = rtmp) {
		rtmp = TAILQ_NEXT(req, entry);

		if (memcmp(f->id, req->id, TOX_PUBLIC_KEY_SIZE))
			continue;
		unlinkat(gslots[REQUEST].fd[OUT], req->idstr, 0);
		close(req->fd);
		TAILQ_REMOVE(&reqhead, req, entry);
		free(req->msg);
		free(req);
	}
}

static void
cbfriendmessage(Tox *m, uint32_t frnum, TOX_MESSAGE_TYPE type, const uint8_t *data, size_t len, void *udata)
{
	struct  friend *f;
	time_t  t;
	uint8_t msg[len + 1];
	char    buft[64];

	memcpy(msg, data, len);
	msg[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->num == frnum) {
			t = time(NULL);
			strftime(buft, sizeof(buft), "%F %R", localtime(&t));
			dprintf(f->fd[FTEXT_OUT], "%s %s\n", buft, msg);
			if (friendmsg_log)
				logmsg(": %s > %s\n", f->name, msg);
			break;
		}
	}
}

static void
cbfriendrequest(Tox *m, const uint8_t *id, const uint8_t *data, size_t len, void *udata)
{
	struct file reqfifo;
	struct request *req;

	req = calloc(1, sizeof(*req));
	if (!req)
		eprintf("calloc:");
	req->fd = -1;

	memcpy(req->id, id, TOX_PUBLIC_KEY_SIZE);
	id2str(req->id, req->idstr);

	if (len > 0) {
		req->msg = malloc(len + 1);
		if (!req->msg)
			eprintf("malloc:");
		memcpy(req->msg, data, len);
		req->msg[len] = '\0';
	} else {
		req->msg = "ratox is awesome!";
	}

	reqfifo.name = req->idstr;
	reqfifo.flags = O_RDONLY | O_NONBLOCK;
	fiforeset(gslots[REQUEST].fd[OUT], &req->fd, reqfifo);

	TAILQ_INSERT_TAIL(&reqhead, req, entry);

	logmsg("Request > %s : %s\n",
	       req->idstr, req->msg);
}

static void
cbnamechange(Tox *m, uint32_t frnum, const uint8_t *data, size_t len, void *user)
{
	struct  friend *f;
	uint8_t name[len + 1];

	memcpy(name, data, len);
	name[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->num == frnum) {
			if (memcmp(f->name, name, len + 1) == 0)
				break;
			ftruncate(f->fd[FNAME], 0);
			lseek(f->fd[FNAME], 0, SEEK_SET);
			dprintf(f->fd[FNAME], "%s\n", name);
			logmsg(": %s : Name > %s\n", f->name, name);
			memcpy(f->name, name, len + 1);
			break;
		}
	}
	datasave();
}

static void
cbstatusmessage(Tox *m, uint32_t frnum, const uint8_t *data, size_t len, void *udata)
{
	struct friend *f;
	uint8_t status[len + 1];

	memcpy(status, data, len);
	status[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->num == frnum) {
			ftruncate(f->fd[FSTATUS], 0);
			lseek(f->fd[FSTATUS], 0, SEEK_SET);
			dprintf(f->fd[FSTATUS], "%s\n", status);
			logmsg(": %s : Status > %s\n", f->name, status);
			break;
		}
	}
	datasave();
}

static void
cbfriendstate(Tox *m, uint32_t frnum, TOX_USER_STATUS state, void *udata)
{
	struct friend *f;

	if (state >= LEN(ustate)) {
		weprintf("Received invalid user status: %d\n", state);
		return;
	}

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->num == frnum) {
			ftruncate(f->fd[FSTATE], 0);
			lseek(f->fd[FSTATE], 0, SEEK_SET);
			dprintf(f->fd[FSTATE], "%s\n", ustate[state]);
			logmsg(": %s : State > %s\n", f->name, ustate[state]);
			break;
		}
	}
	datasave();
}

static void
cbfilecontrol(Tox *m, uint32_t frnum, uint32_t fnum, TOX_FILE_CONTROL ctrltype, void *udata)
{
	struct friend *f;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->num == frnum)
			break;
	if (!f)
		return;

	switch (ctrltype) {
	case TOX_FILE_CONTROL_RESUME:
		if (f->tx.state == TRANSFER_PAUSED) {
			logmsg(": %s : Tx > Resumed\n", f->name);
			f->tx.state = TRANSFER_INPROGRESS;
		} else {
			f->tx.fnum = fnum;
			f->tx.buf = malloc(TOX_MAX_CUSTOM_PACKET_SIZE);
			if (!f->tx.buf)
				eprintf("malloc:");
			f->tx.n = 0;
			f->tx.pendingbuf = 0;
			f->tx.state = TRANSFER_INPROGRESS;
			logmsg(": %s : Tx > In Progress\n", f->name);
		}
		break;
	case TOX_FILE_CONTROL_PAUSE:
		if (f->tx.state == TRANSFER_INPROGRESS) {
			logmsg(": %s : Tx > Paused\n", f->name);
			f->tx.state = TRANSFER_PAUSED;
		}
		break;
	case TOX_FILE_CONTROL_CANCEL:
		/* Check wether we're sending or receiving */
		if (f->tx.fnum == fnum) {
			logmsg(": %s : Tx > Rejected\n", f->name);
			f->tx.state = TRANSFER_NONE;
			free(f->tx.buf);
			f->tx.buf = NULL;
			fiforeset(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN]);
		} else {
			logmsg(": %s : Rx > Cancelled by Sender\n", f->name);
			cancelrxtransfer(f);
		}
		break;
	default:
		weprintf("Unhandled file control type: %d\n", ctrltype);
		break;
	};
}

static void
cbfiledatareq(Tox *m, uint32_t frnum, uint32_t fnum, uint64_t pos, size_t flen, void *udata)
{
	struct friend *f;
	ssize_t n;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->num == frnum)
			break;

	/* Grab another buffer from the FIFO */
	if (!f->tx.pendingbuf) {
		n = fiforead(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN],
		             f->tx.buf, flen);
		f->tx.n = n;
		f->tx.pendingbuf = 0;
	}

	if (f->tx.n < 0) {
		if (errno != EWOULDBLOCK)
			weprintf("Reading data for file sending would block\n");
		return;
	}

	if (!tox_file_send_chunk(tox, f->num, f->tx.fnum, pos, f->tx.buf, f->tx.n, NULL))
		f->tx.pendingbuf = 1;

	/*
	 * For streams, core will know that the transfer is finished
	 * if a chunk with length less than the length requested in the
	 * callback is sent.
	 */
	if (!f->tx.pendingbuf && (size_t)f->tx.n < flen) {
		logmsg(": %s : Tx > Complete\n", f->name);
		f->tx.state = TRANSFER_NONE;
		f->tx.fnum = -1;
		free(f->tx.buf);
		f->tx.buf = NULL;
		fiforeset(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN]);
		return;
	}
}

static void
cbfilesendreq(Tox *m, uint32_t frnum, uint32_t fnum, uint32_t kind, uint64_t fsz,
	      const uint8_t *fname, size_t flen, void *udata)
{
	struct  friend *f;
	uint8_t filename[flen + 1];

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->num == frnum)
			break;
	if (!f)
		return;

	memcpy(filename, fname, flen);
	filename[flen] = '\0';

	if (kind == TOX_FILE_KIND_AVATAR) {
		if (!tox_file_control(tox, f->num, fnum, TOX_FILE_CONTROL_CANCEL, NULL))
			weprintf("Failed to kill avatar transfer\n");
		return;
	}

	/* We only support a single transfer at a time */
	if (f->rxstate == TRANSFER_INPROGRESS) {
		logmsg(": %s : Rx > Rejected %s, already one in progress\n",
		       f->name, filename);
		if (!tox_file_control(tox, f->num, f->tx.fnum, TOX_FILE_CONTROL_CANCEL, NULL))
			weprintf("Failed to kill new Rx transfer\n");
		return;
	}

	f->tx.fnum = fnum;

	ftruncate(f->fd[FFILE_STATE], 0);
	lseek(f->fd[FFILE_STATE], 0, SEEK_SET);
	dprintf(f->fd[FFILE_STATE], "%s\n", filename);
	f->rxstate = TRANSFER_PENDING;
	logmsg(": %s : Rx > Pending %s\n", f->name, filename);
}

static void
cbfiledata(Tox *m, uint32_t frnum, uint32_t fnum, uint64_t pos,
	   const uint8_t *data, size_t len, void *udata)
{
	struct   friend *f;
	ssize_t  n;
	uint16_t wrote = 0;

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->num == frnum)
			break;
	if (!f)
		return;

	/* When length is 0, the transfer is finished */
	if (!len) {
		logmsg(": %s : Rx > Complete\n", f->name);
		if (f->fd[FFILE_OUT] != -1) {
			close(f->fd[FFILE_OUT]);
			f->fd[FFILE_OUT] = -1;
		}
		ftruncate(f->fd[FFILE_STATE], 0);
		lseek(f->fd[FFILE_STATE], 0, SEEK_SET);
		f->rxstate = TRANSFER_NONE;
		return;
	}

	while (len > 0) {
		n = write(f->fd[FFILE_OUT], &data[wrote], len);
		if (n < 0) {
			if (errno == EPIPE) {
				cancelrxtransfer(f);
				break;
			} else if (errno == EWOULDBLOCK) {
				continue;
			}
		}
		wrote += n;
		len -= n;
	}
}

static void
canceltxtransfer(struct friend *f)
{
	if (f->tx.state == TRANSFER_NONE)
		return;
	logmsg(": %s : Tx > Cancelling\n", f->name);
	if (!tox_file_control(tox, f->num, f->tx.fnum, TOX_FILE_CONTROL_CANCEL, NULL))
		weprintf("Failed to kill Tx transfer\n");
	f->tx.fnum = -1;
	f->tx.state = TRANSFER_NONE;
	free(f->tx.buf);
	f->tx.buf = NULL;
	fiforeset(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN]);
}

static void
cancelrxtransfer(struct friend *f)
{
	if (f->rxstate == TRANSFER_NONE)
		return;
	logmsg(": %s : Rx > Cancelling\n", f->name);
	if (!tox_file_control(tox, f->num, f->tx.fnum, TOX_FILE_CONTROL_CANCEL, NULL))
		weprintf("Failed to kill Rx transfer\n");
	if (f->fd[FFILE_OUT] != -1) {
		close(f->fd[FFILE_OUT]);
		f->fd[FFILE_OUT] = -1;
	}
	ftruncate(f->fd[FFILE_STATE], 0);
	lseek(f->fd[FFILE_STATE], 0, SEEK_SET);
	f->rxstate = TRANSFER_NONE;
}

static void
sendfriendtext(struct friend *f)
{
	ssize_t n;
	uint8_t buf[TOX_MAX_MESSAGE_LENGTH];
	TOX_ERR_FRIEND_SEND_MESSAGE err;

	n = fiforead(f->dirfd, &f->fd[FTEXT_IN], ffiles[FTEXT_IN], buf, sizeof(buf));
	if (n <= 0)
		return;
	if (buf[n - 1] == '\n' && n > 1)
		n--;
	tox_friend_send_message(tox, f->num, TOX_MESSAGE_TYPE_NORMAL, buf, n, &err);
	if (err != TOX_ERR_FRIEND_SEND_MESSAGE_OK)
		weprintf("Failed to send message\n");
}

static void
removefriend(struct friend *f)
{
	char c;

	if (fiforead(f->dirfd, &f->fd[FREMOVE], ffiles[FREMOVE], &c, 1) != 1 || c != '1')
		return;
	tox_friend_delete(tox, f->num, NULL);
	datasave();
	logmsg(": %s > Removed\n", f->name);
	frienddestroy(f);
}

static void
invitefriend(struct conference *c)
{
	ssize_t n;
	char buf[2 * TOX_ADDRESS_SIZE + 1];
	struct friend *f;

	n = fiforead(c->dirfd, &c->fd[CINVITE], cfiles[CINVITE], buf, sizeof(buf));

	if (n > sizeof(buf) || n <= 0)
		return;
	if (buf[n - 1] == '\n')
		buf[n - 1] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry)
		if (!memcmp(buf, f->idstr, sizeof(f->idstr)-1))
			break;
	if (!f) {
		weprintf("No friend with id %s found for %s\n", buf, c->numstr);
		return;
	}
	if (tox_friend_get_connection_status(tox, f->num, NULL) == TOX_CONNECTION_NONE) {
		weprintf("%s not online, can't be invited to %s\n", buf, c->numstr);
		return;
	}
	if (!tox_conference_invite(tox, f->num, c->num, NULL))
		weprintf("Failed to invite %s\n", buf);
	else
		logmsg("- %s : Invited > %s\n", c->numstr, buf);
}

static void
sendconftext(struct conference *c)
{
	ssize_t n;
	uint8_t buf[TOX_MAX_MESSAGE_LENGTH];

	n = fiforead(c->dirfd, &c->fd[CTEXT_IN], cfiles[CTEXT_IN], buf, sizeof(buf));
	if (n <= 0)
		return;
	if (buf[n - 1] == '\n' && n > 1)
		n--;
	if (!tox_conference_send_message(tox, c->num, TOX_MESSAGE_TYPE_NORMAL,
	    buf, n, NULL))
		weprintf("Failed to send message to %s\n", c->numstr);
}

static void
updatetitle(struct conference *c)
{
	ssize_t n;
	uint8_t title[TOX_MAX_STATUS_MESSAGE_LENGTH + 1];

	n = fiforead(c->dirfd, &c->fd[CTITLE_IN], cfiles[CTITLE_IN], title, sizeof(title) - 1);
	if (n <= 0)
		return;
	if (title[n - 1] == '\n')
		n--;
	title[n] = '\0';
	if (!tox_conference_set_title(tox, c->num, title, n, NULL)) {
		weprintf("Failed to set title for %s to \"%s\"\n", c->numstr, title);
		return;
	}
	ftruncate(c->fd[CTITLE_OUT], 0);
	lseek(c->fd[CTITLE_OUT], 0, SEEK_SET);
	dprintf(c->fd[CTITLE_OUT], "%s\n", title);
	logmsg("- %s : Title > %s\n", c->numstr, title);
}

static int
readpass(const char *prompt, uint8_t **target, uint32_t *len)
{
	char pass[BUFSIZ], *p;

	p = readpassphrase(prompt, pass, sizeof(pass), RPP_ECHO_OFF);
	if (!p) {
		weprintf("Could not read passphrase");
		return -1;
	}
	if (p[0] == '\0')
		return -1;
	*target = realloc(*target, strlen(p)); /* not null-terminated */
	if (!*target)
		eprintf("realloc:");
	memcpy(*target, p, strlen(p));
	*len = strlen(p);
	return 0;
}

static void
dataload(struct Tox_Options *toxopt)
{
	off_t    sz;
	uint32_t pp2len = 0;
	int      fd;
	uint8_t *data, * intermediate, *passphrase2 = NULL;

	fd = open(savefile, O_RDONLY);
	if (fd < 0) {
		if (encryptsavefile) {
reprompt1:
			while (readpass("Data : New passphrase > ", &passphrase, &pplen) < 0);
			while (readpass("Data : Re-enter passphrase > ", &passphrase2, &pp2len) < 0);

			if (pplen != pp2len || memcmp(passphrase, passphrase2, pplen)) {
				weprintf("Data passphrase mismatch\n");
				goto reprompt1;
			}
			free(passphrase2);
		}
		return;
	}

	sz = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	if (sz == 0) {
		weprintf("Datafile %s is empty\n", savefile);
		return;
	} else if (sz < 0) {
		weprintf("Datafile %s can't be seeked\n", savefile);
		return;
	}

	intermediate = malloc(sz);
	if (!intermediate)
		eprintf("malloc:");

	if (read(fd, intermediate, sz) != sz)
		eprintf("read %s:", savefile);

	if (tox_is_data_encrypted(intermediate)) {
		toxopt->savedata_length = sz-TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
		data = malloc(toxopt->savedata_length);
		if (!data)
			eprintf("malloc:");
		if (!encryptsavefile)
			logmsg("Data : %s > Encrypted, but saving unencrypted\n", savefile);
		while (readpass("Data : Passphrase > ", &passphrase, &pplen) < 0 ||
		       !tox_pass_decrypt(intermediate, sz, passphrase, pplen, data, NULL));
	} else {
		toxopt->savedata_length = sz;
		data = malloc(sz);
		if (!data)
			eprintf("malloc:");
		memcpy(data, intermediate, sz);
		if (encryptsavefile) {
			logmsg("Data : %s > Not encrypted, but saving encrypted\n", savefile);
reprompt2:
			while (readpass("Data : New passphrase > ", &passphrase, &pplen) < 0);
			while (readpass("Data : Re-enter passphrase > ", &passphrase2, &pp2len) < 0);

			if (pplen != pp2len || memcmp(passphrase, passphrase2, pplen)) {
				weprintf("Data passphrase mismatch\n");
				goto reprompt2;
			}
			free(passphrase2);
		}
	}

	toxopt->savedata_data = data;
	toxopt->savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;

	free(intermediate);
	close(fd);
}

static void
datasave(void)
{
	off_t    sz;
	int      fd;
	uint8_t *data, *intermediate;

	fd = open(savefile, O_WRONLY | O_TRUNC | O_CREAT , 0666);
	if (fd < 0)
		eprintf("open %s:", savefile);

	sz = tox_get_savedata_size(tox);
	intermediate = malloc(sz);
	if (!intermediate)
		eprintf("malloc:");

	tox_get_savedata(tox, intermediate);

	sz += encryptsavefile ? TOX_PASS_ENCRYPTION_EXTRA_LENGTH : 0;
	data = malloc(sz);
	if (!data)
		eprintf("malloc:");

	if (encryptsavefile){
		tox_pass_encrypt(intermediate, sz - TOX_PASS_ENCRYPTION_EXTRA_LENGTH, passphrase, pplen, data, NULL);
	} else {
		memcpy(data, intermediate, sz);
	}
	if (write(fd, data, sz) != sz)
		eprintf("write %s:", savefile);
	fsync(fd);

	free(data);
	free(intermediate);
	close(fd);
}

static int
localinit(void)
{
	DIR    *d;
	size_t  i, m;
	int     r;
	uint8_t name[TOX_MAX_NAME_LENGTH + 1];
	uint8_t address[TOX_ADDRESS_SIZE];
	uint8_t status[TOX_MAX_STATUS_MESSAGE_LENGTH + 1];

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
				gslots[i].fd[m] = fifoopen(gslots[i].dirfd, gfiles[m]);
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
	r = tox_self_get_name_size(tox);
	if (r == 0) {
		logmsg("Name > Empty\n");
	}
	tox_self_get_name(tox, name);
	name[r] = '\0';
	ftruncate(gslots[NAME].fd[OUT], 0);
	dprintf(gslots[NAME].fd[OUT], "%s\n", name);

	/* Dump status */
	r = tox_self_get_status_message_size(tox);
	if (r == 0) {
		logmsg("Status > Empty\n");
	}
	tox_self_get_status_message(tox, status);
	status[r] = '\0';
	ftruncate(gslots[STATUS].fd[OUT], 0);
	dprintf(gslots[STATUS].fd[OUT], "%s\n", status);

	/* Dump user state */
	r = tox_self_get_status(tox);
	ftruncate(gslots[STATE].fd[OUT], 0);
	dprintf(gslots[STATE].fd[OUT], "%s\n", ustate[r]);

	/* Dump ID */
	idfd = open("id", O_WRONLY | O_CREAT, 0666);
	if (idfd < 0)
		eprintf("open id:");
	tox_self_get_address(tox, address);
	for (i = 0; i < TOX_ADDRESS_SIZE; i++)
		dprintf(idfd, "%02X", address[i]);
	dprintf(idfd, "\n");

	/* Dump Nospam */
	ftruncate(gslots[NOSPAM].fd[OUT], 0);
	dprintf(gslots[NOSPAM].fd[OUT], "%08X\n", tox_self_get_nospam(tox));

	return 0;
}

static int
toxinit(void)
{
	struct Tox_Options toxopt;

	tox_options_default(&toxopt);

	toxopt.ipv6_enabled = ipv6;
	toxopt.udp_enabled = !tcp;
	if (proxy) {
		tcp = 1;
		toxopt.udp_enabled = !tcp;
		logmsg("Net > Forcing TCP mode\n");
		toxopt.proxy_host = proxyaddr;
		toxopt.proxy_port = proxyport;
		toxopt.proxy_type = proxytype;
		logmsg("Net > Using proxy %s:%hu\n", proxyaddr, proxyport);
	}

	dataload(&toxopt);

	tox = tox_new(&toxopt, NULL);
	if (!tox)
		eprintf("Core : Tox > Initialization failed\n");

	datasave();

	toxav = toxav_new(tox, NULL);
	if (!toxav)
		eprintf("Core : ToxAV > Initialization failed\n");

	framesize = (AUDIOSAMPLERATE * AUDIOFRAME * AUDIOCHANNELS) / 1000;

	tox_callback_friend_connection_status(tox, cbconnstatus);
	tox_callback_friend_message(tox, cbfriendmessage);
	tox_callback_friend_request(tox, cbfriendrequest);
	tox_callback_friend_name(tox, cbnamechange);
	tox_callback_friend_status_message(tox, cbstatusmessage);
	tox_callback_friend_status(tox, cbfriendstate);
	tox_callback_file_recv_control(tox, cbfilecontrol);
	tox_callback_file_recv(tox, cbfilesendreq);
	tox_callback_file_recv_chunk(tox, cbfiledata);
	tox_callback_file_chunk_request(tox, cbfiledatareq);

	toxav_callback_call(toxav, cbcallinvite, NULL);
	toxav_callback_call_state(toxav, cbcallstate, NULL);

	toxav_callback_audio_receive_frame(toxav, cbcalldata, NULL);

	tox_callback_conference_invite(tox, cbconfinvite);
	tox_callback_conference_message(tox, cbconfmessage);
	tox_callback_conference_title(tox, cbconftitle);
	tox_callback_conference_namelist_change(tox, cbconfmembers);

	if (toxopt.savedata_data)
		free((void *)toxopt.savedata_data);

	return 0;
}

static int
toxconnect(void)
{
	struct  node *n;
	struct  node tmp;
	size_t  i, j;
	bool r;
	uint8_t id[TOX_ADDRESS_SIZE];

	srand(time(NULL));

	/* shuffle it to minimize load on nodes */
	for (i = LEN(nodes) - 1; i > 0; i--) {
		j = rand() % LEN(nodes);
		tmp = nodes[j];
		nodes[j] = nodes[i];
		nodes[i] = tmp;
	}

	for (i = 0; i < LEN(nodes); i++) {
		n = &nodes[i];
		if (ipv6 && !n->addr6)
			continue;
		str2id(n->idstr, id);
		r = tox_bootstrap(tox, ipv6 ? n->addr6 : n->addr4, n->udp_port, id, NULL);
		if (!r)
			weprintf("Bootstrap failed for %s\n", ipv6 ? n->addr6 : n->addr4);
		str2id(n->idstr, id);
		r += tox_add_tcp_relay(tox, ipv6 ? n->addr6 : n->addr4, n->tcp_port, id, NULL);
		if (!r)
			weprintf("Adding a relay failed for %s\n", ipv6 ? n->addr6 : n->addr4);
	}
	return 0;
}

/* Caller has to ensure `idstr' is big enough */
static void
id2str(uint8_t *id, char *idstr)
{
	int  i;
	char hex[] = "0123456789ABCDEF";

	for (i = 0; i < TOX_PUBLIC_KEY_SIZE; i++) {
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
	char  *p = idstr;

	for (i = 0; i < len; ++i, p += 2)
		sscanf(p, "%2hhx", &id[i]);
}

static void
friendcreate(uint32_t frnum)
{
	struct  friend *f;
	DIR    *d;
	size_t  i;
	int     r;
	uint8_t status[TOX_MAX_STATUS_MESSAGE_LENGTH + 1];
	TOX_ERR_FRIEND_QUERY err;

	f = calloc(1, sizeof(*f));
	if (!f)
		eprintf("calloc:");

	i = tox_friend_get_name_size(tox, frnum, &err);
	if (err != TOX_ERR_FRIEND_QUERY_OK) {
		weprintf("Failed to get name for %ld\n", (long)frnum);
		return;
	} else if (i == 0) {
		snprintf(f->name, sizeof(f->name), "Anonymous");
	} else {
		tox_friend_get_name(tox, frnum, (uint8_t *)f->name, NULL);
		f->name[i] = '\0';
	}

	f->num = frnum;
	if (!tox_friend_get_public_key(tox, f->num, f->id, NULL)) {
		weprintf("Failed to get key for %s\n", f->name);
		return;
	}
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
			f->fd[i] = fifoopen(f->dirfd, ffiles[i]);
		}
	}

	/* Dump name */
	ftruncate(f->fd[FNAME], 0);
	dprintf(f->fd[FNAME], "%s\n", f->name);

	/* Dump online state */
	ftruncate(f->fd[FONLINE], 0);
	dprintf(f->fd[FONLINE], "%d\n",
		tox_friend_get_connection_status(tox, frnum, NULL));

	/* Dump status */
	i = tox_friend_get_status_message_size(tox, frnum, NULL);
	if (i == SIZE_MAX) {
		weprintf("Failed to get status for %s\n", f->name);
		i = 0;
	}
	tox_friend_get_status_message(tox, frnum, status, NULL);
	status[i] = '\0';
	ftruncate(f->fd[FSTATUS], 0);
	dprintf(f->fd[FSTATUS], "%s\n", status);

	/* Dump user state */
	ftruncate(f->fd[FSTATE], 0);
	dprintf(f->fd[FSTATE], "%s\n", ustate[tox_friend_get_status(tox, frnum, NULL)]);

	/* Dump file pending state */
	ftruncate(f->fd[FFILE_STATE], 0);

	/* Dump call pending state */
	ftruncate(f->fd[FCALL_STATE], 0);
	dprintf(f->fd[FCALL_STATE], "none\n");

	f->av.state = 0;

	TAILQ_INSERT_TAIL(&friendhead, f, entry);
}

static void
confcreate(uint32_t cnum)
{
	struct conference *c;
	DIR	 *d;
	size_t	 i;
	int	 r;
	uint8_t	 title[TOX_MAX_NAME_LENGTH + 1];
	TOX_ERR_CONFERENCE_TITLE err;

	c = calloc(1, sizeof(*c));
	if(!c)
		eprintf("calloc:");
	c->num = cnum;
	sprintf(c->numstr, "%08X", c->num);
	r = mkdir(c->numstr, 0777);
	if(r < 0 && errno != EEXIST)
		eprintf("mkdir %s:", c->numstr);

	d = opendir(c->numstr);
	if (!d)
		eprintf("opendir %s:", c->numstr);

	r = dirfd(d);
	if (r < 0)
		eprintf("dirfd %s:", c->numstr);
	c->dirfd = r;

	for (i = 0; i < LEN(cfiles); i++) {
		c->fd[i] = -1;
		if (cfiles[i].type == FIFO) {
			fiforeset(c->dirfd, &c->fd[i], cfiles[i]);
		} else if (cfiles[i].type == STATIC) {
			c->fd[i] = fifoopen(c->dirfd, cfiles[i]);
		}
	}

	writemembers(c);

	/* No warning is printed here in the case of an error
	 * because this always fails when joining after an invite,
	 * but cbconftitle() is called in the next iteration afterwards,
	 * so it doesn't matter after all.
	 */

	i = tox_conference_get_title_size(tox, c->num, &err);
	if (err != TOX_ERR_CONFERENCE_TITLE_OK)
		i = 0;
	tox_conference_get_title(tox, c->num, title, NULL);
	title[i] = '\0';
	ftruncate(c->fd[CTITLE_OUT], 0);
	dprintf(c->fd[CTITLE_OUT], "%s\n", title);

	TAILQ_INSERT_TAIL(&confhead, c, entry);

	logmsg("- %s > Created\n", c->numstr);
}

static void
frienddestroy(struct friend *f)
{
	size_t i;

	canceltxtransfer(f);
	cancelrxtransfer(f);
	if (f->av.state > 0)
		cancelcall(f, "Destroying");
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
confdestroy(struct conference *c)
{
	size_t i;

	for (i = 0; i <LEN(cfiles); i++) {
		if(c->dirfd != -1) {
			unlinkat(c->dirfd, cfiles[i].name, 0);
			if (c->fd[i] != -1)
				close(c->fd[i]);
		}
	}
	rmdir(c->numstr);
	TAILQ_REMOVE(&confhead, c, entry);
}

static void
friendload(void)
{
	size_t sz;
	uint32_t i;
	uint32_t *frnums;

	sz = tox_self_get_friend_list_size(tox);
	frnums = malloc(sz * sizeof(*frnums));
	if (!frnums)
		eprintf("malloc:");

	tox_self_get_friend_list(tox, frnums);

	for (i = 0; i < sz; i++)
		friendcreate(frnums[i]);

	free(frnums);
}

static void
setname(void *data)
{
	ssize_t n;
	int     r;
	char    name[TOX_MAX_NAME_LENGTH + 1];

	ftruncate(gslots[NAME].fd[ERR], 0);
	lseek(gslots[NAME].fd[ERR], 0, SEEK_SET);

	n = fiforead(gslots[NAME].dirfd, &gslots[NAME].fd[IN],
		     gfiles[IN], name, sizeof(name) - 1);
	if (n <= 0)
		return;
	if (name[n - 1] == '\n')
		n--;
	name[n] = '\0';
	r = tox_self_set_name(tox, (uint8_t *)name, n, NULL);
	if (r < 0) {
		dprintf(gslots[STATE].fd[ERR], "Failed to set name to \"%s\"\n", name);
		weprintf("Failed to set name to \"%s\"\n", name);
		return;
	}
	datasave();
	logmsg("Name > %s\n", name);
	ftruncate(gslots[NAME].fd[OUT], 0);
	lseek(gslots[NAME].fd[OUT], 0, SEEK_SET);
	dprintf(gslots[NAME].fd[OUT], "%s\n", name);
}

static void
setstatus(void *data)
{
	ssize_t n;
	int     r;
	uint8_t status[TOX_MAX_STATUS_MESSAGE_LENGTH + 1];

	ftruncate(gslots[STATUS].fd[ERR], 0);
	lseek(gslots[STATUS].fd[ERR], 0, SEEK_SET);

	n = fiforead(gslots[STATUS].dirfd, &gslots[STATUS].fd[IN], gfiles[IN],
		     status, sizeof(status) - 1);
	if (n <= 0)
		return;
	if (status[n - 1] == '\n')
		n--;
	status[n] = '\0';
	r = tox_self_set_status_message(tox, status, n, NULL);
	if (r < 0) {
		dprintf(gslots[STATUS].fd[ERR], "Failed so set status message to \"%s\"\n", status);
		weprintf("Failed to set status message to \"%s\"\n", status);
		return;
	}
	datasave();
	logmsg("Status > %s\n", status);
	ftruncate(gslots[STATUS].fd[OUT], 0);
	lseek(gslots[STATUS].fd[OUT], 0, SEEK_SET);
	dprintf(gslots[STATUS].fd[OUT], "%s\n", status);
}

static void
setuserstate(void *data)
{
	size_t  i;
	ssize_t n;
	char    buf[PIPE_BUF];

	ftruncate(gslots[STATE].fd[ERR], 0);
	lseek(gslots[STATE].fd[ERR], 0, SEEK_SET);

	n = fiforead(gslots[STATE].dirfd, &gslots[STATE].fd[IN], gfiles[IN],
		     buf, sizeof(buf) - 1);
	if (n <= 0)
		return;
	if (buf[n - 1] == '\n')
		n--;
	buf[n] = '\0';
	for (i = 0; i < LEN(ustate); i++) {
		if (strcmp(buf, ustate[i]) == 0) {
			tox_self_set_status(tox, i);
			break;
		}
	}
	if (i == LEN(ustate)) {
		dprintf(gslots[STATE].fd[ERR], "Invalid state %s\n", buf);
		weprintf("Invalid state %s\n", buf);
		return;
	}

	ftruncate(gslots[STATE].fd[OUT], 0);
	lseek(gslots[STATE].fd[OUT], 0, SEEK_SET);
	dprintf(gslots[STATE].fd[OUT], "%s\n", buf);
	datasave();
	logmsg("State > %s\n", buf);
}

static void
sendfriendreq(void *data)
{
	ssize_t n;
	uint32_t r;
	char    buf[PIPE_BUF], *p;
	char   *msg = "ratox is awesome!";
	uint8_t id[TOX_ADDRESS_SIZE];
	TOX_ERR_FRIEND_ADD err;

	ftruncate(gslots[REQUEST].fd[ERR], 0);
	lseek(gslots[REQUEST].fd[ERR], 0, SEEK_SET);

	n = fiforead(gslots[REQUEST].dirfd, &gslots[REQUEST].fd[IN], gfiles[IN],
		     buf, sizeof(buf) - 1);
	if (n <= 0)
		return;
	buf[n] = '\0';

	/* locate start of msg */
	for (p = buf; *p && !isspace(*p); p++)
		;
	if (*p == '\0')
		goto out; /* no msg */
	*p++ = '\0';
	if (*p == '\0') {
		goto out; /* no msg */
	} else {
		msg = p;
		if (msg[strlen(msg) - 1] == '\n')
			msg[strlen(msg) - 1] = '\0';
	}
out:
	if (strlen(buf) != sizeof(id) * 2) {
		dprintf(gslots[REQUEST].fd[ERR], "Invalid friend ID\n");
		weprintf("Invalid friend ID\n");
		return;
	}
	str2id(buf, id);

	r = tox_friend_add(tox, id, (uint8_t *)msg, strlen(msg), &err);

	if (err != TOX_ERR_FRIEND_ADD_OK) {
		dprintf(gslots[REQUEST].fd[ERR], "%s\n", reqerr[err]);
		weprintf("%s\n", reqerr[err]);
		return;
	}
	friendcreate(r);
	datasave();
	logmsg("Request > Sent\n");
}

static void
setnospam(void *data)
{
	ssize_t  n, i;
	uint32_t nsval;
	uint8_t  nospam[2 * sizeof(uint32_t) + 1];
	uint8_t  address[TOX_ADDRESS_SIZE];

	ftruncate(gslots[NOSPAM].fd[ERR], 0);
	lseek(gslots[NOSPAM].fd[ERR], 0, SEEK_SET);

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
			weprintf("Input contains invalid characters ![0-9, A-F]\n");
			goto end;
		}
	}

	nsval = strtoul((char *)nospam, NULL, 16);
	tox_self_set_nospam(tox, nsval);
	datasave();
	logmsg("Nospam > %08X\n", nsval);
	ftruncate(gslots[NOSPAM].fd[OUT], 0);
	lseek(gslots[NOSPAM].fd[OUT], 0, SEEK_SET);
	dprintf(gslots[NOSPAM].fd[OUT], "%08X\n", nsval);

	tox_self_get_address(tox, address);
	ftruncate(idfd, 0);
	lseek(idfd, 0, SEEK_SET);
	for (i = 0; i < TOX_ADDRESS_SIZE; i++)
		dprintf(idfd, "%02X", address[i]);
	dprintf(idfd, "\n");
end:
	fiforeset(gslots[NOSPAM].dirfd, &gslots[NOSPAM].fd[IN], gfiles[IN]);
}

static void
newconf(void *data)
{
	uint32_t cnum;
	size_t n;
	char *title, input[TOX_MAX_NAME_LENGTH + 2 + 1];

	ftruncate(gslots[CONF].fd[ERR], 0);
	lseek(gslots[CONF].fd[ERR], 0, SEEK_SET);

	n = fiforead(gslots[CONF].dirfd, &gslots[CONF].fd[IN], gfiles[IN],
		     input, sizeof(input) - 1);
	if (n <= 0)
		return;
	if (input[n - 1] == '\n')
		n--;
	input[n] = '\0';
	if(!((input[0] == 't' || input[0] == 'a' || input[0] == 'v') && input[1] == ' ')) {
		dprintf(gslots[CONF].fd[ERR], "No flag t|a|v found in input \"%s\"\n", input);
		weprintf("No flag found in input\n");
		return;
	}
	if(input[0] == 'a' || input[0] == 'v') {
		dprintf(gslots[CONF].fd[ERR], "Conferences other than text not supported yet\n");
		weprintf("Conferences other than text not supported yet\n");
		return;
	}
	title = input + 2;
	n -= 2;
	cnum = tox_conference_new(tox, NULL);
	if (cnum == UINT32_MAX) {
		dprintf(gslots[CONF].fd[ERR], "Failed to create new conference\n");
		weprintf("Failed to create new conference\n");
		return;
	}
	if (!tox_conference_set_title(tox, cnum, (uint8_t *)title, n, NULL))
		weprintf("Failed to set conference title to \"%s\"", title);
	confcreate(cnum);
}

static void
loop(void)
{
	struct file reqfifo, invfifo;
	struct friend *f, *ftmp;
	struct request *req, *rtmp;
	struct conference *c, *ctmp;
	struct invite *inv, *itmp;
	struct timeval tv;
	fd_set rfds;
	time_t t0, t1, c0, c1;
	size_t i;
	int    connected = 0, n, r, fd, fdmax;
	char   tstamp[64], ch;
	uint32_t frnum, cnum;

	t0 = time(NULL);
	logmsg("DHT > Connecting\n");
	toxconnect();
	while (running) {
		/* Handle connection states */
		if (tox_self_get_connection_status(tox) != TOX_CONNECTION_NONE) {
			if (!connected) {
				logmsg("DHT > Connected\n");
				TAILQ_FOREACH(f, &friendhead, entry) {
					canceltxtransfer(f);
					cancelrxtransfer(f);
				}
				connected = 1;
			}
		} else {
			if (connected) {
				logmsg("DHT > Disconnected\n");
				connected = 0;
			}
			t1 = time(NULL);
			if (t1 > t0 + CONNECTDELAY) {
				t0 = time(NULL);
				logmsg("DHT > Connecting\n");
				toxconnect();
			}
		}
		tox_iterate(tox, NULL);
		toxav_iterate(toxav);

		/* Prepare select-fd-set */
		FD_ZERO(&rfds);
		fdmax = -1;

		for (i = 0; i < LEN(gslots); i++)
			FD_APPEND(gslots[i].fd[IN]);

		TAILQ_FOREACH(req, &reqhead, entry)
			FD_APPEND(req->fd);

		TAILQ_FOREACH(inv, &invhead, entry)
			FD_APPEND(inv->fd);

		TAILQ_FOREACH(f, &friendhead, entry) {
			/* Only monitor friends that are online */
			if (tox_friend_get_connection_status(tox, f->num, NULL) != TOX_CONNECTION_NONE) {
				FD_APPEND(f->fd[FTEXT_IN]);

				if (f->tx.state == TRANSFER_NONE)
					FD_APPEND(f->fd[FFILE_IN]);
				if (!f->av.state || (f->av.state & TRANSMITTING))
					FD_APPEND(f->fd[FCALL_IN]);
			}
			FD_APPEND(f->fd[FREMOVE]);
		}

		TAILQ_FOREACH(c, &confhead, entry) {
			FD_APPEND(c->fd[CLEAVE]);
			FD_APPEND(c->fd[CTITLE_IN]);
			FD_APPEND(c->fd[CTEXT_IN]);
			FD_APPEND(c->fd[CINVITE]);
		}

		tv.tv_sec = 0;
		tv.tv_usec = interval(tox, toxav) * 1000;
		n = select(fdmax + 1, &rfds, NULL, NULL, &tv);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			eprintf("select:");
		}

		/* Check for broken transfers (friend went offline, file_out was closed) */
		TAILQ_FOREACH(f, &friendhead, entry) {
			if (tox_friend_get_connection_status(tox, f->num, NULL) == TOX_CONNECTION_NONE) {
				canceltxtransfer(f);
				cancelrxtransfer(f);
			}
			if (f->rxstate != TRANSFER_INPROGRESS)
				continue;
			fd = fifoopen(f->dirfd, ffiles[FFILE_OUT]);
			if (fd < 0) {
				cancelrxtransfer(f);
			} else {
				close(fd);
			}
		}

		/* Accept pending transfers if any */
		TAILQ_FOREACH(f, &friendhead, entry) {
			if (tox_friend_get_connection_status(tox, f->num, NULL) == 0)
				continue;
			if (f->rxstate == TRANSFER_NONE)
				continue;
			if (f->fd[FFILE_OUT] >= 0)
				continue;
			r = fifoopen(f->dirfd, ffiles[FFILE_OUT]);
			if (r < 0)
				continue;
			f->fd[FFILE_OUT] = r;
			if (!tox_file_control(tox, f->num, f->tx.fnum, TOX_FILE_CONTROL_RESUME, NULL)) {
				weprintf("Failed to accept transfer from receiver\n");
				cancelrxtransfer(f);
			} else {
				logmsg(": %s : Rx > Accepted\n", f->name);
				f->rxstate = TRANSFER_INPROGRESS;
			}
		}


		/* Answer pending calls */
		TAILQ_FOREACH(f, &friendhead, entry) {
			if (tox_friend_get_connection_status(tox, f->num, NULL) == TOX_CONNECTION_NONE)
				continue;
			if (!f->av.state)
				continue;

			fd = fifoopen(f->dirfd, ffiles[FCALL_OUT]);
			if (fd < 0) {
				f->av.state &= ~INCOMING;
			} else {
				f->av.state |= INCOMING;
				if (f->fd[FCALL_OUT] >= 0)
					close(fd);
				else
					f->fd[FCALL_OUT] = fd;
			}

			if (f->av.state == TRANSMITTING)
				cancelcall(f, "Hung up");

			if (f->av.state & RINGING) {
				if (f->av.state & OUTGOING) {
					c1 = time(NULL);
					if (c1 > c0 + RINGINGDELAY)
						cancelcall(f, "Timeout");
				}
				if (!(f->av.state & INCOMING))
					continue;
				if (!toxav_answer(toxav, f->num, AUDIOBITRATE, 0, NULL)) {
					weprintf("Failed to answer call\n");
					if (!toxav_call_control(toxav, f->num, TOXAV_CALL_CONTROL_CANCEL, NULL))
						weprintf("Failed to reject call\n");
					break;
				}
				f->av.state &= ~RINGING;
				f->av.state |= TRANSMITTING;
				logmsg(": %s : Audio > Answered\n", f->name);
				ftruncate(f->fd[FCALL_STATE], 0);
				lseek(f->fd[FCALL_STATE], 0, SEEK_SET);
				dprintf(f->fd[FCALL_STATE], "transmitting\n");
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
			reqfifo.name = req->idstr;
			reqfifo.flags = O_RDONLY | O_NONBLOCK;
			if (fiforead(gslots[REQUEST].fd[OUT], &req->fd, reqfifo,
				     &ch, 1) != 1)
				continue;
			if (ch != '0' && ch != '1')
				continue;
			frnum = tox_friend_add_norequest(tox, req->id, NULL);
			if (frnum == UINT32_MAX) {
				weprintf("Failed to add friend %s\n", req->idstr);
				fiforeset(gslots[REQUEST].fd[OUT], &req->fd, reqfifo);
				continue;
			}
			if (ch == '1') {
				friendcreate(frnum);
				logmsg("Request : %s > Accepted\n", req->idstr);
				datasave();
			} else {
				tox_friend_delete(tox, frnum, NULL);
				logmsg("Request : %s > Rejected\n", req->idstr);
			}
			unlinkat(gslots[REQUEST].fd[OUT], req->idstr, 0);
			close(req->fd);
			TAILQ_REMOVE(&reqhead, req, entry);
			free(req->msg);
			free(req);
		}

		for (inv = TAILQ_FIRST(&invhead); inv; inv = itmp) {
			itmp = TAILQ_NEXT(inv, entry);
			if (FD_ISSET(inv->fd, &rfds) == 0)
				continue;
			invfifo.name = inv->fifoname;
			invfifo.flags = O_RDONLY | O_NONBLOCK;
			if (fiforead(gslots[CONF].fd[OUT], &inv->fd, invfifo,
			    &ch, 1) != 1)
				continue;
			if (ch != '0' && ch != '1')
				continue;
			else if (ch == '1'){
				cnum = tox_conference_join(tox, inv->inviter, (uint8_t *)inv->cookie,
							   inv->cookielen, NULL);
				if(cnum == UINT32_MAX)
					weprintf("Failed to join conference\n");
				else
					confcreate(cnum);
			}
			unlinkat(gslots[CONF].fd[OUT], inv->fifoname, 0);
			close(inv->fd);
			TAILQ_REMOVE(&invhead, inv, entry);
			free(inv->fifoname);
			free(inv->cookie);
			free(inv);
		}

		for (c = TAILQ_FIRST(&confhead); c; c = ctmp) {
			ctmp = TAILQ_NEXT(c, entry);
			if (FD_ISSET(c->fd[CINVITE], &rfds))
				invitefriend(c);
			if (FD_ISSET(c->fd[CLEAVE], &rfds)) {
				logmsg("- %s > Leave\n", c->numstr);
				tox_conference_delete(tox, c->num, NULL);
				confdestroy(c);
			}
			if (FD_ISSET(c->fd[CTEXT_IN], &rfds))
				sendconftext(c);
			if (FD_ISSET(c->fd[CTITLE_IN], &rfds))
				updatetitle(c);
		}

		for (f = TAILQ_FIRST(&friendhead); f; f = ftmp) {
			ftmp = TAILQ_NEXT(f, entry);
			if (FD_ISSET(f->fd[FTEXT_IN], &rfds))
				sendfriendtext(f);
			if (FD_ISSET(f->fd[FFILE_IN], &rfds)) {
				switch (f->tx.state) {
				case TRANSFER_NONE:
					/* Prepare a new transfer */
					snprintf(tstamp, sizeof(tstamp), "%lu", (unsigned long)time(NULL));
					f->tx.fnum = tox_file_send(tox, f->num, TOX_FILE_KIND_DATA, UINT64_MAX,
					                           NULL, (uint8_t *)tstamp, strlen(tstamp), NULL);
					if (f->tx.fnum == UINT32_MAX) {
						weprintf("Failed to initiate new transfer\n");
						fiforeset(f->dirfd, &f->fd[FFILE_IN], ffiles[FFILE_IN]);
					} else {
						f->tx.state = TRANSFER_INITIATED;
						logmsg(": %s : Tx > Initiated\n", f->name);
					}
					break;
				}
			}
			if (FD_ISSET(f->fd[FCALL_IN], &rfds)) {
				if (!f->av.state) {
					if (!toxav_call(toxav, f->num, AUDIOBITRATE, 0, NULL)) {
						weprintf("Failed to call\n");
						fiforeset(f->dirfd, &f->fd[FCALL_IN], ffiles[FCALL_IN]);
						break;
					}

					f->av.state |= RINGING;
					logmsg(": %s : Audio > Tx Inviting\n", f->name);
				}
				if (!(f->av.state & OUTGOING)) {
					c0 = time(NULL);
					f->av.n = 0;
					f->av.lastsent.tv_sec = 0;
					f->av.lastsent.tv_nsec = 0;

					f->av.frame = malloc(sizeof(int16_t) * framesize);
					if (!f->av.frame)
						eprintf("malloc:");

					f->av.state |= OUTGOING;
				} else {
					if (f->av.state & TRANSMITTING)
						sendfriendcalldata(f);
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
toxshutdown(void)
{
	struct friend *f, *ftmp;
	struct request *r, *rtmp;
	struct conference *c, *ctmp;
	struct invite *i, *itmp;
	size_t    s, m;

	logmsg("Shutdown\n");

	datasave();

	/* Friends */
	for (f = TAILQ_FIRST(&friendhead); f; f = ftmp) {
		ftmp = TAILQ_NEXT(f, entry);
		frienddestroy(f);
	}

	/* Conferences */
	for (c = TAILQ_FIRST(&confhead); c; c=ctmp) {
		ctmp = TAILQ_NEXT(c, entry);
		confdestroy(c);
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

	/* Invites */
	for (i = TAILQ_FIRST(&invhead); i; i = itmp) {
		itmp = TAILQ_NEXT(i, entry);

		if(gslots[CONF].fd[OUT] != -1) {
			unlinkat(gslots[CONF].fd[OUT], i->fifoname, 0);
			if (i->fd != -1)
				close(i->fd);
		}
		TAILQ_REMOVE(&invhead, i, entry);
		free(i->fifoname);
		free(i->cookie);
		free(i);
	}

	/* Global files and slots */
	for (s = 0; s < LEN(gslots); s++) {
		for (m = 0; m < LEN(gfiles); m++) {
			if (gslots[s].dirfd != -1) {
				unlinkat(gslots[s].dirfd, gfiles[m].name,
					 (gslots[s].outisfolder && m == OUT)
					 ? AT_REMOVEDIR : 0);
				if (gslots[s].fd[m] != -1)
					close(gslots[s].fd[m]);
			}
		}
		rmdir(gslots[s].name);
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
	eprintf("usage: %s [-4|-6] [-E|-e] [-T|-t] [-P|-p] [-q] [savefile]\n", argv0);
}

int
main(int argc, char *argv[])
{
	ARGBEGIN {
	case '4':
		ipv6 = 0;
		break;
	case '6':
		ipv6 = 1;
		break;
	case 'E':
		encryptsavefile = 1;
		break;
	case 'e':
		encryptsavefile = 0;
		break;
	case 'T':
		tcp = 1;
		break;
	case 't':
		tcp = 0;
		break;
	case 'P':
		proxy = 1;
		break;
	case 'p':
		proxy = 0;
		break;
	case 'q':
		quiet = 1;
		break;
	default:
		usage();
	} ARGEND;

	if (argc > 1)
		usage();
	if (argc == 1)
		savefile = *argv;

	setbuf(stdout, NULL);

	signal(SIGHUP, initshutdown);
	signal(SIGINT, initshutdown);
	signal(SIGQUIT, initshutdown);
	signal(SIGTERM, initshutdown);
	signal(SIGPIPE, SIG_IGN);

	if (!quiet)
		printrat();
	toxinit();
	localinit();
	friendload();
	loop();
	toxshutdown();
	return 0;
}
