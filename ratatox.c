/* See LICENSE file for copyright and license details. */
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <tox/tox.h>

#include "arg.h"
#include "queue.h"

#define LEN(x) (sizeof (x) / sizeof *(x))
#define DATAFILE "ratatox.data"

struct node {
	const char *addr;
	uint16_t port;
	uint8_t key[TOX_CLIENT_ID_SIZE];
};

#include "config.h"

struct fifo {
	const char *name;
	int flags;
	mode_t mode;
	void (*cb)(void *);
};

enum {
	NAME_FIFO,
	STATUS_FIFO,
	FRIENDREQ_FIFO,
	NR_GFIFOS
};

static void setname(void *);
static void setstatusmsg(void *);
static void sendfriendreq(void *);

/* Global FIFOs for modifying our own state, they go in $(PWD)/{name,status}_in */
static struct fifo gfifos[] = {
	{ .name = "name_in",      .flags = O_RDONLY | O_NONBLOCK, .mode = 0644, .cb = setname       },
	{ .name = "statusmsg_in", .flags = O_RDONLY | O_NONBLOCK, .mode = 0644, .cb = setstatusmsg  },
	{ .name = "friendreq_in", .flags = O_RDONLY | O_NONBLOCK, .mode = 0644, .cb = sendfriendreq },
};

static int globalfd[NR_GFIFOS];

enum {
	TEXT_IN_FIFO,
	FILE_IN_FIFO,
	NR_FFIFOS
};

/* Friend related FIFOs, they go in <friend-id/{text,file}_in */
static struct fifo ffifos[] = {
	{ .name = "text_in", .flags = O_RDONLY | O_NONBLOCK, .mode = 0644 },
	{ .name = "file_in", .flags = O_RDONLY | O_NONBLOCK, .mode = 0644 },
};

enum {
	TRANSFER_NONE,
	TRANSFER_INITIATED,
	TRANSFER_INPROGRESS,
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
	int fd[NR_FFIFOS];
	struct transfer t;
	TAILQ_ENTRY(friend) entry;
};

struct request {
	uint8_t id[TOX_CLIENT_ID_SIZE];
	/* null terminated id */
	char idstr[2 * TOX_CLIENT_ID_SIZE + 1];
	/* null terminated friend request message */
	char *msgstr;
	TAILQ_ENTRY(request) entry;
};

char *argv0;

static TAILQ_HEAD(friendhead, friend) friendhead = TAILQ_HEAD_INITIALIZER(friendhead);
static TAILQ_HEAD(reqhead, request) reqhead = TAILQ_HEAD_INITIALIZER(reqhead);

static Tox *tox;

static void printrat(void);
static void cbconnstatus(Tox *, int32_t, uint8_t, void *);
static void cbfriendmessage(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cbfriendrequest(Tox *, const uint8_t *, const uint8_t *, uint16_t, void *);
static void cbnamechange(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cbstatusmessage(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cbuserstatus(Tox *, int32_t, uint8_t, void *);
static void cbfilecontrol(Tox *, int32_t, uint8_t, uint8_t, uint8_t, const uint8_t *, uint16_t, void *);
static void sendfriendfile(struct friend *);
static void dataload(void);
static void datasave(void);
static int localinit(void);
static int toxinit(void);
static int toxconnect(void);
static void id2str(uint8_t *, char *);
static void str2id(char *, uint8_t *);
static struct friend *friendcreate(int32_t);
static void friendload(void);
static int cmdrun(void);
static int cmdaccept(char *, size_t);
static int cmdhelp(char *, size_t);
static void writeline(const char *, const char *, const char *, ...);
static void loop(void);

static char qsep[] = " \t\r\n";

/* tokenization routines taken from Plan9 */
static char *
qtoken(char *s, char *sep)
{
	int quoting;
	char *t;

	quoting = 0;
	t = s;	/* s is output string, t is input string */
	while(*t!='\0' && (quoting || strchr(sep, *t)==NULL)) {
		if(*t != '\'') {
			*s++ = *t++;
			continue;
		}
		/* *t is a quote */
		if(!quoting) {
			quoting = 1;
			t++;
			continue;
		}
		/* quoting and we're on a quote */
		if(t[1] != '\'') {
			/* end of quoted section; absorb closing quote */
			t++;
			quoting = 0;
			continue;
		}
		/* doubled quote; fold one quote into two */
		t++;
		*s++ = *t++;
	}
	if(*s != '\0') {
		*s = '\0';
		if(t == s)
			t++;
	}
	return t;
}

static int
tokenize(char *s, char **args, int maxargs)
{
	int nargs;

	for(nargs=0; nargs<maxargs; nargs++) {
		while(*s!='\0' && strchr(qsep, *s)!=NULL)
			s++;
		if(*s == '\0')
			break;
		args[nargs] = s;
		s = qtoken(s, qsep);
	}

	return nargs;
}

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
	printf("                          '~' '~----'\tratatox v"VERSION"\n");
	printf("\033[0m");
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
cbconnstatus(Tox *m, int32_t fid, uint8_t status, void *udata)
{
	struct friend *f;
	uint8_t name[TOX_MAX_NAME_LENGTH + 1];
	char path[PATH_MAX];
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
			snprintf(path, sizeof(path), "%s/online", f->idstr);
			writeline(path, "w", status == 0 ? "0\n" : "1\n");
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
	char path[PATH_MAX];
	time_t t;

	memcpy(msg, data, len);
	msg[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			t = time(NULL);
			strftime(buft, sizeof(buft), "%F %R", localtime(&t));
			snprintf(path, sizeof(path), "%s/text_out", f->idstr);
			writeline(path, "a", "%s %s\n", buft, msg);
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

	TAILQ_INSERT_TAIL(&reqhead, req, entry);

	printout("Pending request from %s with message: %s\n",
		 req->idstr, req->msgstr);
}

static void
cbnamechange(Tox *m, int32_t fid, const uint8_t *data, uint16_t len, void *user)
{
	struct friend *f;
	uint8_t name[len + 1];
	char path[PATH_MAX];

	memcpy(name, data, len);
	name[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			snprintf(path, sizeof(path), "%s/name", f->idstr);
			writeline(path, "w", "%s\n", name);
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
	uint8_t statusmsg[len + 1];
	char path[PATH_MAX];

	memcpy(statusmsg, data, len);
	statusmsg[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			snprintf(path, sizeof(path), "%s/statusmsg", f->idstr);
			writeline(path, "w", "%s\n", statusmsg);
			printout("%s changed status: %s\n",
				 f->namestr[0] == '\0' ? "Anonymous" : f->namestr, statusmsg);
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

	switch (ctrltype) {
	case TOX_FILECONTROL_ACCEPT:
		if (rec_sen == 1) {
			TAILQ_FOREACH(f, &friendhead, entry) {
				if (f->fid != fid)
					continue;
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
				break;
			}
		}
		break;
	case TOX_FILECONTROL_FINISHED:
		if (rec_sen == 1) {
			TAILQ_FOREACH(f, &friendhead, entry) {
				if (f->fid != fid)
					continue;
				f->t.state = TRANSFER_DONE;
				break;
			}
		}
		break;
	default:
		fprintf(stderr, "Unhandled file control type: %d\n", ctrltype);
		break;
	};
}

static void
sendfriendfile(struct friend *f)
{
	ssize_t n;

	while (1) {
		/* attempt to transmit the pending buffer */
		if (f->t.pending == 1) {
			if (tox_file_send_data(tox, f->fid, f->t.fnum, f->t.buf, f->t.n) == -1) {
				/* bad luck - we will try again later */
				break;
			}
			f->t.pending = 0;
		}
		/* grab another buffer from the FIFO */
		n = read(f->fd[FILE_IN_FIFO], f->t.buf, f->t.chunksz);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			/* go back to select() until the fd is readable */
			if (errno == EWOULDBLOCK)
				break;
			perror("read");
			exit(EXIT_FAILURE);
		}
		/* we are done */
		if (n == 0) {
			tox_file_send_control(tox, f->fid, 0, f->t.fnum,
					      TOX_FILECONTROL_FINISHED, NULL, 0);
			f->t.state = TRANSFER_DONE;
			break;
		}
		/* store transfer size in case we can't send it right now */
		f->t.n = n;
		if (tox_file_send_data(tox, f->fid, f->t.fnum, f->t.buf, f->t.n) == -1) {
			/* ok we will have to send it later, flip state */
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

again:
	n = read(f->fd[TEXT_IN_FIFO], buf, sizeof(buf));
	if (n < 0) {
		if (errno == EINTR)
			goto again;
		/* go back to select() until the fd is readable */
		if (errno == EWOULDBLOCK)
			return;
		perror("read");
		exit(EXIT_FAILURE);
	}
	if (buf[n - 1] == '\n')
		n--;
	tox_send_message(tox, f->fid, buf, n);
}

static void
dataload(void)
{
	FILE *fp;
	size_t sz;
	uint8_t *data;
	int r;

	fp = fopen(DATAFILE, "r");
	if (!fp)
		return;

	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	rewind(fp);

	data = malloc(sz);
	if (!data) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	if (fread(data, 1, sz, fp) != sz || ferror(fp)) {
		fprintf(stderr, "failed to read %s\n", DATAFILE);
		exit(EXIT_FAILURE);
	}
	r = tox_load(tox, data, sz);
	if (r < 0) {
		fprintf(stderr, "tox_load() failed\n");
		exit(EXIT_FAILURE);
	}
	if (r == 1)
		printf("Found encrypted data in %s\n", DATAFILE);

	free(data);
	fclose(fp);
}

static void
datasave(void)
{
	FILE *fp;
	size_t sz;
	uint8_t *data;

	fp = fopen(DATAFILE, "w");
	if (!fp) {
		fprintf(stderr, "can't open %s for writing\n", DATAFILE);
		exit(EXIT_FAILURE);
	}

	sz = tox_size(tox);
	data = malloc(sz);
	if (!data) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	tox_save(tox, data);
	if (fwrite(data, 1, sz, fp) != sz || ferror(fp)) {
		fprintf(stderr, "failed to write %s\n", DATAFILE);
		exit(EXIT_FAILURE);
	}

	free(data);
	fclose(fp);
}

static int
localinit(void)
{
	uint8_t name[TOX_MAX_NAME_LENGTH + 1];
	uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
	uint8_t statusmsg[TOX_MAX_STATUSMESSAGE_LENGTH + 1];
	FILE *fp;
	int r;
	size_t i;

	for (i = 0; i < LEN(gfifos); i++) {
		r = mkfifo(gfifos[i].name, gfifos[i].mode);
		if (r < 0 && errno != EEXIST) {
			perror("mkfifo");
			exit(EXIT_FAILURE);
		}
		r = open(gfifos[i].name, gfifos[i].flags, 0);
		if (r < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}
		globalfd[i] = r;
	}

	/* Dump current name */
	r = tox_get_self_name(tox, name);
	if (r > sizeof(name) - 1)
		r = sizeof(name) - 1;
	name[r] = '\0';
	writeline("name_out", "w", "%s\n", name);

	/* Dump status message */
	r = tox_get_self_status_message(tox, statusmsg,
					sizeof(statusmsg) - 1);
	if (r > sizeof(statusmsg) - 1)
		r = sizeof(statusmsg) - 1;
	statusmsg[r] = '\0';
	writeline("statusmsg_out", "w", "%s\n", statusmsg);

	/* Dump ID */
	fp = fopen("id", "w");
	if (!fp) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}
	tox_get_address(tox, address);
	for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++)
		fprintf(fp, "%02x", address[i]);
	fputc('\n', fp);
	fclose(fp);

	return 0;
}

static int
toxinit(void)
{
	/* IPv4 only */
	tox = tox_new(0);
	dataload();
	datasave();
	tox_callback_connection_status(tox, cbconnstatus, NULL);
	tox_callback_friend_message(tox, cbfriendmessage, NULL);
	tox_callback_friend_request(tox, cbfriendrequest, NULL);
	tox_callback_name_change(tox, cbnamechange, NULL);
	tox_callback_status_message(tox, cbstatusmessage, NULL);
	tox_callback_user_status(tox, cbuserstatus, NULL);
	tox_callback_file_control(tox, cbfilecontrol, NULL);
	return 0;
}

static int
toxconnect(void)
{
	struct node *bn;
	size_t i;

	for (i = 0; i < LEN(nodes); i++) {
		bn = &nodes[i];
		tox_bootstrap_from_address(tox, bn->addr, bn->port, bn->key);
	}
	return 0;
}

static void
id2str(uint8_t *id, char *idstr)
{
	char hex[] = "0123456789abcdef";
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
	char path[PATH_MAX];
	struct friend *f;
	uint8_t statusmsg[TOX_MAX_STATUSMESSAGE_LENGTH + 1];
	size_t i;
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

	for (i = 0; i < LEN(ffifos); i++) {
		snprintf(path, sizeof(path), "%s/%s", f->idstr,
			 ffifos[i].name);
		r = mkfifo(path, ffifos[i].mode);
		if (r < 0 && errno != EEXIST) {
			perror("mkfifo");
			exit(EXIT_FAILURE);
		}
		r = open(path, ffifos[i].flags, 0);
		if (r < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}
		f->fd[i] = r;
	}

	snprintf(path, sizeof(path), "%s/name", f->idstr);
	writeline(path, "w", "%s\n", f->namestr);
	snprintf(path, sizeof(path), "%s/online", f->idstr);
	writeline(path, "w", tox_get_friend_connection_status(tox, fid) == 0 ? "0\n" : "1\n");
	r = tox_get_status_message_size(tox, fid);
	if (r > sizeof(statusmsg) - 1)
		r = sizeof(statusmsg) - 1;
	statusmsg[r] = '\0';
	snprintf(path, sizeof(path), "%s/statusmsg", f->idstr);
	writeline(path, "w", "%s\n", statusmsg);
	snprintf(path, sizeof(path), "%s/textout", f->idstr);
	writeline(path, "a", "");

	TAILQ_INSERT_TAIL(&friendhead, f, entry);

	return f;
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

struct cmd {
	const char *cmd;
	int (*cb)(char *, size_t);
	const char *usage;
} cmds[] = {
	{ .cmd = "a", .cb = cmdaccept, .usage = "usage: a [id]\tAccept or list pending requests\n" },
	{ .cmd = "h", .cb = cmdhelp,   .usage = NULL },
};

static int
cmdaccept(char *cmd, size_t sz)
{
	struct request *req, *tmp;
	char *args[2];
	int r;
	int found = 0;

	r = tokenize(cmd, args, 2);

	if (r == 1) {
		TAILQ_FOREACH(req, &reqhead, entry) {
			printout("Pending request from %s with message: %s\n",
				 req->idstr, req->msgstr);
			found = 1;
		}
		if (found == 0)
			printf("No pending requests\n");
	} else {
		for (req = TAILQ_FIRST(&reqhead); req; req = tmp) {
			tmp = TAILQ_NEXT(req, entry);
			if (strcmp(req->idstr, args[1]) == 0) {
				tox_add_friend_norequest(tox, req->id);
				printout("Accepted friend request for %s\n", req->idstr);
				datasave();
				TAILQ_REMOVE(&reqhead, req, entry);
				free(req->msgstr);
				free(req);
				break;
			}
		}
	}

	return 0;
}

static int
cmdhelp(char *cmd, size_t sz)
{
	size_t i;

	for (i = 0; i < LEN(cmds); i++)
		if (cmds[i].usage)
			fprintf(stderr, "%s", cmds[i].usage);
	return 0;
}

static int
cmdrun(void)
{
	char cmd[BUFSIZ];
	ssize_t n;
	size_t i;

again:
	n = read(STDIN_FILENO, cmd, sizeof(cmd) - 1);
	if (n < 0) {
		if (errno == EINTR)
			goto again;
		perror("read");
		exit(EXIT_FAILURE);
	}
	if (n == 0)
		return 0;
	cmd[n] = '\0';
	if (cmd[strlen(cmd) - 1] == '\n')
		cmd[strlen(cmd) - 1] = '\0';
	if (cmd[0] == '\0')
		return 0;

	for (i = 0; i < LEN(cmds); i++)
		if (cmd[0] == cmds[i].cmd[0])
			if (cmd[1] == '\0' || isspace((int)cmd[1]))
				return (*cmds[i].cb)(cmd, strlen(cmd));

	fprintf(stderr, "Unknown command '%s', type h for help\n", cmd);
	return -1;
}

static void
writeline(const char *path, const char *mode,
	  const char *fmt, ...)
{
	FILE *fp;
	va_list ap;

	fp = fopen(path, mode);
	if (!fp) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	fclose(fp);
}

static void
setname(void *data)
{
	uint8_t name[TOX_MAX_NAME_LENGTH + 1];
	int r;

again:
	r = read(globalfd[NAME_FIFO], name, sizeof(name) - 1);
	if (r < 0) {
		if (errno == EINTR)
			goto again;
		if (errno == EWOULDBLOCK)
			return;
		perror("read");
		return;
	}
	if (name[r - 1] == '\n')
		r--;
	name[r] = '\0';
	tox_set_name(tox, name, r);
	datasave();
	printout("Changed name to %s\n", name);
	writeline("name_out", "w", "%s\n", name);
}

static void
setstatusmsg(void *data)
{
	uint8_t statusmsg[TOX_MAX_STATUSMESSAGE_LENGTH + 1];
	int r;

again:
	r = read(globalfd[STATUS_FIFO], statusmsg, sizeof(statusmsg) - 1);
	if (r < 0) {
		if (errno == EINTR)
			goto again;
		if (errno == EWOULDBLOCK)
			return;
		perror("read");
		return;
	}
	if (statusmsg[r - 1] == '\n')
		r--;
	statusmsg[r] = '\0';
	tox_set_status_message(tox, statusmsg, r);
	datasave();
	printout("Changed status message to %s\n", statusmsg);
	writeline("statusmsg_out", "w", "%s\n", statusmsg);
}

static void
sendfriendreq(void *data)
{
	char *p;
	uint8_t id[TOX_FRIEND_ADDRESS_SIZE];
	uint8_t buf[BUFSIZ], *msg = "ratatox is awesome!";
	int r;

again:
	r = read(globalfd[FRIENDREQ_FIFO], buf, sizeof(buf) - 1);
	if (r < 0) {
		if (errno == EINTR)
			goto again;
		if (errno == EWOULDBLOCK)
			return;
		perror("read");
		return;
	}
	buf[r] = '\0';

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

	r = tox_add_friend(tox, id, buf, strlen(buf));
	switch (r) {
	case TOX_FAERR_TOOLONG:
		fprintf(stderr, "Message is too long\n");
		break;
	case TOX_FAERR_NOMESSAGE:
		fprintf(stderr, "Please add a message to your request\n");
		break;
	case TOX_FAERR_OWNKEY:
		fprintf(stderr, "That appears to be your own ID\n");
		break;
	case TOX_FAERR_ALREADYSENT:
		fprintf(stderr, "Friend request already sent\n");
		break;
	case TOX_FAERR_UNKNOWN:
		fprintf(stderr, "Unknown error while sending your request\n");
		break;
	default:
		printout("Friend request sent\n");
		break;
	}
	datasave();
}

static void
loop(void)
{
	struct friend *f;
	time_t t0, t1;
	int connected = 0;
	int i, n;
	int fdmax;
	fd_set rfds;
	struct timeval tv;

	t0 = time(NULL);
	printout("Connecting to DHT...\n");
	toxconnect();
	while (1) {
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
		FD_SET(STDIN_FILENO, &rfds);
		fdmax = STDIN_FILENO;

		for (i = 0; i < NR_GFIFOS; i++) {
			FD_SET(globalfd[i], &rfds);
			if (globalfd[i] > fdmax)
				fdmax = globalfd[i];
		}

		TAILQ_FOREACH(f, &friendhead, entry) {
			/* Only monitor friends that are online */
			if (tox_get_friend_connection_status(tox, f->fid) == 1) {
				for (i = 0; i < NR_FFIFOS; i++) {
					FD_SET(f->fd[i], &rfds);
					if (f->fd[i] > fdmax)
						fdmax = f->fd[i];
				}
			}
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
		TAILQ_FOREACH(f, &friendhead, entry) {
			if (tox_get_friend_connection_status(tox, f->fid) == 0) {
				if (f->t.state != TRANSFER_NONE) {
					printout("Stale transfer detected, friend offline\n");
					f->t.state = TRANSFER_NONE;
					free(f->t.buf);
				}
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
			if (tox_get_friend_connection_status(tox, f->fid) == 0)
				continue;
			if (f->t.state == TRANSFER_NONE)
				continue;
			if (f->t.pending == 0)
				continue;
			switch (f->t.state) {
			case TRANSFER_INPROGRESS:
				sendfriendfile(f);
				if (f->t.state == TRANSFER_DONE) {
					printout("Transfer complete\n");
					f->t.state = TRANSFER_NONE;
					free(f->t.buf);
				}
				break;
			}
		}

		if (n == 0)
			continue;

		if (FD_ISSET(STDIN_FILENO, &rfds) != 0)
			cmdrun();

		for (i = 0; i < NR_GFIFOS; i++) {
			if (FD_ISSET(globalfd[i], &rfds) == 0)
				continue;
			(*gfifos[i].cb)(NULL);
		}

		TAILQ_FOREACH(f, &friendhead, entry) {
			for (i = 0; i < NR_FFIFOS; i++) {
				if (FD_ISSET(f->fd[i], &rfds) == 0)
					continue;
				switch (i) {
				case TEXT_IN_FIFO:
					sendfriendtext(f);
					break;
				case FILE_IN_FIFO:
					switch (f->t.state) {
					case TRANSFER_NONE:
						/* prepare a new transfer */
						f->t.state = TRANSFER_INITIATED;
						tox_new_file_sender(tox, f->fid,
							0, (uint8_t *)"file", strlen("file") + 1);
						printout("Initiated transfer to %s\n",
							 f->namestr[0] == '\0' ? "Anonymous" : f->namestr);
						break;
					case TRANSFER_INPROGRESS:
						sendfriendfile(f);
						if (f->t.state == TRANSFER_DONE) {
							printout("Transfer complete\n");
							f->t.state = TRANSFER_NONE;
							free(f->t.buf);
						}
						break;
					}
					break;
				default:
					fprintf(stderr, "Unhandled FIFO read\n");
				}
			}
		}
	}
}

int
main(int argc, char *argv[])
{
	printrat();
	printf("Type h for help\n");
	toxinit();
	localinit();
	friendload();
	loop();
	return EXIT_SUCCESS;
}
