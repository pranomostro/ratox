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

enum {
	TEXT_IN_FIFO,
	NR_FIFOS
};

static struct fifo {
	const char *name;
	int flags;
	mode_t mode;
} fifos[] = {
	{ .name = "text_in", .flags = O_RDONLY | O_NONBLOCK, .mode = 0644 },
};

struct friend {
	/* null terminated name */
	char namestr[TOX_MAX_NAME_LENGTH + 1];
	int fid;
	uint8_t id[TOX_CLIENT_ID_SIZE];
	/* null terminated id */
	char idstr[2 * TOX_CLIENT_ID_SIZE + 1];
	int fd[NR_FIFOS];
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

static void printbanner(void);
static void cb_conn_status(Tox *, int32_t, uint8_t, void *);
static void cb_friend_message(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cb_friend_request(Tox *, const uint8_t *, const uint8_t *, uint16_t, void *);
static void cb_name_change(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cb_status_message(Tox *, int32_t, const uint8_t *, uint16_t, void *);
static void cb_user_status(Tox *, int32_t, uint8_t, void *);
static void send_friend_text(struct friend *);
static void dataload(void);
static void datasave(void);
static int toxinit(void);
static int toxconnect(void);
static void id2str(uint8_t *, char *);
static void str2id(char *, uint8_t *);
static struct friend *friendcreate(int32_t);
static void friendload(void);
static int cmdrun(void);
static int cmdaccept(char *, size_t);
static int cmdfriend(char *, size_t);
static int cmdid(char *, size_t);
static int cmdname(char *, size_t);
static int cmdhelp(char *, size_t);
static void writeparam(struct friend *, const char *, const char *, const char *, ...);
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
printbanner(void)
{
	printf("\033[31m");
	printf("                       ,     .\n");
	printf("                       (\\,;,/)\n");
	printf("                        (o o)\\//,\n");
	printf("                         \\ /     \\,\n");
	printf("                         `+'(  (   \\    )\n");
	printf("                            //  \\   |_./\n");
	printf("                          '~' '~----'\tratatox v0.0\n");
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
cb_conn_status(Tox *m, int32_t fid, uint8_t status, void *udata)
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
			writeparam(f, "online", "w", status == 0 ? "0\n" : "1\n");
			return;
		}
	}

	friendcreate(fid);
}

static void
cb_friend_message(Tox *m, int32_t fid, const uint8_t *data, uint16_t len, void *udata)
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
			writeparam(f, "text_out", "a", "%s %s\n", buft, msg);
			printout("%s %s\n", f->namestr, msg);
			break;
		}
	}
}

static void
cb_friend_request(Tox *m, const uint8_t *id, const uint8_t *data, uint16_t len, void *udata)
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
cb_name_change(Tox *m, int32_t fid, const uint8_t *data, uint16_t len, void *user)
{
	struct friend *f;
	uint8_t name[len + 1];

	memcpy(name, data, len);
	name[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			writeparam(f, "name", "w", "%s\n", name);
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
cb_status_message(Tox *m, int32_t fid, const uint8_t *data, uint16_t len, void *udata)
{
	struct friend *f;
	uint8_t statusmsg[len + 1];

	memcpy(statusmsg, data, len);
	statusmsg[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			writeparam(f, "statusmsg", "w", "%s\n", statusmsg);
			printout("%s changed status: %s\n", f->namestr, statusmsg);
			break;
		}
	}
	datasave();
}

static void
cb_user_status(Tox *m, int32_t fid, uint8_t status, void *udata)
{
	struct friend *f;
	char *statusstr[] = { "none", "away", "busy" };

	if (status >= LEN(statusstr)) {
		fprintf(stderr, "received invalid user status: %d\n", status);
		return;
	}

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			printout("%s changed user status: %s\n", f->namestr,
			         statusstr[status]);
			break;
		}
	}
}

static void
send_friend_text(struct friend *f)
{
	uint8_t buf[TOX_MAX_MESSAGE_LENGTH];
	ssize_t n;

again:
	n = read(f->fd[TEXT_IN_FIFO], buf, sizeof(buf));
	if (n < 0) {
		if (errno == EINTR)
			goto again;
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
toxinit(void)
{
	uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
	int i;

	/* IPv4 only */
	tox = tox_new(0);
	dataload();
	datasave();
	tox_callback_connection_status(tox, cb_conn_status, NULL);
	tox_callback_friend_message(tox, cb_friend_message, NULL);
	tox_callback_friend_request(tox, cb_friend_request, NULL);
	tox_callback_name_change(tox, cb_name_change, NULL);
	tox_callback_status_message(tox, cb_status_message, NULL);
	tox_callback_user_status(tox, cb_user_status, NULL);

	tox_get_address(tox, address);
	printf("ID: ");
	for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++)
		printf("%02x", address[i]);
	printf("\n");

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

	for (i = 0; i < LEN(fifos); i++) {
		snprintf(path, sizeof(path), "%s/%s", f->idstr,
			 fifos[i].name);
		r = mkfifo(path, fifos[i].mode);
		if (r < 0 && errno != EEXIST) {
			perror("mkfifo");
			exit(EXIT_FAILURE);
		}
		r = open(path, fifos[i].flags, 0);
		if (r < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}
		f->fd[i] = r;
	}

	writeparam(f, "name", "w", "%s\n", f->namestr);
	writeparam(f, "online", "w",
	       tox_get_friend_connection_status(tox, fid) == 0 ? "0\n" : "1\n");
	r = tox_get_status_message_size(tox, fid);
	if (r > TOX_MAX_STATUSMESSAGE_LENGTH)
		r = TOX_MAX_STATUSMESSAGE_LENGTH;
	statusmsg[r] = '\0';
	writeparam(f, "statusmsg", "w", "%s\n", statusmsg);
	writeparam(f, "text_out", "a", "");

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
	{ .cmd = "f", .cb = cmdfriend, .usage = "usage: f id\tSend friend request to ID\n" },
	{ .cmd = "i", .cb = cmdid,     .usage = "usage: i\tShow ID\n" },
	{ .cmd = "n", .cb = cmdname,   .usage = "usage: n [name]\tChange or show current name\n" },
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
cmdfriend(char *cmd, size_t sz)
{
	char *args[2];
	uint8_t id[TOX_FRIEND_ADDRESS_SIZE];
	uint8_t msgstr[] = "ratatox is awesome!";
	int r;

	r = tokenize(cmd, args, 2);
	if (r != 2) {
		fprintf(stderr, "Command error, type h for help\n");
		return -1;
	}
	str2id(args[1], id);

	r = tox_add_friend(tox, id, msgstr, strlen((const char *)msgstr));
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
	return 0;
}

static int
cmdid(char *cmd, size_t sz)
{
	uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
	int i;

	tox_get_address(tox, address);
	for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++)
		printf("%02x", address[i]);
	printf("\n");
	return 0;
}

static int
cmdname(char *cmd, size_t sz)
{
	char *args[2];
	uint8_t name[TOX_MAX_NAME_LENGTH + 1];
	uint16_t len;
	int r;

	r = tokenize(cmd, args, 2);

	if (r == 1) {
		len = tox_get_self_name(tox, name);
		name[len] = '\0';
		printf("%s\n", name);
	} else {
		tox_set_name(tox, (uint8_t *)args[1], strlen(args[1]));
		datasave();
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
writeparam(struct friend *f, const char *file, const char *mode,
       const char *fmt, ...)
{
	FILE *fp;
	char path[PATH_MAX];
	va_list ap;

	snprintf(path, sizeof(path), "%s/%s", f->idstr, file);
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

		TAILQ_FOREACH(f, &friendhead, entry) {
			for (i = 0; i < NR_FIFOS; i++) {
				FD_SET(f->fd[i], &rfds);
				if (f->fd[i] > fdmax)
					fdmax = f->fd[i];
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
		if (n == 0)
			continue;

		if (FD_ISSET(STDIN_FILENO, &rfds) != 0)
			cmdrun();

		TAILQ_FOREACH(f, &friendhead, entry) {
			for (i = 0; i < NR_FIFOS; i++) {
				if (FD_ISSET(f->fd[i], &rfds) == 0)
					continue;
				switch (i) {
				case TEXT_IN_FIFO:
					send_friend_text(f);
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
	printbanner();
	toxinit();
	friendload();
	loop();
	return EXIT_SUCCESS;
}
