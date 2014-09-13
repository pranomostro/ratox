#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <tox/tox.h>

#include "queue.h"

#define LEN(x) (sizeof (x) / sizeof *(x))

static struct bootstrapnode {
	char *addr;
	uint16_t port;
	uint8_t key[TOX_CLIENT_ID_SIZE];
} bootstrapnodes[] = {
	{
		"95.85.13.245",
		33445,
		{
			0x71, 0x87, 0x96, 0x9B, 0xB1, 0x0B, 0x54, 0xC9, 0x85, 0x38, 0xBA, 0xE9, 0x4C, 0x06, 0x9C, 0xE5,
			0xC8, 0x4E, 0x65, 0x0D, 0x54, 0xF7, 0xE5, 0x96, 0x54, 0x3D, 0x8F, 0xB1, 0xEC, 0xF4, 0xCF, 0x23
		}
	},
	{
		"37.187.46.132",
		33445,
		{
			0xA9, 0xD9, 0x82, 0x12, 0xB3, 0xF9, 0x72, 0xBD, 0x11, 0xDA, 0x52, 0xBE, 0xB0, 0x65, 0x8C, 0x32,
			0x6F, 0xCC, 0xC1, 0xBF, 0xD4, 0x9F, 0x34, 0x7F, 0x9C, 0x2D, 0x3D, 0x8B, 0x61, 0xE1, 0xB9, 0x27
		}
	},
	{
		"144.76.60.215",
		33445,
		{
			0x04, 0x11, 0x9E, 0x83, 0x5D, 0xF3, 0xE7, 0x8B, 0xAC, 0xF0, 0xF8, 0x42, 0x35, 0xB3, 0x00, 0x54,
			0x6A, 0xF8, 0xB9, 0x36, 0xF0, 0x35, 0x18, 0x5E, 0x2A, 0x8E, 0x9E, 0x0A, 0x67, 0xC8, 0x92, 0x4F
		}
	},
	{
		"23.226.230.47",
		33445,
		{
			0xA0, 0x91, 0x62, 0xD6, 0x86, 0x18, 0xE7, 0x42, 0xFF, 0xBC, 0xA1, 0xC2, 0xC7, 0x03, 0x85, 0xE6,
			0x67, 0x96, 0x04, 0xB2, 0xD8, 0x0E, 0xA6, 0xE8, 0x4A, 0xD0, 0x99, 0x6A, 0x1A, 0xC8, 0xA0, 0x74
		}
	},
	{
		"54.199.139.199",
		33445,
		{
			0x7F, 0x9C, 0x31, 0xFE, 0x85, 0x0E, 0x97, 0xCE, 0xFD, 0x4C, 0x45, 0x91, 0xDF, 0x93, 0xFC, 0x75,
			0x7C, 0x7C, 0x12, 0x54, 0x9D, 0xDD, 0x55, 0xF8, 0xEE, 0xAE, 0xCC, 0x34, 0xFE, 0x76, 0xC0, 0x29
		}
	},
	{
		"109.169.46.133",
		33445,
		{
			0x7F, 0x31, 0xBF, 0xC9, 0x3B, 0x8E, 0x40, 0x16, 0xA9, 0x02, 0x14, 0x4D, 0x0B, 0x11, 0x0C, 0x3E,
			0xA9, 0x7C, 0xB7, 0xD4, 0x3F, 0x1C, 0x4D, 0x21, 0xBC, 0xAE, 0x99, 0x8A, 0x7C, 0x83, 0x88, 0x21
		}
	},
	{
		"192.210.149.121",
		33445,
		{
			0xF4, 0x04, 0xAB, 0xAA, 0x1C, 0x99, 0xA9, 0xD3, 0x7D, 0x61, 0xAB, 0x54, 0x89, 0x8F, 0x56, 0x79,
			0x3E, 0x1D, 0xEF, 0x8B, 0xD4, 0x6B, 0x10, 0x38, 0xB9, 0xD8, 0x22, 0xE8, 0x46, 0x0F, 0xAB, 0x67
		}
	},
	{
		"76.191.23.96",
		33445,
		{
			0x4B, 0xA5, 0x76, 0x60, 0xDE, 0x3E, 0x85, 0x4C, 0x53, 0x0E, 0xED, 0x60, 0x1B, 0xF8, 0xD5, 0x4B,
			0x7E, 0xFA, 0xE9, 0x60, 0x52, 0x3B, 0x6C, 0xFC, 0x10, 0x21, 0x0C, 0xC0, 0x8E, 0x2C, 0xB8, 0x08
		}
	},
};

enum {
	TEXT_IN_FIFO,
	NR_FIFOS
};

static struct fifo {
	const char *name;
	mode_t mode;
} fifos[] = {
	{ "text_in",  0644 },
};

struct friend {
	/* null terminated name */
	uint8_t namestr[TOX_MAX_NAME_LENGTH + 1];
	int fid;
	uint8_t id[TOX_CLIENT_ID_SIZE];
	/* null terminated id */
	uint8_t idstr[2 * TOX_CLIENT_ID_SIZE + 1];
	int fd[NR_FIFOS];
	TAILQ_ENTRY(friend) entry;
};

static TAILQ_HEAD(friendhead, friend) friendhead = TAILQ_HEAD_INITIALIZER(friendhead);

static Tox *tox;
static void dataload(void);
static void datasave(void);
static void friendcreate(int32_t);

static void
cb_conn_status(Tox *tox, int32_t fid, uint8_t status, void *udata)
{
	struct friend *f;
	uint8_t name[TOX_MAX_NAME_LENGTH + 1];
	uint8_t *nick;
	int n;

	n = tox_get_name(tox, fid, name);
	if (n < 0) {
		fprintf(stderr, "tox_get_name() on fid %d failed\n", fid);
		exit(1);
	}
	name[n] = '\0';

	if (n == 0) {
		if (status == 0)
			printf("Anonymous went offline\n");
		else
			printf("Anonymous came online\n");
	} else {
		if (status == 0)
			printf("%s went offline\n", name);
		else
			printf("%s came online\n", name);
	}

	TAILQ_FOREACH(f, &friendhead, entry)
		if (f->fid == fid)
			return;

	friendcreate(fid);
}

static void
cb_friend_message(Tox *tox, int32_t fid, const uint8_t *data, uint16_t len, void *udata)
{
	FILE *fp;
	struct friend *f;
	uint8_t msg[len + 1];
	char path[PATH_MAX];

	memcpy(msg, data, len);
	msg[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			snprintf(path, sizeof(path), "%s/text_out", f->idstr);
			fp = fopen(path, "a");
			if (!fp) {
				perror("fopen");
				exit(1);
			}
			fputs(msg, fp);
			fputc('\n', fp);
			fclose(fp);
			break;
		}
	}
}

static void
cb_friend_request(Tox *tox, const uint8_t *id, const uint8_t *data, uint16_t len, void *udata)
{
	uint8_t msg[len + 1];

	memcpy(msg, data, len);
	msg[len] = '\0';
	tox_add_friend_norequest(tox, id);
	if (len > 0)
		printf("Accepted friend request with msg: %s\n", msg);
	else
		printf("Accepted friend request\n");
	datasave();
}

static void
cb_name_change(Tox *m, int32_t fid, const uint8_t *data, uint16_t len, void *user)
{
	FILE *fp;
	char path[PATH_MAX];
	struct friend *f;
	uint8_t name[len + 1];

	memcpy(name, data, len);
	name[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			snprintf(path, sizeof(path), "%s/name", f->idstr);
			fp = fopen(path, "w");
			if (!fp) {
				perror("fopen");
				exit(1);
			}
			fputs(name, fp);
			fputc('\n', fp);
			fclose(fp);
			if (memcmp(f->namestr, name, len + 1) == 0)
				break;
			if (f->namestr[0] == '\0') {
				printf("%s -> %s\n", "Anonymous", name);
			} else {
				printf("%s -> %s\n", f->namestr, name);
			}
			memcpy(f->namestr, name, len + 1);
			break;
		}
	}
	datasave();
}

static void
cb_status_message(Tox *m, int32_t fid, const uint8_t *data, uint16_t len, void *udata)
{
	FILE *fp;
	char path[PATH_MAX];
	struct friend *f;
	uint8_t status[len + 1];

	memcpy(status, data, len);
	status[len] = '\0';

	TAILQ_FOREACH(f, &friendhead, entry) {
		if (f->fid == fid) {
			snprintf(path, sizeof(path), "%s/status", f->idstr);
			fp = fopen(path, "w");
			if (!fp) {
				perror("fopen");
				exit(1);
			}
			fputs(status, fp);
			fputc('\n', fp);
			fclose(fp);
			printf("%s current status to %s\n", f->namestr, status);
			break;
		}
	}
	datasave();
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
		exit(1);
	}
	tox_send_message(tox, f->fid, buf, n);
}

static void
dataload(void)
{
	FILE *fp;
	size_t sz;
	uint8_t *data;

	fp = fopen("ratatox.data", "r");
	if (!fp)
		return;

	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	rewind(fp);

	data = malloc(sz);
	if (!data) {
		perror("malloc");
		exit(1);
	}

	if (fread(data, 1, sz, fp) != sz) {
		fprintf(stderr, "failed to read ratatox.data\n");
		exit(1);
	}
	tox_load(tox, data, sz);

	free(data);
	fclose(fp);
}

static void
datasave(void)
{
	FILE *fp;
	size_t sz;
	uint8_t *data;

	fp = fopen("ratatox.data", "w");
	if (!fp) {
		fprintf(stderr, "can't open ratatox.data for writing\n");
		exit(1);
	}

	sz = tox_size(tox);
	data = malloc(sz);
	if (!data) {
		perror("malloc");
		exit(1);
	}

	tox_save(tox, data);
	if (fwrite(data, 1, sz, fp) != sz) {
		fprintf(stderr, "failed to write ratatox.data\n");
		exit(1);
	}

	free(data);
	fclose(fp);
}

static void
toxrestore(void)
{
	dataload();
	datasave();
}

static int
toxinit(void)
{
	uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
	int i;

	tox = tox_new(0);
	toxrestore();
	tox_callback_connection_status(tox, cb_conn_status, NULL);
	tox_callback_friend_message(tox, cb_friend_message, NULL);
	tox_callback_friend_request(tox, cb_friend_request, NULL);
	tox_callback_name_change(tox, cb_name_change, NULL);
	tox_callback_status_message(tox, cb_status_message, NULL);
	tox_set_name(tox, "TLH", strlen("TLH"));
	tox_set_user_status(tox, TOX_USERSTATUS_NONE);

	tox_get_address(tox, address);
	printf("ID: ");
	for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++)
		printf("%02x", address[i]);
	putchar('\n');


	return 0;
}

static int
toxconnect(void)
{
	struct bootstrapnode *bn;
	size_t i;

	for (i = 0; i < LEN(bootstrapnodes); i++) {
		bn = &bootstrapnodes[i];
		tox_bootstrap_from_address(tox, bn->addr, bn->port, bn->key);
	}
	return 0;
}

static int
id2str(uint8_t *id, uint8_t *idstr)
{
	uint8_t hex[] = "0123456789abcdef";
	int i;

	for (i = 0; i < TOX_CLIENT_ID_SIZE; i++) {
		*idstr++ = hex[(id[i] >> 4) & 0xf];
		*idstr++ = hex[id[i] & 0xf];
	}
	*idstr = '\0';
}

static void
friendcreate(int32_t fid)
{
	struct friend *f;
	char path[PATH_MAX];
	int i;
	int r;

	f = calloc(1, sizeof(*f));
	if (!f) {
		perror("malloc");
		exit(1);
	}

	r = tox_get_name(tox, fid, f->namestr);
	if (r < 0) {
		fprintf(stderr, "tox_get_name() on fid %d failed\n", fid);
		exit(1);
	}
	f->namestr[r] = '\0';

	f->fid = fid;
	tox_get_client_id(tox, f->fid, f->id);
	id2str(f->id, f->idstr);

	r = mkdir(f->idstr, 0755);
	if (r < 0 && errno != EEXIST) {
		perror("mkdir");
		exit(1);
	}

	for (i = 0; i < LEN(fifos); i++) {
		snprintf(path, sizeof(path), "%s/%s", f->idstr,
			 fifos[i].name);
		r = mkfifo(path, fifos[i].mode);
		if (r < 0 && errno != EEXIST) {
			perror("mkfifo");
			exit(1);
		}
		r = open(path, O_RDONLY | O_NONBLOCK, 0);
		if (r < 0) {
			perror("open");
			exit(1);
		}
		f->fd[i] = r;
	}
	TAILQ_INSERT_TAIL(&friendhead, f, entry);
}

static void
friendload(void)
{
	int32_t *fids;
	uint32_t sz;
	uint32_t i, j;
	int n;
	char name[TOX_MAX_NAME_LENGTH + 1];

	sz = tox_count_friendlist(tox);
	fids = malloc(sz);
	if (!fids) {
		perror("malloc");
		exit(1);
	}

	tox_get_friendlist(tox, fids, sz);

	for (i = 0; i < sz; i++)
		friendcreate(fids[i]);
}

static void
loop(void)
{
	struct friend *f;
	time_t t0, t1;
	int connected = 0;
	int i, n;
	int fdmax = 0;
	fd_set rfds;
	struct timeval tv;

	t0 = time(NULL);
	toxconnect();
	while (1) {
		if (tox_isconnected(tox) == 1) {
			if (connected == 0) {
				printf("Connected to DHT\n");
				connected = 1;
			}
		} else {
			t1 = time(NULL);
			if (t1 > t0 + 5) {
				t0 = time(NULL);
				printf("Connecting to DHT...\n");
				toxconnect();
			}
		}
		tox_do(tox);

		FD_ZERO(&rfds);
		TAILQ_FOREACH(f, &friendhead, entry) {
			for (i = 0; i < NR_FIFOS; i++) {
				if (f->fd[i] > fdmax)
					fdmax = f->fd[i];
				FD_SET(f->fd[i], &rfds);
			}
		}

		tv.tv_sec = 0;
		tv.tv_usec = tox_do_interval(tox) * 1000;
		n = select(fdmax + 1, &rfds, NULL, NULL,
			   &tv);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("select");
			exit(1);
		}

		TAILQ_FOREACH(f, &friendhead, entry) {
			for (i = 0; i < NR_FIFOS; i++) {
				if (FD_ISSET(f->fd[i], &rfds) == 0)
					continue;
				switch (i) {
				case TEXT_IN_FIFO:
					send_friend_text(f);
					break;
				default:
					fputs("Unhandled FIFO read\n", stderr);
				}
			}
		}
	}
}

int
main(void)
{
	toxinit();
	friendload();
	loop();
	return 0;
}
