/* See LICENSE file for copyright and license details. */

/* Connection delay in seconds */
#define CONNECTDELAY 3

/* Ringing delay in seconds */
#define RINGINGDELAY 16

/* Maximum number of simultaneous calls */
#define MAXCALLS 8

/* Audio settings definition */
#define AUDIOCHANNELS     1
#define AUDIOBITRATE      32
#define AUDIOFRAME        20
#define AUDIOSAMPLERATE   48000

/* Video settings definition */
#define VIDEOWIDTH        1280
#define VIDEOHEIGHT       720
#define VIDEOBITRATE      2500

static int   friendmsg_log = 1;
static int   confmsg_log   = 0;

static char *savefile        = ".ratox.tox";
static int   encryptsavefile = 0;

static int                 ipv6        = 0;
static int                 tcp         = 0;
static int                 proxy       = 0;
static TOX_PROXY_TYPE      proxytype   = TOX_PROXY_TYPE_SOCKS5; /* NONE, HTTP, SOCKS5 */
static int                 quiet       = 0;
static char     proxyaddr[] = "localhost";
static uint16_t proxyport   = 8080;

#include "nodes.h"
