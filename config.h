/* See LICENSE file for copyright and license details. */

/* Connection delay in seconds */
#define CONNECTDELAY 3

/* Ringing delay in seconds */
#define RINGINGDELAY 16

/* Maximum number of simultaneous calls */
#define MAXCALLS 8

static char *savefile        = ".ratox.tox";
static int   encryptsavefile = 0;

static int      ipv6        = 0;
static int      tcp         = 0;
static int      proxy       = 0;
static int      proxytype   = 2; /* 1 = HTTP, 2 = SOCKS5 */
static char     proxyaddr[] = "localhost";
static uint16_t proxyport   = 8080;

#include "nodes.h"
