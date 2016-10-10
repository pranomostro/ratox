/* See LICENSE file for copyright and license details. */

#include <tox/tox.h>

/* Connection delay in seconds */
#define CONNECTDELAY 3

/* Ringing delay in seconds */
#define RINGINGDELAY 16

/* Maximum number of simultaneous calls */
#define MAXCALLS 8

static char *savefile        = ".ratox.tox";
static int   encryptsavefile = 0;

static int      ipv6                 = 0;
static int      tcp                  = 0;
static int      proxy                = 0;
static TOX_PROXY_TYPE      proxytype = TOX_PROXY_TYPE_SOCKS5; /* NONE, HTTP, SOCKS5 */
static char     proxyaddr[] = "localhost";
static uint16_t proxyport   = 8080;

#include "nodes.h"
