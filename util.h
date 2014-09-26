/* See LICENSE file for copyright and license details. */
#include "arg.h"

#define LEN(x) (sizeof (x) / sizeof *(x))

extern char *argv0;

void enprintf(int, const char *, ...);
void eprintf(const char *, ...);
void weprintf(const char *, ...);
