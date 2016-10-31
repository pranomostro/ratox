# ratox version
VERSION = 0.2.1

# paths
PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

TOX_CFLAGS = -I./toxcore/toxcore -I./toxcore/toxav -I./toxcore/toxencryptsave -I/usr/include/opus

CC = cc
LD = $(CC)
CPPFLAGS = -DVERSION=\"${VERSION}\" $(TOX_CFLAGS)
CFLAGS   = -g -Wall -Wunused $(CPPFLAGS)
LDFLAGS  = -g -lopus -lvpx -lpthread -lsodium
