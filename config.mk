# ratox version
VERSION = 0.3

# paths
PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

CC = cc
LD = $(CC)
CPPFLAGS = -DVERSION=\"${VERSION}\"
CFLAGS   = -g -I/usr/local/include -Wall -Wunused $(CPPFLAGS)
LDFLAGS  = -g -L/usr/local/lib
LDLIBS   = -ltoxcore -ltoxav -ltoxencryptsave -lsodium -lopus -lvpx -lm -lpthread
