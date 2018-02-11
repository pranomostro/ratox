# ratox version
VERSION = 0.4

# paths
PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

CC = cc
LD = $(CC)
CPPFLAGS = -DVERSION=\"${VERSION}\"
CFLAGS   = -I/usr/local/include -Wall -Wunused $(CPPFLAGS) -g
LDFLAGS  = -L/usr/local/lib64 -g
LDLIBS   = -ltoxcore -lsodium -lopus -lvpx -lm -lpthread
