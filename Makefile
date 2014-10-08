include config.mk

.POSIX:
.SUFFIXES: .c .o

HDR = arg.h config.h readpassphrase.h util.h
LIB = \
	eprintf.o \
	readpassphrase.o
SRC = \
	ratox.c

OBJ = $(SRC:.c=.o) $(LIB)
BIN = $(SRC:.c=)
MAN = $(SRC:.c=.1)

all: binlib

binlib: util.a
	$(MAKE) bin

bin: $(BIN)

$(OBJ): $(HDR) config.mk

config.h:
	@echo creating $@ from config.def.h
	@cp config.def.h $@

.o:
	@echo LD $@
	@$(LD) -o $@ $< util.a $(LDFLAGS)

.c.o:
	@echo CC $<
	@$(CC) -c -o $@ $< $(CFLAGS)

util.a: $(LIB)
	@echo AR $@
	@$(AR) -r -c $@ $(LIB)
	@ranlib $@

install: all
	@echo installing executable to $(DESTDIR)$(PREFIX)/bin
	@mkdir -p $(DESTDIR)$(PREFIX)/bin
	@cp -f $(BIN) $(DESTDIR)$(PREFIX)/bin
	@chmod 755 $(DESTDIR)$(PREFIX)/bin/$(BIN)
	@echo installing manual page to $(DESTDIR)$(MANPREFIX)/man1
	@mkdir -p $(DESTDIR)$(MANPREFIX)/man1
	@cp -f ratox.1 $(DESTDIR)$(MANPREFIX)/man1

uninstall:
	@echo removing executable from $(DESTDIR)$(PREFIX)/bin
	@rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)
	@echo removing manual page from $(DESTDIR)$(MANPREFIX)/man1
	@rm $(DESTDIR)$(MANPREFIX)/man1/ratox.1

clean:
	@echo cleaning
	@rm -f $(BIN) $(OBJ) $(LIB) util.a
