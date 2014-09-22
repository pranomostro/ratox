include config.mk

.POSIX:
.SUFFIXES: .c .o

HDR = arg.h readpassphrase.h
LIB = \
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

$(OBJ): readpassphrase.h config.mk

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
	@cd $(DESTDIR)$(PREFIX)/bin && chmod 755 $(BIN)

uninstall:
	@echo removing executable from $(DESTDIR)$(PREFIX)/bin
	@cd $(DESTDIR)$(PREFIX)/bin && rm -f $(BIN)

clean:
	@echo cleaning
	@rm -f $(BIN) $(OBJ) $(LIB) util.a
