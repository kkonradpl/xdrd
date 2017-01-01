CC = gcc
CFLAGS = -Wall -pedantic -std=c99 -c -O2 -D_GNU_SOURCE
LIBS = -lpthread -lcrypto
LIBS_WIN = $(LIBS) -lws2_32
INSTALL = install -c
TARGET = xdrd

PREFIX = $(DESTDIR)/usr
BINDIR = $(PREFIX)/bin

xdrd:	xdrd.o
	$(CC) -o $(TARGET) xdrd.o $(LIBS)

.PHONY:	windows
windows:	xdrd.o
	$(CC) -o $(TARGET) xdrd.o $(LIBS_WIN)

xdrd.o: xdrd.c xdr-protocol.h
	$(CC) $(CFLAGS) xdrd.c

.PHONY:	clean
clean:
	rm -f *.o xdrd

.PHONY:	install
install:	xdrd
	$(INSTALL) $(TARGET) $(BINDIR)/$(TARGET)

.PHONY:	uninstall
uninstall:
	rm -f $(BINDIR)/$(TARGET)
