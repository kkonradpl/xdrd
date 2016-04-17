CC = gcc
CFLAGS = -Wall -pedantic -std=c99 -c -O2 -D_GNU_SOURCE
LIBS = -lpthread -lcrypto

xdrd:	xdrd.o
	$(CC) -o xdrd xdrd.o $(LIBS)

xdrd.o:	xdrd.c xdr-protocol.h
	$(CC) $(CFLAGS) xdrd.c

clean:
	rm -f *.o xdrd
