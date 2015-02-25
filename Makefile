CC = gcc
CFLAGS = -Wall -pedantic -std=c99 -c -O2 -D_GNU_SOURCE
LIBS = -lpthread

xdrd:			xdrd.o sha1.o
				$(CC) -s -o xdrd xdrd.o sha1.o $(LIBS)

xdrd.o:			xdrd.c sha1.h
				$(CC) $(CFLAGS) xdrd.c

sha1.o:			sha1.c sha1.h
				$(CC) $(CFLAGS) sha1.c

clean:
				rm -f *.o xdrd
