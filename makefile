.POSIX:
.SUFFIXES:

CC = gcc
CFLAGS = -pedantic -O3 -Wall -Wextra -Werror
LDFLAGS = -lcrypto -shared -fPIC

all: keygen.o rtrs.o
	$(CC) -o librtrs.so $(CFLAGS) $^ $(LDFLAGS)

rtrs.o: rtrs.c
keygen.o: keygen.c

clean:
	rm *.o *.so

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) $<
