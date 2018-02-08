.POSIX:
.SUFFIXES:

CC = gcc
CFLAGS = -pedantic -Wall -Wextra -Werror
LDFLAGS = -lcrypto -shared -fPIC

all: keygen.o rtrs.o echash.o sub.o
	$(CC) -o librtrs.so $(CFLAGS) $^ $(LDFLAGS)

rtrs.o: rtrs.c
keygen.o: keygen.c
echash.o: echash.c
sub.o: sub.c

debug: CFLAGS += -DDEBUG -g -fsanitize=address
debug: all

test: debug test.c
	$(CC) -o test -g $(CFLAGS) test.c -L. -lasan -lrtrs -lcrypto && LD_LIBRARY_PATH=. ./test

clean:
	rm *.o *.so

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) $<
