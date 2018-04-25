.POSIX:
.SUFFIXES:

CC = gcc
CFLAGS = -pedantic -Wall -Wextra -Werror -fPIC
CFLAGS += -DFORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS = -lcrypto -lm -shared -fPIC -Wl,-z,relro,-z,now

all: keygen.o rtrs.o echash.o sub.o bootle.o spend.o multisig.o verify.o
	$(CC) -o librtrs.so $(CFLAGS) $^ $(LDFLAGS)

rtrs.o: rtrs.c
keygen.o: keygen.c
echash.o: echash.c
sub.o: sub.c
spend.o: spend.c
bootle.o: bootle.c
multisig.o: multisig.c
verify.o: verify.c

debug: CFLAGS += -DDEBUG -g -fsanitize=address
debug: all

test: debug test.c
	$(CC) -o test -g $(CFLAGS) test.c -L. -lasan -lm -lrtrs -lcrypto && LD_LIBRARY_PATH=. ./test

clean:
	rm *.o *.so

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) $<
