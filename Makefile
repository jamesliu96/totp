CC = cc

OPENSSL_CFLAGS = $(shell pkg-config --libs openssl)

libtotp.so:
	$(CC) -c -Wall -fPIC -O2 src/totp.c
	$(CC) -shared -o libtotp.so totp.o $(OPENSSL_CFLAGS)

all: libtotp.so

clean:
	rm -rf totp.o libtotp.so
	rm -rf test/test

test: all
	$(CC) -Wall -o test/test test/test.c -L./ -ltotp -Isrc/
	./test/test

.PHONY: all clean test