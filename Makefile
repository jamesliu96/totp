CC = cc

FLAGS = -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto -lz

libtotp.so:
	$(CC) --shared -Wall -fPIC -O2 $(FLAGS) src/totp.c -o libtotp.so

all: libtotp.so

clean:
	rm -rf totp.o libtotp.so
	rm -rf test/test

test: all
	$(CC) -Wall $(FLAGS) -Isrc/ -L./ -ltotp test/test.c -o test/test
	./test/test

.PHONY: all clean test