BIN	= uc_crypto
CC	= gcc
CFLAGS	= -g -static -Wall 
COMPILE	= *.c

all: bin lib

bin:
	$(CC) $(CFLAGS) -I. $(COMPILE) -o $(BIN)

lib:
	$(CC) -shared -fPIC -I. $(COMPILE) -shared -o $(BIN).so

prepare:
	wget https://tweetnacl.cr.yp.to/20131229/tweetnacl.c
	wget https://tweetnacl.cr.yp.to/20131229/tweetnacl.h
	wget https://raw.githubusercontent.com/ultramancool/tweetnacl-usable/master/randombytes.c

clean:
	rm -rf mcore_* __pycache__/ uc_crypto *.so
	rm tweetnacl.* randombytes.c
