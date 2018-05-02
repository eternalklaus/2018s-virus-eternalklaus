### This is a sample Makefile. You are free to modify this file.
CFLAGS= -g -O2 -Wall -static #-static -nostdlib -fPIC -pie
all: bin bin/virus
bin/virus: src/virus.c
	$(CC) $(CFLAGS) -o $@ $<

bin:
	@mkdir -p $@

clean:
	@rm -rf bin/

.PHONY: all clean
