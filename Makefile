### This is a sample Makefile. You are free to modify this file.
CFLAGS=-g -O2 -fPIC -pie -Wall
all: bin bin/virus

bin/virus: src/virus.c
	$(CC) $(CFLAGS) -o$@ $<

bin:
	@mkdir -p $@

clean:
	@rm -rf bin/

.PHONY: all clean
