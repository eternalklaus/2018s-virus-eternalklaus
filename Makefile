CFLAGS= -Wall -fno-stack-protector
TARGET= bin/virus
SOURCE=src/virus.c
CC= gcc 

$(TARGET):;\
$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

all:$(TARGET)

clean:;\
rm $(TARGET)
.PHONY: all clean
