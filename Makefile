VERSION = 2.4.20
TOPDIR = $(shell /bin/pwd)

CC = gcc
CFLAGS = -fno-builtin-FUNCTION
TARGET = main

SRC = $(shell find . -name "*.c")

OBJ = $(SRC:%.c=%.o) 

SUB_OBJ = netfilter.o
$(TARGET):$(SUB_OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(SUB_OBJ)

%*.o:%*.c
	$(CC) -c $^ -o $@

clean:
	rm -f *.o netfilter/*.o