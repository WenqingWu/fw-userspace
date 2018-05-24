VERSION = 2.4.20
TOPDIR = $(shell /bin/pwd)

CC = gcc
TARGET = main

SRC = $(shell find . -name "*.c")

OBJ = $(SRC:%.c=%.o) 

$(TARGET):$(OBJ)
	$(CC) -o $(TARGET) $(OBJ)

%*.o:%*.c
	$(CC) -c $^ -o $@

clean:
	rm -f *.o netfilter/*.o