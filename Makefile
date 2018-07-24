VERSION = 2.4.20
TOPDIR = $(shell /bin/pwd)

CC = gcc
CFLAGS = -Iinclude -fgnu89-inline
TARGET = fwtest

# SRC = $(shell find . -name "*.c")
# SRC = $(wildcard *.c ./netfilter/*.c ./core/*.c ./kernel/*.c)
SRC = $(wildcard ./core/*.c ./netfilter/*.c *.c)

OBJ = $(SRC:%.c=%.o) 

$(TARGET):$(OBJ)
	$(CC) -o $(TARGET) $(OBJ)

%*.o:%*.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f *.o netfilter/*.o core/*.o fwtest