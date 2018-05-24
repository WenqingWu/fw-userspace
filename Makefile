cc = gcc
TARGET = main

deps = $(shell find . -name "*.h")
src = $(shell find . -name "*.c")

obj = $(src:%.c=%.o) 

$(TARGET): $(obj)
	$(cc) -D __KERNEL__ -o $(TARGET) $(obj)

%.o: %.c $(deps)
	$(cc) -D __KERNEL__ -c $< -o $@

