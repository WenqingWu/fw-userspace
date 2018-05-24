cc = gcc
TARGET = main

deps = $(shell find . -name "*.h")
src = $(shell find . -name "*.c")

obj = $(src:%.c=%.o) 

$(TARGET): $(obj)
	$(cc)  -o $(TARGET) $(obj)

%.o: %.c
	$(cc)  -c $^ -o $@

clean:
	rm -f *.o netfilter/*.o