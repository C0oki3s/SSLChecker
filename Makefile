# Define the compiler
CC = gcc

# Define the flags for the compiler
CFLAGS = -Wall -I/usr/include/json-c

# Define the flags for the linker
LDFLAGS = -lssl -lcrypto -ljson-c -pthread

# Define the target executable name
TARGET = ssl

# Define the source file
SRCS = ssl.c

# Define the object file
OBJS = $(SRCS:.c=.o)

# The default rule
all: $(TARGET)

# Rule to link the object files into the final executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Rule to compile the source file into an object file
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

# Rule to clean up the build directory
clean:
	rm -f $(TARGET) $(OBJS)

# Rule to install the necessary libraries
install:
	sudo apt-get update
	sudo apt-get install -y libssl-dev libjson-c-dev

# Phony targets
.PHONY: all clean install
