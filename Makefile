# Define the compiler
CC = gcc

# Define the flags for the compiler
CFLAGS = -Wall -I/usr/include/json-c -g -O2

# Define the flags for the linker
LDFLAGS = -lssl -lcrypto -ljson-c -lssh2 -pthread

# Define the target executable name
TARGET = ssl

# Define the source file
SRCS = ssl.c

# Define the object file
OBJS = $(SRCS:.c=.o)

# Define dependency files
DEPS = $(SRCS:.c=.d)

# The default rule
all: $(TARGET)

# Rule to link the object files into the final executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Rule to compile the source file into an object file
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to generate dependency files
%.d: %.c
	$(CC) $(CFLAGS) -M $< > $@

# Rule to clean up the build directory
clean:
	rm -f $(TARGET) $(OBJS) $(DEPS)

# Rule to install the necessary libraries
install:
	sudo apt-get update
	sudo apt-get install -y libssl-dev libjson-c-dev libssh2-1-dev

# Include dependency files
-include $(DEPS)

# Phony targets
.PHONY: all clean install

# Suppress command output unless V=1 is specified
ifndef V
.SILENT:
endif