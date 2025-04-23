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
all: check-libs $(TARGET)

# Rule to check for required libraries
check-libs:
	@echo "Checking for required libraries..."
	@pkg-config --exists libssl json-c libssh2 || { \
		echo "Error: Missing required libraries. Run 'make install' to install them."; \
		exit 1; \
	}
	@echo "All required libraries are present."

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

# Rule to install the necessary libraries (Debian/Ubuntu)
install:
	@echo "Installing required libraries for Debian/Ubuntu..."
	@sudo apt-get update || { echo "Failed to update package lists"; exit 1; }
	@sudo apt-get install -y libssl-dev libjson-c-dev libssh2-1-dev pkg-config || { echo "Failed to install libraries"; exit 1; }
	@echo "Libraries installed successfully."
	@echo "Note: For other systems, use the following:"
	@echo "  CentOS/RHEL: sudo yum install -y openssl-devel json-c-devel libssh2-devel pkgconf"
	@echo "  macOS (Homebrew): brew install openssl json-c libssh2 pkg-config"

# Include dependency files
-include $(DEPS)

# Phony targets
.PHONY: all clean install check-libs

# Suppress command output unless V=1 is specified
ifndef V
.SILENT:
endif