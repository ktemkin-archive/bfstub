
# Use our cross-compile prefix to set up our basic cross compile environment.
CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
LD = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy

# Pull in information about our "hosted" libfdt.
include ../lib/fdt/Makefile.libfdt

# Allow user of our libraries.
VPATH = .:..:../lib:../lib/fdt

TARGET=test_runner
TESTS = \
	test_microlib.o \
	test_image.o

# Specify the pieces of discharge that will be used "under test".
OBJS = \
	microlib.o \
	printf.o \
	memmove.o \
	cache.o \
	image.o \
	$(LIBFDT_OBJS)

COMMON_FLAGS = \
	-D__RUNNING_ON_OS__ \
	-D__USE_SYSTEM_HEADERS__ \
	-Iinclude \
	-I../include \
	-Ilib/fdt \
	-I../lib/fdt \
	-I.. \
	-fno-stack-protector \
	-fno-common \
	-fno-builtin \
	-Werror \
	-Wall

CFLAGS = \
	$(COMMON_FLAGS) \
	-std=gnu99 \
	-ffreestanding \

CXXFLAGS = \
	-std=c++11 \
	$(COMMON_FLAGS)

LDFLAGS =

all: $(TARGET)

run_tests: $(TARGET)
	./test_runner

$(TARGET): $(TARGET).o $(OBJS) $(TESTS) helpers.o
	$(CXX) $(CXXFLAGS) $^ -o $@

%.o: %.S
	$(CC) $(CFLAGS) $< -c -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

clean:
	rm -f *.o $(TARGET) $(TARGET).bin $(TARGET).elf $(TARGET).fit

.PHONY: all clean run_tests
