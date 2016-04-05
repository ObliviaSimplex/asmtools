CC = gcc
CFLAGS = -fPIC -Wall -O0 
LDFLAGS = -shared
STACKFLAGS = -zexecstack -fno-stack-protector

AS = as
LD = ld

ASFLAGS =
BINLDFLAGS = -Ttext 200000 --oformat binary

ELFCODE = example.elf
FLATBIN = example.bin
EXAMPLE = example.s
EXAMPLE_HEADER = example.h

DUMP = xxd
DUMPFLAGS = -i


TARGET = libhatchery.so
SOURCES = hatchery.c
HEADERS = hatchery.h
TEST = test
TESTSRC = main.c example.h
OBJECTS = $(SOURCES:.c=.o)



.PHONY: dump clean dotest all

all: $(TARGET) $(TEST) $(FLATBIN) $(EXAMPLE_HEADER) dotest

clean:
	rm -f $(OBJECTS) $(TARGET) $(TEST) $(FLATBIN) $(ELFCODE) $(EXAMPLE_HEADER)

$(TARGET): $(OBJECTS)
	export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:`pwd`"
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDFLAGS) $(STACKFLAGS)


$(ELFCODE): $(EXAMPLE)
	$(AS) $(ASFLAGS) $(EXAMPLE) -o $(ELFCODE)

$(FLATBIN): $(ELFCODE)
	$(LD) $(BINLDFLAGS) $(ELFCODE) -o $(FLATBIN)

$(EXAMPLE_HEADER): $(FLATBIN)
	  $(DUMP) $(DUMPFLAGS) $(FLATBIN) | tee $(EXAMPLE_HEADER)


$(TEST): $(TARGET) $(TESTSRC) $(EXAMPLE_HEADER)
	$(CC) -L `pwd` -lhatchery main.c -o test $(STACKFLAGS)

dotest:
	LD_LIBRARY_PATH="$LD_LIBRARY_PATH:`pwd`" ./test

