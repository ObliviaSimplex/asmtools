CC = gcc
CFLAGS = -fPIC -Wall -O0
LDFLAGS = -shared

TARGET = libhatchery.so
SOURCES = hatchery.c
HEADERS = hatchery.h
TEST = test
TESTSRC = main.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET) $(TEST)

clean:
	#echo "About to remove $(OBJECTS) $(TARGET)."
	#echo "Hit <ENTER> to continue..."
	#read
	rm -f $(OBJECTS) $(TARGET) $(TEST)

$(TARGET): $(OBJECTS)
	export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:`pwd`"
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

$(TEST): $(TARGET) $(TESTSRC)
	$(CC) -L `pwd` -lhatchery main.c -o test
	LD_LIBRARY_PATH="$LD_LIBRARY_PATH:`pwd`" ./test
