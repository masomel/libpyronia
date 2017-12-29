CC = gcc
CFLAGS = -fPIC -g
LDFLAGS = -shared

TARGET = libsmv.so
SOURCES = kernel_comm.c memdom_lib.c smv_lib.c
HEADERS = kernel_comm.h memdom_lib.h smv_lib.h
OBJECTS = $(SOURCES:.c=.o)

PREFIX = /usr/local

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@  $(OBJECTS)

install:
	sudo cp $(TARGET) $(PREFIX)/lib; sudo cp *.h $(PREFIX)/include

clean:
	rm -f $(OBJECTS) $(TARGET)
