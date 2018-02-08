CC=gcc
CFLAGS=-g -Wall -DPYR_TESTING=1
LIBS=-lsmv -lpthread

TESTS = memdom_ops_test

all: $(TESTS)

memdom_ops_test: memdom_ops_tests.c ; $(CC) $(CFLAGS) $^ -o $@ $(LIBS)

.PHONY: clean test

test: ; for t in $(TESTS); do bash test.sh $$t ; done

clean: ; rm -rf *.o *~ *_test
