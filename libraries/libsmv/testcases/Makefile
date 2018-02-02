GCC = gcc
CFLAGS = -g -Wall -L/usr/local/
LIBS = -lsmv -lpthread

TESTS = tc_smv_create tc_memdom_create \
	 privs_t1 tc_smvthread_create \
	 tc_shared_mm tc_memdom_alloc

all: $(TESTS)

tc_smv_create:
	$(GCC) $(CFLAGS) $@.c -o $@.o $(LIBS)

tc_memdom_create:
	$(GCC) $(CFLAGS) $@.c -o $@.o $(LIBS)

privs_t1:
	$(GCC) $(CFLAGS) $@.c -o $@.o $(LIBS)

tc_smvthread_create:
	$(GCC) $(CFLAGS) $@.c -o $@.o $(LIBS)

tc_shared_mm:
	$(GCC) $(CFLAGS) $@.c -o $@.o $(LIBS)

tc_cond_var:
	$(GCC) $(CFLAGS) $@.c -o $@.o $(LIBS)

tc_memdom_alloc:
	$(GCC) $(CFLAGS) $@.c -o $@.o $(LIBS)

test: ; for t in $(TESTS); do bash test.sh $$t ; done

clean:
	rm *.o
