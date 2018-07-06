CC = gcc
CFLAGS = -O3 -std=c99 -W -fPIC 
 
LIB_OBJS = \
	./src/murmur3.o

LIBRARY = murmur3.so

$(LIBRARY): $(LIB_OBJS)
	$(CC) -shared -Wl,--export-dynamic $(LIB_OBJS) -o $(LIBRARY)

tests:
	$(CC) -o murmur3-tests murmur3-tests.c ./murmur3.so

clean:
	rm -rf *.so src/*.o ./murmur3-tests
