
CFLAGS      = -c -fpic
INCLUDES    = -I/usr/local/ssl/include
LFLAGS      = -L/usr/local/ssl/lib
LIBS        = -lssl -lcrypto -pthread -lm -ldl

RM= rm -f


all: sample_engine sample_engine.so


sample_engine: sample_engine.c
	$(CC) $(CFLAGS) $(INCLUDES) sample_engine.c $(LIBS)

sample_engine.so: sample_engine.o
	$(CC) -shared -o sample_engine.so sample_engine.o

clean:
	$(RM) sample_engine.o
	$(RM) sample_engine.so
