
CFLAGS      = -c -fpic
INCLUDES    = -I/usr/local/ssl/include
LFLAGS      = -L/usr/local/ssl/lib
LIBS        = -lssl -lcrypto -pthread -lm -ldl

RM= rm -f


all: sample md5 sha256

sample: sample_engine sample_engine.so

sample_engine: sample_engine.c
	$(CC) $(CFLAGS) $(INCLUDES) sample_engine.c $(LIBS)

sample_engine.so: sample_engine.o
	$(CC) -shared -o sample_engine.so sample_engine.o


md5: md5_engine md5_engine.so

md5_engine: md5_engine.c rfc1321/md5.c
	$(CC) $(CFLAGS) $(INCLUDES) md5_engine.c $(LIBS)
	$(CC) $(CFLAGS) $(INCLUDES) rfc1321/md5.c -o rfc1321/md5.o $(LIBS)

md5_engine.so: md5_engine.o
	$(CC) -shared -lcrypto -o md5_engine.so md5_engine.o rfc1321/md5.o


sha256: sha256_engine.o sha256_engine.so

sha256_engine.o: sha256_engine.c
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) sha256_engine.c

sha256_engine.so: sha256_engine.o
	$(CC) -shared -lcrypto -o sha256_engine.so sha256_engine.o


clean:
	$(RM) sample_engine.o
	$(RM) sample_engine.so
	$(RM) md5_engine.o
	$(RM) md5_engine.so
	$(RM) rfc1321/md5.o
	$(RM) sha256_engine.o
	$(RM) sha256_engine.so
