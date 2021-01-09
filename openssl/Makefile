
CFLAGS      = -c -fpic
INCLUDES    = -I/usr/local/include
LFLAGS      = -L/usr/local/lib
LIBS        = -lssl -lcrypto -pthread -lm -ldl

RM= rm -f


all: sample md5 sha256

sample: sample_engine sample_engine.so

sample_engine: sample_engine.c
	$(CC) sample_engine.c $(CFLAGS) $(INCLUDES) $(LIBS)

sample_engine.so: sample_engine.o
	$(CC) -shared -o sample_engine.so sample_engine.o


md5: md5_engine md5_engine.so md5_tester md_test

md5_engine: md5_engine.c rfc1321/md5.c
	$(CC) md5_engine.c $(CFLAGS) $(INCLUDES) $(LIBS)
	$(CC) rfc1321/md5.c $(CFLAGS) $(INCLUDES) $(LIBS) -o rfc1321/md5.o

md5_engine.so: md5_engine.o
	$(CC) -shared -lcrypto -o md5_engine.so md5_engine.o rfc1321/md5.o

md5_tester: md5_tester.c
	$(CC) md5_tester.c -o md5_tester $(INCLUDES) $(LFLAGS) $(LIBS)

md_test: md_test.c
	$(CC) md_test.c -o md_test $(INCLUDES) $(LFLAGS) $(LIBS)


sha256: sha256_engine.o sha256_engine.so

sha256_engine.o: sha256_engine.c
	$(CC) sha256_engine.c $(CFLAGS) $(INCLUDES) $(LIBS)

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
