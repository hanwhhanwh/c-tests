
CFLAGS      = -c -fpic
INCLUDES    = -I/usr/local/include
LFLAGS      = -L/usr/local/lib
LIBS        = -lssl -lcrypto -pthread -lm -ldl

RM= rm -f


all: oezgan_engine oezgan_tester


oezgan_engine: oezgan_engine.o oezgan_engine.so

oezgan_engine.o: OezganEngine.c
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) OezganEngine.c

oezgan_engine.so: OezganEngine.o
	$(CC) -shared -o OezganEngine.so OezganEngine.o


oezgan_tester:
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) EngineTester.c


clean:
	$(RM) OezganEngine.o
	$(RM) OezganEngine.so
