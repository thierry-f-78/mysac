MY_CFLAGS = -I..
MY_LDFLAGS = -L.. -lmysac 

all: client client_iofunc

client: client.o
	$(CC) -o client client.o $(LDFLAGS) $(MY_LDFLAGS)

client.o: client.c
	$(CC) -c -o client.o client.c $(CFLAGS) $(MY_CFLAGS)

client_iofunc: client_iofunc.o
	$(CC) -o client_iofunc client_iofunc.o $(LDFLAGS) $(MY_LDFLAGS)

client_iofunc.o: client_iofunc.c
	$(CC) -c -o client_iofunc.o client_iofunc.c $(CFLAGS) $(MY_CFLAGS)

clean:
	client.o client_iofunc.o client client_iofunc
