CFLAGS = -I../events/ -O0 -g
LDFLAGS = -g -L../events -levents -lmysqlclient_r

OBJS = mysac.o mysac_net.o

main: main.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f main main.o $(OBJS)
