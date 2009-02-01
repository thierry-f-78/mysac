CFLAGS = -I../events/ -I/usr/include/mysql -O0 -g
LDFLAGS = -g -L../events -levents -lmysqlclient_r

OBJS = mysac.o mysac_net.o mysac_decode_paquet.o mysac_decode_row.o

main: main.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f main main.o $(OBJS)
