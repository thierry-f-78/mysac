CFLAGS = -I../events/ -O0 -g
LDFLAGS = -L../events -levents -lmysqlclient_r

main: main.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f main *.o
