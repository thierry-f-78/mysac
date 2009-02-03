CFLAGS = -I/usr/include/mysql -O0 -g
LDFLAGS = -g -lmysqlclient_r

OBJS = mysac.o mysac_net.o mysac_decode_field.o mysac_decode_row.o mysac_errors.o

build: make.deps
	$(MAKE) lib

lib: libmysac.a libmysac.so

libmysac.so: libmysac.a
	$(LD) -o libmysac.so -shared -soname libmysac.so.0.0 libmysac.a

libmysac.a: $(OBJS)
	$(AR) -rcv libmysac.a $(OBJS)

make.deps: *.c *.h
	for src in *.c; do \
		DEPS="$$(sed -e 's/^#include[ 	]"\(.*\)"/\1/; t; d;' $$src | xargs echo)"; \
		echo "$${src//.c/.o}: $$src $$DEPS"; \
	done > make.deps

clean:
	rm -rf make.deps libmysac.so libmysac.a main.o man html $(OBJS)

doc:
	doxygen mysac.doxygen

include make.deps
