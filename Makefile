CC     := gcc
CFLAGS := -Wall -Werror 

SRCS   := client.c \
		  server.c 

OBJS   := ${SRCS:c=o}
PROGS  := ${SRCS:.c=}

CURDIR	:= ${shell pwd}

.PHONY: all
all: server libmfs.so img

img: mkfs.c
	${CC} ${CFLAGS} mkfs.c -o mkfs

libmfs.so: mfs.o
	${CC} ${CFLAGS} -shared -Wl,-soname,libmfs.so -o libmfs.so mfs.o udp.c -lc

mfs.o: mfs.c
	${CC} fPIC -g -c mfs.c

server: server.c load
	${CC} ${CFLAGS} server.c udp.c -o server

load:
	export LD_LIBRARY_PATH=${CURDIR}

clean:
	rm -f *.o
	rm -f *.so
	rm -f mkfs
	rm -f *.img

%.o: %.c Makefile
	${CC} ${CFLAGS} -c $<
