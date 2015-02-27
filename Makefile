
CFLAGS = -Wall -I/usr/local/include -ggdb # use -ggdb for debug build, -O3 for production
LDFLAGS = -L/usr/local/lib
CC = g++ $(CFLAGS)

OBJS = client_connection.o config.o connection.o connection_pool.o database_connection.o encode_decode.o main.o lcfg_static.o packets.o server.o sha1.o stats.o
HEADERS = client_connection.h config.h connection.h connection_pool.h database_connection.h encode_decode.h lcfg_static.h main.h mysql_flags.h packets.h server.h sha1.h stats.h

mfproxy : $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -levent -o mfproxy

clean :
	rm -f mfproxy *.o *.log

lcfg_static.o : lcfg_static.c
	gcc $(CFLAGS) -c lcfg_static.c -o lcfg_static.o

%.o : %.cxx $(HEADERS)
	$(CC) -c $< -o $@


