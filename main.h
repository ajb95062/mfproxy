

// standard includes
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <syslog.h>


// libevent
#include <event2/event.h>
#include <event2/util.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/dns.h>


// a few useful macros
#define loopi(limit)  for(int i = 0; i < (limit); i++)
#define loopj(limit)  for(int j = 0; j < (limit); j++)
#define arraysize(a)  (sizeof(a)/sizeof((a)[0]))


// forward class declarations
class DatabaseBackendConfig;
struct PacketData;
class Packet;
class BinaryEncoder;
class BinaryDecoder;
class Connection;
class DatabaseConnection;
class ClientConnection;
class ConnectionPool;
class StatsdInterface;


// main.cxx
extern const char * program_name;
void timeval_subtract(struct timeval * result, struct timeval * x, struct timeval * y);
double timeval_seconds(const struct timeval * tv);
void log_message(const char * format, ...);
void log_error_message(const char * format, ...);
void log_debug_message(const char * format, ...);
void panic(const char * format, ...);
void not_yet_implemented();


extern "C" {
#include "lcfg_static.h"
}

#include "sha1.h"

#include "config.h"
#include "mysql_flags.h"
#include "stats.h"
#include "packets.h"
#include "encode_decode.h"
#include "connection_pool.h"
#include "connection.h"
#include "client_connection.h"
#include "database_connection.h"
#include "server.h"

