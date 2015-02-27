

// Stats collection and support for talking to a statsd backend.


// Represents runtime stats collected for a given period of time
// (generally in the 1-60 second range).  These are then sent to statsd.
class StatsCollector {
public:
  // Time period that these stats are for.  Initially only interval_start is populated.
  struct timeval interval_start, interval_end;
  double elapsed_seconds;  // interval_end - interval_start

public:
  void start();
  void stop();
  void send_to_statsd(StatsdInterface * interface);
};


// Stats about client connections.
class ClientStatsCollector : public StatsCollector {
public:
  // Network socket stats.
  int connections_accepted;
  int connections_closed;

  // Client network traffic stats.
  long bytes_read_from_clients;
  long bytes_sent_to_clients;

public:
  void start();
  void send_to_statsd(StatsdInterface * interface);
};


// Each ConnectionPool has one of these.
class PoolStatsCollector : public StatsCollector {
public:
  ConnectionPool * pool;
  
  // Network socket stats.
  int database_connections_established;
  int database_connections_closed;

  // Query timing stats.
  long queries_processed;
  long transactions_completed;
  double total_query_time;
  double lease_wait_time;
  double database_wait_time;
  double query_result_read_time;

  // Traffic to/from DBs in the pool.
  long bytes_read_from_databases;
  long bytes_sent_to_databases;

public:
  void start();
  void send_to_statsd(StatsdInterface * interface);
  void add_stats(const PoolStatsCollector * stats);
};


// Tracks the number of objects/memory currently allocated in the system.
// This can be used to check for memory leaks.
class AllocationStats {
public:
  // Object counts:
  int packets;  // instances of Packet or subclasses
  int packet_data_links;  // instances of PacketWithLink
  int client_connections;  // ClientConnection
  int database_connections;  // DatabaseConnection
  int encoder_buffer_chunks;  // BinaryEncoderBuffer chunk instances used by encode_decode.cxx
  int pending_lease_requests;  // PendingLeaseRequest

  // Amount of bytes taken by packet_data.data buffers.
  size_t packet_data_bytes;

  // Amount taken by dynamically allocated strings (for example, as part of packet field extraction).
  // This doesn't necessarily track everything, only things that are expected to be dynamic.
  // For example, we don't bother tracking strings allocated to configuration settings.
  size_t string_data_bytes;

public:
  AllocationStats();

  void send_to_statsd(StatsdInterface * interface);
};


// Manages the details of talking to statsd.
// Note that as of this writing, libevent does not support creating bufferevent
// objects for UDP sockets, which is what we really need for proper nonblocking
// statsd support.  So for now, we have to handle buffering the datagrams ourselves.
class StatsdInterface {
public:
  evutil_socket_t socket_fd;

  // libevent event that indicates the statsd socket is ready for writing.
  // We have to manage this explicitly via event_add and event_del to avoid
  // constant firing of events when there are no datagrams to actually write.
  struct event * write_event;
  
  // DNS resolution stuff.
  // TODO: This is sort of duplicated in ConnectionPool so we may want to factor
  // this out into a separate DNSResolver object or something.
  struct sockaddr_in remote_address;
  time_t last_successful_dns_resolution_at;  // If nonzero, then last successful DNS resolution time.

  // Time at which stats were last sent to statsd.  Zero if stats have never been sent.
  time_t stats_last_sent_at;

  // Datagram buffer linked list.
  struct Datagram {
    int length;
    uint8_t * data;
    Datagram * next;
  };
  Datagram * datagram_buffer_head, * datagram_buffer_tail;

public:
  StatsdInterface();

  void setup_for_libevent();
  bool is_ready_to_send() const;
  void buffer_datagram(const uint8_t * data, size_t length);
  void send_buffered_datagrams();
  void start_getaddrinfo_request();
  void send_current_stats_to_statsd();

  void send_integer_metric(const char * metric_namespace, const char * metric_name,
                           uint64_t value, const char * metric_type);
  void send_double_metric(const char * metric_namespace, const char * metric_name,
                          double value, const char * metric_type);
  void send_metric(const char * metric_namespace, const char * metric_name,
                   const char * value, const char * metric_type);
};
