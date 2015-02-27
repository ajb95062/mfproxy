

// Connection pool and connection lease management stuff.


// Each ConnectionPool has a linked list of these, which represent client connections
// who are waiting for a database lease to become available in the pool.
class PendingLeaseRequest {
public:
  ClientConnection * client_connection;

  // The packet that triggered the pending lease request.  This will be executed
  // immediately once we actually acquire a connection lease.
  Packet * pending_packet;

  time_t requested_at_time;
  PendingLeaseRequest * next;

public:
  PendingLeaseRequest();
  ~PendingLeaseRequest();

  void handle_pending_packet();
};


// represents a pool of connections to a single database backend
class ConnectionPool {
public:
  int pool_size;  // Same as config->connection_pool_size.
  const DatabaseBackendConfig * config;
  DatabaseConnection ** connections;
  PendingLeaseRequest * pending_lease_requests_head, * pending_lease_requests_tail;

  // If non-null, this is the current pending nonblocking DNS lookup request
  // for this database backend.
  struct evdns_getaddrinfo_request * getaddrinfo_request;
  struct sockaddr_in remote_address;
  time_t last_successful_dns_resolution_at;  // If nonzero, then last successful DNS resolution time.

  // Runtime stats for things related to this connection pool.
  PoolStatsCollector stats;

public:
  ConnectionPool(const DatabaseBackendConfig * new_config);

  // Event handling:
  bool start_establishing_one_database_connection_if_needed();
  void perform_periodic_connection_maintenance();

  // Utility:
  void count_established_connections(int * established_connections, int * in_use_connections) const;

  // DNS:
  void start_getaddrinfo_request_if_needed();
  bool dns_resolution_in_progress() const { return getaddrinfo_request != 0; }
  void start_connecting_connections_that_were_waiting_on_dns();
  void handle_unsuccessful_dns_resolution(int errcode);
  void invalidate_dns_cache() { last_successful_dns_resolution_at = 0; }

  // Connection lease management methods:
  DatabaseConnection * find_connection_to_lease_for_client(const ClientConnection * client_connection) const;
  DatabaseConnection * lease_connection_for_client(ClientConnection * client_connection);
  void release_leased_connection(DatabaseConnection * leased_connection);
  void add_pending_lease_request(ClientConnection * client_connection, Packet * originating_packet);
  PendingLeaseRequest * find_pending_lease_request(const ClientConnection * client_connection) const;
  void cancel_pending_lease_requests_for_client_connection(ClientConnection * client_connection);
  void check_pending_lease_requests();
  void randomly_suspend_or_unsuspend_connections();
};


