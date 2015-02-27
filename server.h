

// The Server singleton (global variable current_server) holds the overall state of
// the proxy server including the various network connections.


enum ServerRunState {
  // Initial state, before we are accepting connections from clients.
  SERVER_RUN_STATE_STARTING_UP = 0,

  // Normal active run state.  
  SERVER_RUN_STATE_ACTIVE,

  // A clean shutdown has been requested (via an OS signal or other mechanism).
  // Once all in-progress client transactions have finished, we'll start the clean
  // shutdown process.
  SERVER_RUN_STATE_SHUTDOWN_REQUESTED,

  // We have initiated the clean shutdown process by closing all client connections
  // and sending QUIT packets to the database backend connections.  We are now waiting
  // on the databases to close the connection sockets from their end.  As soon as they
  // do, the proxy process will exit.
  SERVER_RUN_STATE_SHUTTING_DOWN
};


class Server {
public:
  // libevent stuff
  struct event_base * event_base;
  struct evdns_base * evdns_base;  // for nonblocking DNS lookups
  evutil_socket_t listen_fd;  // socket that accepts new connections
  struct evconnlistener * listener;  // libevent connection listener object
  struct event * db_connect_timer_event;  // timer-based event to perform staggered DB connections
  bool db_connect_timer_in_progress;  // whether or not db_connect_timer_event is enabled

  ServerRunState run_state;
  time_t startup_time;
  FILE * logfile;

  // Configured connection pools.
  int connection_pool_count;
  ConnectionPool ** connection_pools;

  // Next connection ID we'll hand out to a connecting client.
  uint32_t next_connection_id;

  // Doubly linked list of current client connections.
  ClientConnection * client_connections_head;
  int client_connections_count;  // Running tally, so that we don't have to iterate the list to count connections.

  PoolStatsCollector lifetime_db_stats;
  ClientStatsCollector client_stats;
  AllocationStats allocation_stats;
  StatsdInterface * statsd_interface;

public:
  static uint32_t default_capability_flags();

public:
  // Lifecycle methods:
  Server();
  void startup();
  void check_limits();
  void open_logfile();
  void close_logfile();

  // Stats support:
  void start_stats_collectors();
  void send_stats_to_statsd(StatsdInterface * interface);
  // void update_proctitle();

  // Clean-shutdown support:
  void start_clean_shutdown_process();
  bool can_continue_shutting_down_cleanly() const;
  void continue_clean_shutdown_process();
  bool can_finish_shutting_down_cleanly() const;
  void finish_clean_shutdown_process();

  // Initialization:
  void create_connection_pools();
  void setup_listener(int port_number);

  // Connection/network management:
  void schedule_database_connect_timer_event();
  bool start_establishing_one_database_connection_if_needed();
  void perform_periodic_database_connection_maintenance();
  void randomly_suspend_or_unsuspend_connections();
  ConnectionPool * find_connection_pool_with_apparent_database_name(const char * database_name) const;
  ConnectionPool * default_connection_pool() const;
  void start_resolving_dns(const char * hostname, int port, DatabaseConnection * connection);
  void add_client_connection(ClientConnection * connection);
  void remove_client_connection(ClientConnection * connection);
};

  
extern Server * current_server;
