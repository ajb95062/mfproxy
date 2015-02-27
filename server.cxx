

#include "main.h"


Server * current_server = 0;


// libevent callbacks
static void periodic_connection_maintenance_callback(evutil_socket_t fd, short event_type, void * context);
static void randomly_suspend_or_unsuspend_connections_callback(evutil_socket_t fd, short event_type, void * context);
static void accept_callback(struct evconnlistener * listener, evutil_socket_t connection_fd,
                            struct sockaddr * address, int socklen, void * context);
static void accept_error_callback(struct evconnlistener * listener, void * context);
static void clean_shutdown_timeout_callback(evutil_socket_t fd, short event_type, void * context);
static void staggered_db_connect_callback(evutil_socket_t fd, short event_type, void * context);
static void sigterm_event_callback(evutil_socket_t fd, short event_type, void * context);
static void sighup_event_callback(evutil_socket_t fd, short event_type, void * context);


// MySQL capability flags (CF_CLIENT_*) to present to connecting clients, and to
// request from backend databases.
// TODO: add CF_CLIENT_COMPRESS here once we support packet compression.
// TODO: add CF_CLIENT_LOCAL_FILES here once we support LOAD DATA INFILE.
uint32_t Server::default_capability_flags() {
  // NOTE: CF_CLIENT_NO_SCHEMA seems to mess up things like SHOW TABLES, so don't use that
  // flag even though the DB engine advertises that as available.
  return (CF_CLIENT_LONG_PASSWORD | CF_CLIENT_FOUND_ROWS | CF_CLIENT_LONG_FLAG | CF_CLIENT_CONNECT_WITH_DB |
          CF_CLIENT_ODBC | CF_CLIENT_IGNORE_SPACE | CF_CLIENT_PROTOCOL_41 |
          CF_CLIENT_INTERACTIVE | CF_CLIENT_IGNORE_SIGPIPE | CF_CLIENT_TRANSACTIONS | CF_CLIENT_RESERVED |
          CF_CLIENT_SECURE_CONNECTION | CF_CLIENT_MULTI_STATEMENTS | CF_CLIENT_MULTI_RESULTS | CF_CLIENT_PS_MULTI_RESULTS |
          CF_CLIENT_PLUGIN_AUTH);
}


Server::Server() {
  event_base = 0;
  evdns_base = 0;
  listen_fd = -1;
  listener = 0;
  db_connect_timer_event = 0;
  db_connect_timer_in_progress = false;
  
  logfile = 0;
  run_state = SERVER_RUN_STATE_STARTING_UP;
  next_connection_id = 1;
  client_connections_head = 0;
  client_connections_count = 0;

  statsd_interface = 0;
}


void Server::startup() {
  startup_time = time(0);
  lifetime_db_stats.start();
  create_connection_pools();
  check_limits();
  open_logfile();

  // Set up libevent stuff.
  struct event * event;
  struct timeval tv;

  event_base = event_base_new();

  // Set up evdns (libevent nonblocking DNS), if configured.
  if(global_config->use_nonblocking_dns) {
    evdns_base = evdns_base_new(event_base, 1);
    if(!evdns_base)
      panic("Could not initialize evdns (try setting use_nonblocking_dns to false in the config file)");
  }

  // Persistent event to randomly suspend or unsuspend DB connections (for load testing), if configured.
  // TODO: roll this into periodic_connection_maintenance_callback()
  if(global_config->simulate_busy_dbs) {
    event = event_new(event_base, -1, EV_PERSIST, randomly_suspend_or_unsuspend_connections_callback, this);
    tv.tv_sec = 2; tv.tv_usec = 0;
    evtimer_add(event, &tv);
  }
  
  // Persistent event to handle time-based connection events that are decoupled from
  // the main event loop (such as query timeouts and reconnecting dead database connections).
  event = event_new(event_base, -1, EV_PERSIST, periodic_connection_maintenance_callback, this);
  tv.tv_sec = 1; tv.tv_usec = 0;
  evtimer_add(event, &tv);

  // Timer-based event to connect to backend databases in a staggered manner,
  // so that we don't try to make all the connections at once.  We don't activate
  // it immediately though.  Instead, we'll start by explicitly establishing
  // one (arbitrary) database connection, and then when that completes it will
  // schedule an invocation of this timer event for the future (and so on).
  db_connect_timer_event = evtimer_new(event_base, staggered_db_connect_callback, this);

  // Initialize stats collectors.
  current_server->start_stats_collectors();

  // Set up statsd interface if configured.
  if(global_config->statsd_hostname) {
    statsd_interface = new StatsdInterface;
    statsd_interface->setup_for_libevent();
  }

  // Hook up signal handlers.
  // TODO: separate TERM and INT here, maybe
  event_add(evsignal_new(event_base, SIGTERM, sigterm_event_callback, this), 0);
  event_add(evsignal_new(event_base, SIGINT, sigterm_event_callback, this), 0);
  event_add(evsignal_new(event_base, SIGHUP, sighup_event_callback, this), 0);

  // Enter startup run mode.
  run_state = SERVER_RUN_STATE_ACTIVE;

  // Kick off the first connection to one of the backend databases.
  // This will start the sequence (via db_connect_timer_event) of connecting
  // to ALL the backend databases in a staggered manner.  This avoids swamping
  // MySQL's listen() queue with a ton of simultaneous connections.
  current_server->start_establishing_one_database_connection_if_needed();

  // Listen for client connections.
  setup_listener(global_config->listen_on_port);

  // Done setting up libevent; enter runloop.
  event_base_loop(event_base, 0);
}


// Check OS-dependent limitations before startup and issue warnings/errors
// if anything looks problematic.  Currently this just checks for file descriptor
// limits that may put a hard limit on how many network connections we can have
// at once.
void Server::check_limits() {
  // Estimate the number of network sockets we'll need at max capacity.
  // This includes:
  //   - max_clients limit
  //   - total number of backend database connections across all pools
  //   - a few extra file descriptors for random overhead
  int fd_needed = 20;  // 20=overhead
  if(global_config->max_clients > 0)
    fd_needed += global_config->max_clients;
  loopi(connection_pool_count)
    fd_needed += connection_pools[i]->config->connection_pool_size;

  // Check the current FD limits and issue a warning if it's too low.
  struct rlimit limit;
  if(getrlimit(RLIMIT_NOFILE, &limit) != 0)
    log_error_message("Could not determine the current file descriptor limit with rlimit().  Skipping the check.");
  else if(limit.rlim_cur < (rlim_t)fd_needed)
    log_error_message("Warning: file descriptor limit (currently %d) is too low (we need %d).  Consider increasing it with \"ulimit -n %d\".",
                      (int)limit.rlim_cur, (int)fd_needed, (int)fd_needed);
  log_debug_message("Current file descriptor limit is %d; max is %d.", (int)limit.rlim_cur, (int)limit.rlim_max);
}


void Server::open_logfile() {
  if(global_config->use_syslog)
    openlog(global_config->syslog_ident, LOG_NDELAY, LOG_DAEMON);
  else {
    if(global_config->logfile_name) {
      if(!(logfile = fopen(global_config->logfile_name, "a")))
        panic("Could not open logfile \"%s\" for writing.", global_config->logfile_name);
    }
    else
      logfile = stdout;
    setlinebuf(logfile);  // make sure logfile is flushed every line
  }
}


void Server::close_logfile() {
  if(!(logfile == 0 || logfile == stdout || logfile == stderr)) {
    fclose(logfile);
    logfile = 0;
  }
  if(global_config->use_syslog)
    closelog();
}


void Server::start_stats_collectors() {
  client_stats.start();
  loopi(connection_pool_count)
    connection_pools[i]->stats.start();
}


void Server::send_stats_to_statsd(StatsdInterface * interface) {
  client_stats.stop();
  loopi(connection_pool_count)
    connection_pools[i]->stats.stop();
  
  client_stats.send_to_statsd(interface);
  loopi(connection_pool_count) {
    lifetime_db_stats.add_stats(&connection_pools[i]->stats);
    connection_pools[i]->stats.send_to_statsd(interface);
  }
  allocation_stats.send_to_statsd(interface);

  interface->send_buffered_datagrams();

  start_stats_collectors();
}


// TODO: if we can get a portable way to set the procline, this can be used to show some
// important stats in an easy-to-see way.
#if 0
void Server::update_proctitle() {
  int established_connections_count, in_use_connections_count;
  int total_established_connections_count = 0, total_in_use_connections_count = 0, max_connections_count = 0;

  loopi(connection_pool_count) {
    connection_pools[i]->count_established_connections(&established_connections_count, &in_use_connections_count);
    total_established_connections_count += established_connections_count;
    total_in_use_connections_count += in_use_connections_count;
    max_connections_count += connection_pools[i]->pool_size;
  }
  
  char buf[250];
  snprintf(buf, sizeof(buf), "%s [clients: %d, dbs: %d/%d (%d in use), queries: %ld]",
           (program_name ? program_name : "proxy"),
           (int)client_connections_count,
           total_established_connections_count, max_connections_count,
           total_in_use_connections_count,
           (long)lifetime_db_stats.queries_processed);

  setproctitle(buf);
}
#endif


// Start a clean shutdown.  This is a multi-step process that tries to avoid
// interrupting in-progress queries and transactions.
void Server::start_clean_shutdown_process() {
  if(run_state != SERVER_RUN_STATE_ACTIVE) {
    log_message("Clean shutdown is already in progress.  Ignoring further clean shutdown requests.");
    return;
  }

  // If configured, add a timer event that will perform a hard exit if too much time is taken by
  // the clean-shutdown process.
  if(global_config->clean_shutdown_timeout >= 0) {
    struct timeval tv;
    tv.tv_sec = global_config->clean_shutdown_timeout;
    tv.tv_usec = 0;
    evtimer_add(evtimer_new(event_base, clean_shutdown_timeout_callback, this), &tv);
  }
  
  log_message("Clean shutdown requested.  Waiting for in-progress queries and transactions to finish.");
  
  // Stop accepting new client connections.
  evconnlistener_free(listener);

  // Enter SHUTDOWN_REQUESTED state.  If there are currently no in-progress client
  // queries or transactions, we can continue immediately to the second phase of
  // shutting down (i.e., closing the database connections).  Otherwise, we continue
  // operating as normal, but ConnectionPool::release_leased_connection knows to look
  // for this state and will call continue_shutdown_process() itself once ready.
  run_state = SERVER_RUN_STATE_SHUTDOWN_REQUESTED;
  if(can_continue_shutting_down_cleanly())
    continue_clean_shutdown_process();
}


// Determine if all in-progress client queries and/or transactions have finished,
// so that we can start shuting down the proxy process without interrupting anything.
// Once we are able to start shutting down cleanly, we'll send QUIT packets to all
// the backend database connections and wait for them to close from their end.
bool Server::can_continue_shutting_down_cleanly() const {
  if(run_state != SERVER_RUN_STATE_SHUTDOWN_REQUESTED)
    return false;
  
  // Scan each client connection; if any have an active database connection
  // lease then we're not ready to exit yet.
  for(ClientConnection * c = client_connections_head; c; c = c->next_connection)
    if(c->currently_leased_database_connection)
      return false;
  return true;
}


// All client connections have finished their in-progress queries and transactions.
// We can close the clients' network sockets and start cleanly closing the backend
// database connections by sending them QUIT packets.
void Server::continue_clean_shutdown_process() {
  log_message("Clean shutdown second phase entered.  Sending QUIT to database connections.");
  
  // Close all client connections.
  while(client_connections_head)
    client_connections_head->close();
  
  // Send QUIT packets to all backend databases.  We'll then transition into
  // SERVER_RUN_STATE_SHUTTING_DOWN to indicate that we are waiting for the
  // database connections to close their sockets in response to the QUIT.
  loopi(connection_pool_count) {
    ConnectionPool * p = connection_pools[i];
    loopj(p->pool_size) {
      DatabaseConnection * d = p->connections[j];
      if(d->state == CONNECTION_STATE_READY)
        d->send_quit_packet();
    }
  }
  run_state = SERVER_RUN_STATE_SHUTTING_DOWN;

  // Check if we can finish shutting down immediately (e.g., if all database connections
  // already closed by chance).  Otherwise, the database connection closing logic will check
  // for this case and tell us.
  if(can_finish_shutting_down_cleanly())
    finish_clean_shutdown_process();
}


// Second phase of clean-shutdown.  We are in the SHUTTING_DOWN run-state and have sent
// QUIT packets to all the backend database connections and are waiting for the databases
// to close the network connections from their end.  Once all the database connections
// are closed we can finally exit the process cleanly.
bool Server::can_finish_shutting_down_cleanly() const {
  if(run_state != SERVER_RUN_STATE_SHUTTING_DOWN)
    return false;
  
  loopi(connection_pool_count) {
    ConnectionPool * p = connection_pools[i];
    loopj(p->pool_size) {
      DatabaseConnection * d = p->connections[j];
      if(d->state != CONNECTION_STATE_UNCONNECTED)
        return false;  // At least one DB connection is still active.
    }
  }
  return true;
}


// Everything has been cleanly shut down and we can finally exit.
void Server::finish_clean_shutdown_process() {
  log_message("Clean shutdown complete.  Proxy process is exiting.");
  close_logfile();
  exit(0);
}


void Server::create_connection_pools() {
  DatabaseBackendConfig * db_config;
  int index;

  connection_pool_count = global_config->database_backend_config_count;
  connection_pools = new ConnectionPool *[connection_pool_count];
  
  for(db_config = global_config->database_backend_config_list, index = 0;
      db_config && index < connection_pool_count;
      db_config = db_config->next, index++)
    connection_pools[index] = new ConnectionPool(db_config);
}


void Server::setup_listener(int port_number) {
  struct sockaddr_in addr;

  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port_number);
  addr.sin_addr.s_addr = INADDR_ANY;

  // Create the listener socket and set it to be nonblocking.
  listener = evconnlistener_new_bind(event_base, accept_callback, this,
                                     LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
                                     (struct sockaddr *)&addr, sizeof(addr));
  if(!listener) {
    // Couldn't create listening socket; abort.
    perror("bind/listen");
    exit(1);
  }
  evutil_make_socket_nonblocking(evconnlistener_get_fd(listener));
  evconnlistener_set_error_cb(listener, accept_error_callback);
  log_message("Listening on port %d.", port_number);
}


// Start up the staggered database connection timer event, if not already started.
// After the configured 'delay_milliseconds_between_db_connections' has elapsed,
// this event will attempt to establish the next disconnected database connection.
void Server::schedule_database_connect_timer_event() {
  struct timeval tv;
  int delay_ms = global_config->delay_milliseconds_between_db_connections;

  if(db_connect_timer_in_progress)
    return;  // Already scheduled; don't re-add it.

  tv.tv_sec = delay_ms / 1000;
  tv.tv_usec = (delay_ms % 1000) * 1000L;
  evtimer_add(db_connect_timer_event, &tv);
  db_connect_timer_in_progress = true;
}


// Try to find an unconnected database connection.  If there is one, start the
// connection process for it.  Return true if a connection startup was initiated.
bool Server::start_establishing_one_database_connection_if_needed() {
  if(run_state == SERVER_RUN_STATE_SHUTTING_DOWN)
    return false;
    
  loopi(connection_pool_count)
    if(connection_pools[i]->start_establishing_one_database_connection_if_needed())
      return true;

  return false;
}


void Server::perform_periodic_database_connection_maintenance() {
  loopi(connection_pool_count)
    connection_pools[i]->perform_periodic_connection_maintenance();
  schedule_database_connect_timer_event();
}


void Server::randomly_suspend_or_unsuspend_connections() {
  loopi(connection_pool_count)
    connection_pools[i]->randomly_suspend_or_unsuspend_connections();
}


ConnectionPool * Server::find_connection_pool_with_apparent_database_name(const char * database_name) const {
  loopi(connection_pool_count)
    if(strcmp(connection_pools[i]->config->apparent_database_name, database_name) == 0)
      return connection_pools[i];
  return 0;
}


// This is the connection pool used for new client connections by default, until the connection
// selects a database explicitly in the initial handshake, or via an InitDB packet.
ConnectionPool * Server::default_connection_pool() const {
  ConnectionPool * p = find_connection_pool_with_apparent_database_name(global_config->default_apparent_database_name);
  if(!p)
    panic("default_apparent_database_name \"%s\" does not match any configured backends.",
          global_config->default_apparent_database_name);
  return p;
}


void Server::add_client_connection(ClientConnection * connection) {
  // Add connection to the beginning of the doubly linked list.
  connection->next_connection = client_connections_head;
  connection->prev_connection = 0;
  if(client_connections_head)
    client_connections_head->prev_connection = connection;
  client_connections_head = connection;
  client_connections_count++;
}


// NOTE: this doesn't actually delete the connection, it only removes it from the connection list.
void Server::remove_client_connection(ClientConnection * connection) {
  // Delete connection from the doubly linked list.
  if(connection->prev_connection)
    connection->prev_connection->next_connection = connection->next_connection;
  else
    client_connections_head = connection->next_connection;
  if(connection->next_connection)
    connection->next_connection->prev_connection = connection->prev_connection;
  connection->next_connection = connection->prev_connection = 0;
  client_connections_count--;
}


// Every few seconds, try to (re)connect to databases that are in the UNCONNECTED state.
static void periodic_connection_maintenance_callback(evutil_socket_t fd, short event_type, void * context) {
  Server * server = (Server *)context;
  server->perform_periodic_database_connection_maintenance();
}


// TODO: roll this into perform_periodic_database_connection_maintenance
static void randomly_suspend_or_unsuspend_connections_callback(evutil_socket_t fd, short event_type, void * context) {
  Server * server = (Server *)context;
  server->randomly_suspend_or_unsuspend_connections();
}


// A new client connection has been successfully accepted.
static void accept_callback(struct evconnlistener * listener, evutil_socket_t connection_fd,
                            struct sockaddr * address, int socklen, void * context) {
  Server * server = (Server *)context;

  // Initialize connection state structure.
  ClientConnection * connection = new ClientConnection;
  connection->socket_fd = connection_fd;
  connection->remote_address = *(struct sockaddr_in *)address;
  connection->connection_id = server->next_connection_id++;

  // Link connection into the global list of current connections.
  server->add_client_connection(connection);

  // Set up bufferevent stuff.
  connection->connection_established();

  // Make sure we have not hit the client connection limit (if configured).
  if(global_config->max_clients > 0 &&
     server->client_connections_count > global_config->max_clients) {
    // Too many connections.  The client connection has already been accepted; we have to
    // send the client an error packet and then flag it as close_when_output_finishes.
    // This is what the MySQL server itself does when there are too many connections.
    connection->send_error_packet("Too many connections", "08004", 0);
    connection->close_when_output_finishes = true;
    log_message("Aborting new client connection because max_clients limit has been exceeded.");
    return;
  }
  else {
    // We're under the max connection limit, so start the handshake process.
    connection->send_initial_handshake_packet();
  }
}


static void accept_error_callback(struct evconnlistener * listener, void * context) {
  int err = EVUTIL_SOCKET_ERROR();
  log_error_message("Error accepting new connection: %s", evutil_socket_error_to_string(err));
}


static void clean_shutdown_timeout_callback(evutil_socket_t fd, short event_type, void * context) {
  log_error_message("Clean shutdown process is taking too long to complete; performing a hard exit.");
  exit(1);
}


static void staggered_db_connect_callback(evutil_socket_t fd, short event_type, void * context) {
  Server * server = (Server *)context;
  server->db_connect_timer_in_progress = false;
  server->start_establishing_one_database_connection_if_needed();
}


static void sigterm_event_callback(evutil_socket_t fd, short event_type, void * context) {
  Server * server = (Server *)context;
  log_message("SIGTERM / SIGINT received.");
  server->start_clean_shutdown_process();
}


// Ignore SIGHUP for convenience (so that you can start the proxy from a terminal shell
// and then logout easily).
static void sighup_event_callback(evutil_socket_t fd, short event_type, void * context) {
  log_message("SIGHUP received - ignoring.");
}

