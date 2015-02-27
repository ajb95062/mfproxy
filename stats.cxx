

#include "main.h"


// Libevent callbacks for the statsd interface.
static void statsd_evdns_callback(int errcode, struct evutil_addrinfo * addr, void * context);
static void statsd_timer_event_callback(evutil_socket_t fd, short event_type, void * context);
static void statsd_write_event_callback(evutil_socket_t fd, short event_type, void * context);



// Start a new stat collection interval.  Subclasses extend this to clear out their
// existing collected data.
void StatsCollector::start() {
  gettimeofday(&interval_start, 0);
}


void StatsCollector::stop() {
  struct timeval diff;
  gettimeofday(&interval_end, 0);
  timeval_subtract(&diff, &interval_end, &interval_start);
  elapsed_seconds = timeval_seconds(&diff);
  if(elapsed_seconds <= 0.000001)
    elapsed_seconds = 0.000001;  // avoid division by zero in pathological cases
}


void ClientStatsCollector::start() {
  StatsCollector::start();

  connections_accepted = 0;
  connections_closed = 0;
  bytes_read_from_clients = 0;
  bytes_sent_to_clients = 0;
}


void ClientStatsCollector::send_to_statsd(StatsdInterface * interface) {
  interface->send_integer_metric("clients", "connections_accepted", connections_accepted, "c");
  interface->send_integer_metric("clients", "connections_closed", connections_closed, "c");
  interface->send_integer_metric("clients", "bytes_read_from_clients", bytes_read_from_clients, "c");
  interface->send_integer_metric("clients", "bytes_sent_to_clients", bytes_sent_to_clients, "c");

  // Gauges
  interface->send_integer_metric("clients", "current_connected_clients", current_server->client_connections_count, "g");
}


AllocationStats::AllocationStats() {
  packets = 0;
  packet_data_links = 0;
  client_connections = 0;
  database_connections = 0;
  encoder_buffer_chunks = 0;
  pending_lease_requests = 0;
  packet_data_bytes = 0;
  string_data_bytes = 0;
}


void AllocationStats::send_to_statsd(StatsdInterface * interface) {
  // NOTE: These are all gauges, not counters.
  interface->send_integer_metric("memory", "packets", packets, "g");
  interface->send_integer_metric("memory", "packet_data_links", packet_data_links, "g");
  interface->send_integer_metric("memory", "client_connections", client_connections, "g");
  interface->send_integer_metric("memory", "database_connections", database_connections, "g");
  interface->send_integer_metric("memory", "encoder_buffer_chunks", encoder_buffer_chunks, "g");
  interface->send_integer_metric("memory", "pending_lease_requests", pending_lease_requests, "g");
  interface->send_integer_metric("memory", "packet_data_bytes", packet_data_bytes, "g");
  interface->send_integer_metric("memory", "string_data_bytes", string_data_bytes, "g");
}


void PoolStatsCollector::start() {
  StatsCollector::start();

  database_connections_established = 0;
  database_connections_closed = 0;
  queries_processed = 0;
  transactions_completed = 0;
  total_query_time = 0.0;
  lease_wait_time = 0.0;
  database_wait_time = 0.0;
  query_result_read_time = 0.0;
  bytes_read_from_databases = 0;
  bytes_sent_to_databases = 0;
}


void PoolStatsCollector::send_to_statsd(StatsdInterface * interface) {
  char metric_namespace[250];
  snprintf(metric_namespace, sizeof(metric_namespace),
           "pools.%s", pool->config->apparent_database_name);

  interface->send_integer_metric(metric_namespace, "database_connections_established", database_connections_established, "c");
  interface->send_integer_metric(metric_namespace, "database_connections_closed", database_connections_closed, "c");
  interface->send_integer_metric(metric_namespace, "queries_processed", queries_processed, "c");
  interface->send_integer_metric(metric_namespace, "transactions_completed", transactions_completed, "c");
  interface->send_double_metric(metric_namespace, "total_query_time", total_query_time, "c");
  interface->send_double_metric(metric_namespace, "lease_wait_time", lease_wait_time, "c");
  interface->send_double_metric(metric_namespace, "database_wait_time", database_wait_time, "c");
  interface->send_double_metric(metric_namespace, "query_result_read_time", query_result_read_time, "c");
  interface->send_integer_metric(metric_namespace, "bytes_read_from_databases", bytes_read_from_databases, "c");
  interface->send_integer_metric(metric_namespace, "bytes_sent_to_databases", bytes_sent_to_databases, "c");

  // Send derived average timing gauges.
  if(queries_processed > 0) {
    interface->send_double_metric(metric_namespace, "average_query_time", total_query_time / (double)queries_processed, "g");
    interface->send_double_metric(metric_namespace, "average_lease_wait_time", lease_wait_time / (double)queries_processed, "g");
    interface->send_double_metric(metric_namespace, "average_database_wait_time", database_wait_time / (double)queries_processed, "g");
    interface->send_double_metric(metric_namespace, "average_query_result_read_time", query_result_read_time / (double)queries_processed, "g");
  }

  // Count how many live DB connections we have in the different states.
  int established_connections_count = 0, in_use_connections_count = 0;
  pool->count_established_connections(&established_connections_count, &in_use_connections_count);
  interface->send_integer_metric(metric_namespace, "current_established_connections", established_connections_count, "c");
  interface->send_integer_metric(metric_namespace, "current_leased_connections", in_use_connections_count, "c");
}


void PoolStatsCollector::add_stats(const PoolStatsCollector * stats) {
  database_connections_established += stats->database_connections_established;
  database_connections_closed += stats->database_connections_closed;
  queries_processed += stats->queries_processed;
  transactions_completed += stats->transactions_completed;
  total_query_time += stats->total_query_time;
  lease_wait_time += stats->lease_wait_time;
  database_wait_time += stats->database_wait_time;
  query_result_read_time += stats->query_result_read_time;
  bytes_read_from_databases += stats->bytes_read_from_databases;
  bytes_sent_to_databases += stats->bytes_sent_to_databases;
}


StatsdInterface::StatsdInterface() {
  socket_fd = -1;
  last_successful_dns_resolution_at = 0;
  stats_last_sent_at = 0;
  datagram_buffer_head = datagram_buffer_tail = 0;
}


// Create the UDP socket and set up libevent event handlers.
void StatsdInterface::setup_for_libevent() {
  struct event * event;
  struct timeval tv;
  
  socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(socket_fd < 0) {
    log_error_message("socket() failed during statsd interface initialization: %s", strerror(errno));
    return;
  }
  evutil_make_socket_nonblocking(socket_fd);

  // Persistent event to periodically send stats to statsd.
  // This event also initiates statsd hostname DNS lookups as needed.
  event = event_new(current_server->event_base, -1, EV_PERSIST, statsd_timer_event_callback, this);
  tv.tv_sec = global_config->statsd_send_interval; tv.tv_usec = 0;
  evtimer_add(event, &tv);

  // Event that fires when the statsd socket becomes available for writing.
  write_event = event_new(current_server->event_base, socket_fd, EV_WRITE | EV_PERSIST,
                          statsd_write_event_callback, this);
  event_add(write_event, 0);

  // Explicitly kick off the DNS resolution so that we don't have to wait for the timer event to fire
  // on startup.
  start_getaddrinfo_request();
}


// Determine if everything is set up to send a datagram to statsd.
bool StatsdInterface::is_ready_to_send() const {
  if(socket_fd < 0)
    return false;  // socket not configured yet

  if(last_successful_dns_resolution_at == 0)
    return false;  // DNS not resolved yet

  return true;
}


// Buffer a datagram for sending.  Since we tend to send datagrams in clusters,
// callers should explicitly call send_buffered_datagrams() after sending a cluster
// of datagrams - this buffer_datagram() routine itself only buffers the data.
// NOTE: An internal copy is made of the *data buffer.
void StatsdInterface::buffer_datagram(const uint8_t * data, size_t length) {
  // Don't buffer any data until we are set up to actually start sending stuff.
  // This avoids the possibility of accumulating huge datagram buffers when we are
  // unable to resolve the statsd server IP for long periods of time.
  if(!is_ready_to_send())
    return;
  
  Datagram * datagram = new Datagram;
  datagram->length = length;
  datagram->data = new uint8_t[length];
  memcpy(datagram->data, data, length);

  // Add it to the end of the linked list to implement a FIFO queue.
  datagram->next = 0;
  if(datagram_buffer_tail) {
    datagram_buffer_tail->next = datagram;
    datagram_buffer_tail = datagram;
  }
  else {
    datagram_buffer_head = datagram;
    datagram_buffer_tail = datagram;
  }

  // Allow the socket's write event to trigger, so that we can start writing
  // datagrams as soon as possible.
  event_add(write_event, 0);
}


// Write as many buffered datagrams as we can until we either run out or start
// getting EAGAIN "errors" (indicating that the socket's write buffer is full).
void StatsdInterface::send_buffered_datagrams() {
  while(datagram_buffer_head && is_ready_to_send()) {
    Datagram * d = datagram_buffer_head;
    if(sendto(socket_fd, d->data, d->length, 0x0,
              (struct sockaddr *)&remote_address, sizeof(remote_address)) < 0) {
      if(errno == EAGAIN) {
        // Socket write buffer is full; sendto() would block.
        // Stop processing further datagrams for now until we get another write event.
        return;
      }
      else
        log_error_message("Error sending datagram to statsd: %s", strerror(errno));
    }
    datagram_buffer_head = d->next;
    if(!datagram_buffer_head)
      datagram_buffer_tail = 0;
    delete [] d->data;
    delete d;
  }

  // All data has been sent; deactivate the socket's write event so that
  // it doesn't keep firing.  It'll be reactivated when more datagrams are
  // buffered for output.
  event_del(write_event);
}


// TODO: This duplicates logic in ConnectionPool::start_getaddrinfo_request_if_needed()
void StatsdInterface::start_getaddrinfo_request() {
  struct evdns_getaddrinfo_request * getaddrinfo_request;
  struct evutil_addrinfo hints;
  const char * hostname = global_config->statsd_hostname;
  int port = global_config->statsd_port;
  char port_buf[100];

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = EVUTIL_AI_CANONNAME;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  snprintf(port_buf, sizeof(port_buf), "%d", port);

  getaddrinfo_request =
    evdns_getaddrinfo(current_server->evdns_base, hostname,
                      port_buf, &hints, statsd_evdns_callback, this);
  if(!getaddrinfo_request) {
    // DNS was available immediately.  Callback function has already been invoked.
    log_debug_message("DNS resolution of statsd host \"%s\" returned immediately", hostname);
  }
  else
    log_debug_message("Started DNS resolution of \"%s\" for statsd host.", hostname);
}


void StatsdInterface::send_current_stats_to_statsd() {
  stats_last_sent_at = time(0);
  current_server->send_stats_to_statsd(this);
}


void StatsdInterface::send_integer_metric(const char * metric_namespace, const char * metric_name,
                                          uint64_t value, const char * metric_type) {
  char buf[50];
  snprintf(buf, sizeof(buf), "%ld", (long)value);
  send_metric(metric_namespace, metric_name, buf, metric_type);
}


void StatsdInterface::send_double_metric(const char * metric_namespace, const char * metric_name,
                                         double value, const char * metric_type) {
  char buf[50];
  snprintf(buf, sizeof(buf), "%f", value);
  send_metric(metric_namespace, metric_name, buf, metric_type);
}


// If metric_namespace is provided (non-null), it's inserted before the overall statsd key prefix
// and the actual metric name.
void StatsdInterface::send_metric(const char * metric_namespace, const char * metric_name,
                                  const char * value, const char * metric_type) {
  char buf[500];
  snprintf(buf, sizeof(buf), "%s%s%s%s%s:%s|%s",
           global_config->statsd_key_prefix,
           global_config->statsd_key_prefix[0] ? "." : "",
           metric_namespace ? metric_namespace : "",
           metric_namespace ? "." : "",
           metric_name,
           value,
           metric_type);
  buffer_datagram((const uint8_t *)buf, strlen(buf));
}


// Callback for nonblocking DNS resolution.
static void statsd_evdns_callback(int errcode, struct evutil_addrinfo * addr, void * context) {
  StatsdInterface * interface = (StatsdInterface *)context;
  
  if(errcode)
    log_error_message("Error resolving statsd hostname \"%s\": %s",
                      global_config->statsd_hostname, strerror(errcode));
  else {
    struct sockaddr_in * sa = (struct sockaddr_in *)addr->ai_addr;
    char inet_buf[100];
    evutil_inet_ntop(AF_INET, &sa->sin_addr, inet_buf, sizeof(inet_buf));
    log_debug_message("Resolved statsd hostname \"%s\" to IP address: %s",
                      global_config->statsd_hostname, inet_buf);
    interface->remote_address = *sa;
    interface->last_successful_dns_resolution_at = time(0);
  }
  if(addr)
    evutil_freeaddrinfo(addr);
}


static void statsd_timer_event_callback(evutil_socket_t fd, short event_type, void * context) {
  StatsdInterface * interface = (StatsdInterface *)context;

  // Start DNS resolution if needed.
  if(interface->last_successful_dns_resolution_at == 0 &&
     time(0) - interface->last_successful_dns_resolution_at > global_config->dns_cache_time)
    interface->start_getaddrinfo_request();

  // Send the stats payload to statsd if it's time.
  if(time(0) - interface->stats_last_sent_at > global_config->statsd_send_interval)
    interface->send_current_stats_to_statsd();
}


// The statsd socket is becoming available for writing.
static void statsd_write_event_callback(evutil_socket_t fd, short event_type, void * context) {
  StatsdInterface * interface = (StatsdInterface *)context;
  interface->send_buffered_datagrams();
}

