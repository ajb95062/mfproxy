
#include "main.h"


static void evdns_callback(int errcode, struct evutil_addrinfo * addr, void * ptr);


PendingLeaseRequest::PendingLeaseRequest() {
  pending_packet = 0;
  current_server->allocation_stats.pending_lease_requests++;
}


// NOTE: since the PendingLeaseRequest "owns" the pending_packet, it's responsible
// for deleting it in this destructor.
PendingLeaseRequest::~PendingLeaseRequest() {
  if(pending_packet)
    delete pending_packet;
  current_server->allocation_stats.pending_lease_requests--;
}


void PendingLeaseRequest::handle_pending_packet() {
  Packet * packet = pending_packet;
  pending_packet = 0;  // this protects the packet from being deleted by PendingLeaseRequest's destructor
  packet->is_pending = false;  // allow the packet to be subject to deletion once handling is finished
  client_connection->handle_packet(packet);  // this hands off ownership of the packet
}


ConnectionPool::ConnectionPool(const DatabaseBackendConfig * new_config) {
  pool_size = new_config->connection_pool_size;
  config = new_config;
  pending_lease_requests_head = pending_lease_requests_tail = 0;
  getaddrinfo_request = 0;
  last_successful_dns_resolution_at = 0;
  stats.pool = this;

  connections = new DatabaseConnection *[pool_size];
  loopi(pool_size) {
    char buf[1000];
    connections[i] = new DatabaseConnection();
    connections[i]->pool = this;
    connections[i]->connection_index = i;
    snprintf(buf, sizeof(buf), "[db %s; %d of %d]",
             config->apparent_database_name, (int)(i+1), (int)pool_size);
    connections[i]->set_description_string(buf);
  }
}


// TODO: comment this
bool ConnectionPool::start_establishing_one_database_connection_if_needed() {
  // Try to find a connection in this pool that is eligible for startup.
  DatabaseConnection * eligible_connection = 0;
  loopi(pool_size) {
    DatabaseConnection * c = connections[i];

    // If we have an existing connection in the pool that is already in the process
    // of connecting, don't start establishing a new connection.
    if(c->state == CONNECTION_STATE_WAITING_FOR_DNS ||
       c->state == CONNECTION_STATE_CONNECTING ||
       c->state == CONNECTION_STATE_AUTHENTICATING)
      return false;

    // We can probably start up this database connection; still need to complete
    // the loop through the other connections in this pool to make sure none of them
    // are in the process of connecting though.
    if(c->state == CONNECTION_STATE_UNCONNECTED && !eligible_connection)
      eligible_connection = c;
  }

  if(eligible_connection) {
    eligible_connection->start_resolving_dns_for_connect();
    return true;
  }
  else
    return false;
}


void ConnectionPool::perform_periodic_connection_maintenance() {
  // Do maintenance on the individual database connections.
  loopi(pool_size)
    connections[i]->perform_periodic_maintenance();

  // Abort queries from clients that have been waiting on a connection lease
  // in this pool for too long.
  PendingLeaseRequest * p = 0;
  time_t current_time = time(0);
  do {
    for(p = pending_lease_requests_head; p; p = p->next) {
      // Check whether this lease request has timed out.
      if(config->pending_lease_request_timeout > 0 &&
         current_time - p->requested_at_time > config->pending_lease_request_timeout) {
        // This lease request has timed out.  Send the client an Error packet and abort the lease request.
        // TODO: Make this match what really happens on a native mysql timeout event.
        //       For now just doing this seems to be good enough but we probably should send the "correct" error code.
        ClientConnection * c = p->client_connection;
        log_debug_message("Aborting query from %s due to lease request timeout", c->description_string());
        c->send_error_packet("Timed out waiting for connection lease", 0, p->pending_packet->data.sequence_number + 1);
        cancel_pending_lease_requests_for_client_connection(c);  // Caution: this deletes 'p'.  This is why we keep 'c' explicitly here.
        c->start_accepting_input();

        // We aborted a lease request, so break to check the list again from scratch
        // (since an item has been destructively removed from the pending_lease_requests list).
        break;  
      }
    }
  } while(p);  // i.e., while the break was hit above
}


// Fill in *established_connections and *in_use_connections with the appropriate counts.
void ConnectionPool::count_established_connections(int * established_connections, int * in_use_connections) const {
  *established_connections = 0;
  *in_use_connections = 0;
  loopi(pool_size) {
    DatabaseConnection * d = connections[i];
    if(d->lease_state != LEASE_STATE_UNAVAILABLE)
      (*established_connections)++;
    if(d->lease_state == LEASE_STATE_IN_USE)
      (*in_use_connections)++;
  }
}


void ConnectionPool::start_getaddrinfo_request_if_needed() {
  struct evutil_addrinfo hints;
  const char * hostname = config->hostname;
  int port = config->port;
  char port_buf[100];

  // Check the local DNS cache and just use that if it's fresh enough.
  if(last_successful_dns_resolution_at &&
     global_config->dns_cache_time > 0 &&
     time(0) - last_successful_dns_resolution_at <= global_config->dns_cache_time) {
    start_connecting_connections_that_were_waiting_on_dns();
    return;
  }

  if(getaddrinfo_request) {
    // There's already an in-flight DNS lookup in progress.
    // No need to start a new one.
    return;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = EVUTIL_AI_CANONNAME;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  snprintf(port_buf, sizeof(port_buf), "%d", port);

  getaddrinfo_request =
    evdns_getaddrinfo(current_server->evdns_base, hostname,
                      port_buf, &hints, evdns_callback, this);
  if(!getaddrinfo_request) {
    // DNS was available immediately.  Callback function has already been invoked.
    log_debug_message("DNS resolution of \"%s\" (%s pool) returned immediately",
                      hostname, config->apparent_database_name);
  }
  else
    log_debug_message("Started DNS resolution of \"%s\" for %s pool",
                      hostname, config->apparent_database_name);
}


// DNS lookup for this pool has succeeded.  The resolved address has been stored in
// this->remote_address.  For any database connections in this pool that were waiting
// on this result, start nonblocking connect() calls to the resolved address.
void ConnectionPool::start_connecting_connections_that_were_waiting_on_dns() {
  loopi(pool_size) {
    DatabaseConnection * c = connections[i];
    if(c->state == CONNECTION_STATE_WAITING_FOR_DNS) {
      c->remote_address = remote_address;
      c->start_connecting_to_remote_address();
    }
  }
}


// DNS lookup for this pool has failed.  Revert any database connections waiting on this
// result back to the UNCONNECTED state; eventually a timer event will try to start the
// connection (and DNS lookup) process again.
void ConnectionPool::handle_unsuccessful_dns_resolution(int errcode) {
  log_error_message("Unable to resolve database hostname \"%s\" (%s).  Will try again later.",
                    config->hostname, strerror(errcode));
  loopi(pool_size) {
    DatabaseConnection * c = connections[i];
    if(c->state == CONNECTION_STATE_WAITING_FOR_DNS)
      c->state = CONNECTION_STATE_UNCONNECTED;
  }
}


// We need to find a database connection in this pool to lease to the given client.
// Returns null if no connection is available.  This method does not actually change
// anything, it only tries to find an appropriate DB connection.
// TODO: This takes time linear in the number of database connections.  May want to convert
// this to a more efficient data structure (maybe keep an explicit linked list of available connections).
DatabaseConnection * ConnectionPool::find_connection_to_lease_for_client(const ClientConnection * client_connection) const {
  loopi(pool_size) {
    DatabaseConnection * c = connections[i];
    if(c && c->lease_state == LEASE_STATE_AVAILABLE)
      return c;
  }
  return 0;
}


// If possible, set up a connection lease for the client, and return the leased DB connection.
// If there is no available DB connection, return null.
DatabaseConnection * ConnectionPool::lease_connection_for_client(ClientConnection * client_connection) {
  DatabaseConnection * leased_connection = find_connection_to_lease_for_client(client_connection);
  if(leased_connection) {
    leased_connection->leasing_client_connection = client_connection;
    client_connection->currently_leased_database_connection = leased_connection;
    client_connection->lease_acquired_at_time = client_connection->lease_last_activity_time = time(0);
    gettimeofday(&client_connection->query_timings.lease_acquired, 0);
    leased_connection->lease_state = LEASE_STATE_IN_USE;
    return leased_connection;
  }
  else
    return 0;
}


// A client is finished with a leased connection.  Return it back to the pool
// and clean up.  This will also trigger a check for whether any additional
// pending lease requests can now be satisfied.
void ConnectionPool::release_leased_connection(DatabaseConnection * leased_connection) {
  ClientConnection * client_connection = leased_connection->leasing_client_connection;
  leased_connection->leasing_client_connection = 0;
  client_connection->currently_leased_database_connection = 0;
  leased_connection->lease_state = LEASE_STATE_AVAILABLE;

  // Close the backend database connection if it's been open too long.
  leased_connection->close_if_maximum_lifetime_exceeded();
  
  check_pending_lease_requests();

  // If we're in the first phase of clean shutdown (waiting for in-progress client
  // query transactions to finish), this may have been the last client connection we
  // were waiting on.  Check for this case.
  if(current_server->can_continue_shutting_down_cleanly())
    current_server->continue_clean_shutdown_process();
}


// A client wants to execute the given packet but no database connection is immediately
// available.  A pending lease request will be added for this connection+packet combo.
//
// NOTE: calling this method transfers ownership of the originating_packet's memory
// to the ConnectionPool itself.  The ConnectionPool will be responsible for freeing
// the packet's data buffer and packet object "eventually".
void ConnectionPool::add_pending_lease_request(ClientConnection * client_connection, Packet * originating_packet) {
  // Create the new PendingLeaseRequest and associate it with the connection.
  PendingLeaseRequest * lease_request = new PendingLeaseRequest;
  lease_request->client_connection = client_connection;
  lease_request->pending_packet = originating_packet;
  lease_request->requested_at_time = time(0);
  client_connection->pending_lease_request = lease_request;

  // Set the packet's is_pending flag to indicate that it's now "owned" by a PendingLeaseRequest.
  // The PendingLeaseRequest will then be responsible for freeing the packet's memory later.
  originating_packet->is_pending = true;

  // Add the new lease request to the END of the linked list, to implement a first-come-first-served queue.
  lease_request->next = 0;
  if(pending_lease_requests_tail) {
    pending_lease_requests_tail->next = lease_request;
    pending_lease_requests_tail = lease_request;
  }
  else {
    pending_lease_requests_head = lease_request;
    pending_lease_requests_tail = lease_request;
  }
}


// The given client connection is going away (or we are explicitly aborting a pending lease
// request due to something like a lease timeout).  Remove any pending lease request for this connection
// from our linked list of pending lease requests (there should only be at most one for any given client).
void ConnectionPool::cancel_pending_lease_requests_for_client_connection(ClientConnection * client_connection) {
  PendingLeaseRequest * lease_request, * prev, * next;
  for(lease_request = pending_lease_requests_head, prev = 0;
      lease_request; lease_request = next) {
    next = lease_request->next;
    if(lease_request->client_connection == client_connection) {
      // Get rid of this lease request.
      if(lease_request == pending_lease_requests_tail)
        pending_lease_requests_tail = prev;
      if(prev)
        prev->next = next;
      else
        pending_lease_requests_head = next;
      delete lease_request;
    }
    else
      prev = lease_request;
  }

  client_connection->pending_lease_request = 0;

  // Reset the client connection state; since the query triggering the pending lease
  // request has been aborted, the client is no longer expecting a query response.
  client_connection->switch_to_ready_state();
}


// At least one of the DatabaseConnections in this pool has (possibly) become available for a client to lease.
// Check the pending lease requests to see if we can satisify any of them now, and if so, start the lease.
void ConnectionPool::check_pending_lease_requests() {
  // If we're in the middle of a clean shutdown, don't start any new connection leases.
  // Let the pending clients just keep blocking until they are eventually closed by the
  // shutdown process.
  if(current_server->run_state != SERVER_RUN_STATE_ACTIVE)
    return;
  
  while(pending_lease_requests_head) {
    // There's at least one pending lease request.  Since the lease requests are first come first serve
    // (they have to be to maintain ordering integrity), we need to satisfy the first one before moving
    // onto the next pending lease request.
    PendingLeaseRequest * pending_lease_request = pending_lease_requests_head;
    DatabaseConnection * db_connection = lease_connection_for_client(pending_lease_request->client_connection);

    if(!db_connection)
      break;  // could not satisfy the lease request; give up

    // TODO: check the lease request's requested_at_time and if it's too old,
    // throw a timeout error back to the client (and probably close the client's connection)

    // Disassociate the pending lease request from the connection.
    pending_lease_request->client_connection->pending_lease_request = 0;

    // Remove the pending lease request from the connection pool's linked list.
    // Don't actually delete the lease request yet, though.  This is done in case the
    // processing the buffered packets creates another pending lease request (so that
    // we don't end up with two pending lease requests for the same client connection
    // in the list at once).
    pending_lease_requests_head = pending_lease_request->next;
    if(pending_lease_requests_head == 0)
      pending_lease_requests_tail = 0;

    // Cause the client connection to "re-handle" the pending packet.
    // This time, it should succeed, since the client connection now has a leased DB connection set up.
    pending_lease_request->handle_pending_packet();

    delete pending_lease_request;
  }
}


// 50/50 chance to either suspend or unsuspend all connections in this pool.
// This is used to implement the 'simulate_busy_dbs' option for stress testing.
void ConnectionPool::randomly_suspend_or_unsuspend_connections() {
  if(random() % 2) {
    log_debug_message("Suspending DB connections in \"%s\" pool", config->apparent_database_name);
    loopi(pool_size) 
      if(connections[i]->lease_state == LEASE_STATE_AVAILABLE)
        connections[i]->start_suspending_connection();
  }
  else {
    log_debug_message("Unsuspending DB connections in \"%s\" pool", config->apparent_database_name);
    loopi(pool_size) 
      if(connections[i]->lease_state == LEASE_STATE_SUSPENDED)
        connections[i]->stop_suspending_connection();
  }
}


// Callback for nonblocking DNS resolution.
static void evdns_callback(int errcode, struct evutil_addrinfo * addr, void * ptr) {
  ConnectionPool * pool = (ConnectionPool *)ptr;
  
  pool->getaddrinfo_request = 0;
  if(errcode)
    pool->handle_unsuccessful_dns_resolution(errcode);
  else {
    struct sockaddr_in * sa = (struct sockaddr_in *)addr->ai_addr;
    char inet_buf[100];
    evutil_inet_ntop(AF_INET, &sa->sin_addr, inet_buf, sizeof(inet_buf));
    log_debug_message("Resolved hostname \"%s\" to IP address: %s",
                      pool->config->hostname, inet_buf);
    pool->remote_address = *sa;
    pool->last_successful_dns_resolution_at = time(0);
    pool->start_connecting_connections_that_were_waiting_on_dns();
  }
  if(addr)
    evutil_freeaddrinfo(addr);
}

