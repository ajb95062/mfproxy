

#include "main.h"


static void connect_callback(evutil_socket_t fd, short what, void * arg);


DatabaseConnection::DatabaseConnection() {
  consecutive_connection_failures = 0;
  last_query_sent_at_time = 0;
  lease_state = LEASE_STATE_UNAVAILABLE;
  leasing_client_connection = 0;
  current_server->allocation_stats.database_connections++;
}


DatabaseConnection::~DatabaseConnection() {
  current_server->allocation_stats.database_connections--;
}


// This implements connection maintenance tasks that should be done every few seconds,
// not necessarily tied to the overall event loop flow.  Currently this handles the various
// network timeouts that can occur.
void DatabaseConnection::perform_periodic_maintenance() {
  // Kill client connections who have held their connection leases open too long.
  if(leasing_client_connection && leasing_client_connection->has_exceeded_lease_timeout()) {
    log_debug_message("%s has held a connection lease for too long; killing the connection",
                      leasing_client_connection->description_string());
    leasing_client_connection->close();
  }

  // Abort nonblocking connect() calls if they are taking too long.
  close_if_connect_timeout_exceeded();

  // Check for (idle) database connections that have been open for too long and
  // disconnect them (if configured via 'max_database_connection_lifetime').
  close_if_maximum_lifetime_exceeded();

  // Check for database connections that have timed out waiting on query results.
  close_if_query_timeout_exceeded();
}


// Start the process of connecting to the database.
//
// The first step is to resolve the database host's IP address.  Depending on the
// configuration options, this can be done either via a blocking call to getaddrinfo()
// or by a nonblocking DNS lookup courtesy of libevent (recommended).
//
// When using nonblocking DNS, we'll transition into WAITING_FOR_DNS state while the
// DNS resolution is in progress.  When the resolution finishes we'll then transition
// to the CONNECTING state for a nonblocking connect() to the resolved IP.  If using
// blocking DNS lookups, we'll transition directly to the CONNECTING state once the blocking
// lookup finishes.
//
// NOTE: When using nonblocking DNS, it's the database connection pool that handles the
// lookup, not the database connection itself.  This is so that the connection pool can cache
// the DNS lookup results for subsequent connections within the same pool.  The pool will see
// that we are in the WAITING_FOR_DNS state and use that to notify us when the DNS is resolved.
void DatabaseConnection::start_resolving_dns_for_connect() {
  if(global_config->use_nonblocking_dns) {
    // Start a nonblocking DNS call.
    state = CONNECTION_STATE_WAITING_FOR_DNS;
    pool->start_getaddrinfo_request_if_needed();
    return;
  }
  else {
    // Perform a blocking DNS lookup.
    struct addrinfo hints, * addrinfo_result;
    char port_buf[100];
    int error;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(port_buf, sizeof(port_buf), "%d", (int)pool->config->port);
    error = getaddrinfo(pool->config->hostname, port_buf, &hints, &addrinfo_result);
    if(error) {
      consecutive_connection_failures++;
      log_error_message("Could not resolve database hostname \"%s\": %s.",
                        pool->config->hostname, strerror(errno));
      return;
    }
    struct addrinfo * addrinfo_ptr;
    for(addrinfo_ptr = addrinfo_result; addrinfo_ptr; addrinfo_ptr = addrinfo_ptr->ai_next) {
      if(addrinfo_ptr->ai_family == AF_INET) {
        remote_address = *((struct sockaddr_in *)addrinfo_ptr->ai_addr);
        break;
      }
    }
    freeaddrinfo(addrinfo_result);
    if(!addrinfo_ptr) {
      log_error_message("Could not find IPv4 address for database hostname \"%s\".",
                        pool->config->hostname);
      return;
    }

    // Start the nonblocking connect() to the resolved IP address.
    start_connecting_to_remote_address();
  }
}


// Start a nonblocking connect() to the IP address stored in this->remote_address.
// We'll switch into CONNECTING state while the connect is in progress, then
// eventually switch into WAITING_FOR_HANDSHAKE once the connect finishes.
void DatabaseConnection::start_connecting_to_remote_address() {
  // Record the time in order to check for connect() timeouts.
  gettimeofday(&connect_started_at_time, 0);

  // Create the socket.
  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if(socket_fd < 0) {
    // This shouldn't ever really happen, unless maybe we're out of file descriptors.
    consecutive_connection_failures++;
    log_error_message("socket() failed in start_connecting(): %s (out of file descriptors?)", strerror(errno));
    state = CONNECTION_STATE_UNCONNECTED;
    return;
  }

  if(pool->config->use_nonblocking_connect) {
    // Start a nonblocking connect operation.
    evutil_make_socket_nonblocking(socket_fd);
    if(connect(socket_fd, (struct sockaddr *)&remote_address, sizeof(remote_address)) == 0) {
      // Connection was successfully made immediately.
      // Transition directly to WAITING_FOR_HANDSHAKE state rather
      // than going to CONNECTING state (we're already connected).
      if(consecutive_connection_failures > 0)
        log_message("Connected to %s without having to wait, after %d failed attempts.",
                    description_string(), (int)consecutive_connection_failures);
      else
        log_message("Connected to %s without having to wait.", description_string());
      
      connection_established();
    }
    else if(errno == EINPROGRESS) {
      // Connection could not be completed immediately; set up an event to
      // fire when the nonblocking connect succeeds or fails.  This is a normal
      // condition with nonblocking I/O and not an error.
      // TODO: make sure this is deallocated when it should be
      struct event * connect_event =
        event_new(current_server->event_base, socket_fd,
                  EV_READ | EV_WRITE, connect_callback, this);
      event_add(connect_event, 0);
      state = CONNECTION_STATE_CONNECTING;
    }
    else {
      // Error in connect().  Revert back to the unconnected state;
      // a timer event will eventually retry the connection flow again.
      consecutive_connection_failures++;
      log_error_message("Error in connect() to backend database \"%s\" (errno=%d)",
                        pool->config->hostname, (int)errno);
      ::close(socket_fd);  // No bufferevent is created yet, so we have to explicitly close the socket.
      state = CONNECTION_STATE_UNCONNECTED;
    }
  }
  else {
    // Perform a blocking connect instead of nonblocking.
    // In this case, we have to create the bufferevent up front so that we can use the libevent
    // bufferevent_socket_connect call.
    create_bufferevent();

    // Perform the blocking connect.
    state = CONNECTION_STATE_CONNECTING;
    if(bufferevent_socket_connect(bufferevent, (struct sockaddr *)&remote_address, sizeof(remote_address)) < 0) {
      log_message("Connection to %s could not be established in blocking mode.", description_string());
      consecutive_connection_failures++;
      close();
    }
    else {
      connection_established();
      log_message("Connected to %s in blocking mode; took %0.3fms.",
                  description_string(), (double)(seconds_since_connect_started() * 1000.0));
    }
  }
}


// connect() to the backend database has completed successfully.
void DatabaseConnection::connection_established() {
  established_at_time = time(0);

  if(!bufferevent)  // May have already been created if we did a blocking connect().
    create_bufferevent();

  pool->stats.database_connections_established++;

  // Once connected to the database, we're expecting it to send us a Handshake packet.
  // (We may also get an Error packet at this point in the protocol, for example if
  // the database has exceeded its max_connections limit.)
  state = CONNECTION_STATE_WAITING_FOR_HANDSHAKE;
  expected_packet_type = EXPECTING_HANDSHAKE;

  // Reset some fields - TODO: handle this in a cleaner way.  We only really need this
  // because we don't reallocate the DatabaseConnection objects when they disconnect/reconnect.
  reading_packet_body = false;
  is_closing = false;
  consecutive_connection_failures = 0;

  // Schedule a timer event that will try to establish more connections
  // after a suitable interval of time has elapsed (to avoid overwhelming
  // MySQL with simultaneous connections).
  current_server->schedule_database_connect_timer_event();
}


// The backend database is closing this connection from its end.  Usually this means
// that there is some problem with the database server, or a networking problem.
// When this happens, we have to disconnect any client connections that are using
// this database backend because there is no way to throw a clean error back to the
// client (they may be at any random point in the MySQL protocol).  The client can then
// try to reconnect and just start afresh.
void DatabaseConnection::remote_closed_connection() {
  // NOTE: If we're in the process of doing a clean shutdown, this isn't actually an error.
  // We probably requested the database to close its connection by sending it a QUIT packet.
  if(current_server->run_state != SERVER_RUN_STATE_SHUTTING_DOWN)
    log_error_message("%s remote closed connection.", description_string());

  close();
}


// Only meaningful if a connect() is either currently in progress, or has just succeeded/failed.
double DatabaseConnection::seconds_since_connect_started() {
  struct timeval elapsed_connect_timeval, current_timeval;
  gettimeofday(&current_timeval, 0);
  timeval_subtract(&elapsed_connect_timeval, &current_timeval, &connect_started_at_time);
  return timeval_seconds(&elapsed_connect_timeval);
}


// This implements the 'database_connect_timeout' config option.
// Close pending backend database connections that are taking too long to actually connect.
void DatabaseConnection::close_if_connect_timeout_exceeded() {
  if(!(state == CONNECTION_STATE_CONNECTING &&
       pool->config->database_connect_timeout > 0 &&
       seconds_since_connect_started() > (double)pool->config->database_connect_timeout))
    return;

  // Connection establishment has timed out.  Abort the in-progress connect() by closing the socket.
  // TODO: I'm not certain if calling close() on the socket is really the right way to handle this.
  // It seems logical for that to be the right way but I can't find a definitive reference.
  consecutive_connection_failures++;
  ::close(socket_fd);
  state = CONNECTION_STATE_UNCONNECTED;

  char inet_buf[100];
  evutil_inet_ntop(AF_INET, &pool->remote_address.sin_addr, inet_buf, sizeof(inet_buf));
  log_error_message("Timed out connecting to backend database \"%s\" (%s) after %dms.",
                    pool->config->hostname, inet_buf,
                    (int)(seconds_since_connect_started() * 1000.0));

  // Flush the DNS cache for this pool - maybe we are caching an IP address that has changed,
  // and that's what caused the connection to time out.
  pool->invalidate_dns_cache();
}


// This implements the 'max_database_connection_lifetime' config option.
// Conservatively close backend database connections that have been held open too long,
// on the assumption that the protocol will eventually get out of alignment for some reason.
// This is a basic self-healing mechanism in case that happens.
void DatabaseConnection::close_if_maximum_lifetime_exceeded() {
  // Only close unleased, idle database connections this way.
  // We don't want to interrupt existing transactions or queries just to enforce
  // this soft lifetime limit.
  if(!(lease_state == LEASE_STATE_AVAILABLE && state == CONNECTION_STATE_READY &&
       leasing_client_connection == 0))
    return;

  if(pool->config->max_database_connection_lifetime > 0 &&
     (time(0) - established_at_time) >= pool->config->max_database_connection_lifetime) {
    log_message("Closing %s since it exceeded the maximum lifetime of %d seconds.",
                description_string(), (int)(pool->config->max_database_connection_lifetime));
    close();
  }
}


// If a query has timed out, close the database connection and also the client
// connection that is waiting on the query results.  Generally, the actual timeout logic
// would be implemented by the client itself, and configured with a timeout value
// that is shorter than the one used in this proxy.  In that case, the query timeout
// here would just be a failsafe backup that is rarely hit.
void DatabaseConnection::close_if_query_timeout_exceeded() {
  // Check if we're waiting for the (initial) response to a query (this includes
  // field-list pseudo queries).
  if(!(state == CONNECTION_STATE_WAITING_FOR_QUERY_RESPONSE ||
       state == CONNECTION_STATE_WAITING_FOR_FIELD_LIST_RESPONSE))
    return;

  // Check if we're in the process of reading query result rows or resultset headers.
  // TODO: maybe create a dedicated is_reading_query_results() method.
  if(!(expected_packet_type == EXPECTING_RESULTSET_HEADER ||
       expected_packet_type == EXPECTING_RESULTSET_FIELD_DESCRIPTIONS ||
       expected_packet_type == EXPECTING_RESULTSET_ROWS ||
       expected_packet_type == EXPECTING_FIELD_LIST_RESPONSE))
    return;

  // We're waiting on query results.  Check the timeout.
  if(pool->config->database_query_timeout > 0 &&
     time(0) - last_query_sent_at_time > pool->config->database_query_timeout) {
    // Query has timed out.  We have to close both the client that is waiting on
    // the query, and the backend database connection itself, since it's presumed
    // the backend connection is now "borked" (the MySQL protocol doesn't have a
    // way to recover from this state).
    log_message("Closing %s due to query timeout.", description_string());
    close();  // This closes both the database connection and the client connection.
  }
}


// Close the database socket and put this connection into the UNCONNECTED state.
// If a client connection is currently using this database connection, the client
// will be forcefully disconnected at this point.
//
// NOTE: the DatabaseConnection is not actually deleted here, unlike when close()
// is called on a ClientConnection.
void DatabaseConnection::close() {
  if(leasing_client_connection) {
    log_message("Disconnecting %s because its leased database connection is closing.",
                leasing_client_connection->description_string());
    pool->cancel_pending_lease_requests_for_client_connection(leasing_client_connection);
    leasing_client_connection->really_close();
    leasing_client_connection = 0;
  }
  
  bufferevent_free(bufferevent);  // This closes the underlying socket as well.
  bufferevent = 0;
  lease_state = LEASE_STATE_UNAVAILABLE;
  state = CONNECTION_STATE_UNCONNECTED;
  established_at_time = 0;

  pool->stats.database_connections_closed++;

  // If we're preparing to shut down cleanly, this may have been the last database
  // connection we were waiting on to close before shutdown.  Check for this case.
  if(current_server->can_finish_shutting_down_cleanly())
    current_server->finish_clean_shutdown_process();
}


// This implements the mysql_native_password authentication method.
// The 20-byte result (plus NUL terminator) is stored into *dest.
// http://dev.mysql.com/doc/internals/en/secure-password-authentication.html
void DatabaseConnection::compute_mysql_native_password(uint8_t dest[SHA1_DIGEST_LENGTH + 1],
                                                       const uint8_t random_data_from_server[SHA1_DIGEST_LENGTH + 1],
                                                       const uint8_t * plaintext_password) {
  SHA1_CTX context;
  uint8_t sha1_password[SHA1_DIGEST_LENGTH], sha1_sha1_password[SHA1_DIGEST_LENGTH];

  if(strlen((const char *)plaintext_password) == 0) {
    // Special case: if the password is empty, use an empty auth_response string too.
    // In the Handshake Response packet, the auth_response_length field needs to be set to
    // zero; this indicates the "no password" state to the MySQL server.  The length field
    // has to be set by the caller; all we can do here is zero out the authentication response.
    // May want to add an extra argument to this function to handle this case more cleanly.
    memset(dest, 0, SHA1_DIGEST_LENGTH + 1);
    return;
  }

  // Calculate SHA1(plaintext_password)
  SHA1Init(&context);
  SHA1Update(&context, plaintext_password, strlen((const char *)plaintext_password));
  SHA1Final(sha1_password, &context);

  // Calculate SHA1(SHA1(plaintext_password))
  SHA1Init(&context);
  SHA1Update(&context, sha1_password, SHA1_DIGEST_LENGTH);
  SHA1Final(sha1_sha1_password, &context);

  // Calculate SHA1(random_data_from_server + SHA1(SHA1(plaintext_password)))
  SHA1Init(&context);
  SHA1Update(&context, random_data_from_server, SHA1_DIGEST_LENGTH);
  SHA1Update(&context, sha1_sha1_password, SHA1_DIGEST_LENGTH);
  SHA1Final(dest, &context);

  // Calculate SHA1(password) XOR SHA1(random_data_from_server + SHA1(SHA1(plaintext_password)))
  loopi(SHA1_DIGEST_LENGTH)
    dest[i] ^= sha1_password[i];

  // NUL terminate the string.
  dest[SHA1_DIGEST_LENGTH] = 0;
}


// Used by the 'simulate_busy_dbs' config option.
void DatabaseConnection::start_suspending_connection() {
  if(lease_state != LEASE_STATE_AVAILABLE)
    panic("start_suspending_connection() called when not in LEASE_STATE_AVAILABLE (shouldn't happen)");
  lease_state = LEASE_STATE_SUSPENDED;
}


// Used by the 'simulate_busy_dbs' config option.
void DatabaseConnection::stop_suspending_connection() {
  if(lease_state != LEASE_STATE_SUSPENDED)
    panic("stop_suspending_connection() called when not in LEASE_STATE_SUSPENDED (shouldn't happen)");
  lease_state = LEASE_STATE_AVAILABLE;
  pool->check_pending_lease_requests();
}


void DatabaseConnection::record_outgoing_network_traffic(size_t bytes) {
  pool->stats.bytes_sent_to_databases += bytes;
}


void DatabaseConnection::send_quit_packet() {
  QuitPacket * packet = new QuitPacket;
  synthesize_and_send_packet(packet);
  delete packet;
}


// Start sending a SQL query to the database.
// Queries sent via this method originate directly from the proxy rather than
// simply being forwarded from a client.
void DatabaseConnection::send_query_string(const char * query_string) {
  QueryPacket * query_packet;
  
  if(state != CONNECTION_STATE_READY) {
    // Shouldn't happen in normal use.  (call panic() here?)
    log_error_message("send_query_string() called for %s while not in READY state.", description_string());
    return;
  }

  log_debug_message("%s query: %s", description_string(), query_string);

  state = CONNECTION_STATE_WAITING_FOR_QUERY_RESPONSE;
  expected_packet_type = EXPECTING_RESULTSET_HEADER;
  last_query_sent_at_time = time(0);

  // Synthesize and send a QueryPacket.
  query_packet = new QueryPacket;
  query_packet->data.sequence_number = 0;
  query_packet->query_string = query_string;
  query_packet->query_string_length = strlen(query_string);
  synthesize_and_send_packet(query_packet);
  delete query_packet;
}


void DatabaseConnection::forward_packet_data(PacketData packet_data) {
  if(leasing_client_connection)
    leasing_client_connection->send_packet_data(packet_data);
}


// We've completely finished sending the results of a query (or fieldlist request)
// to the client.  Switch back into the ready/idle state and release the client's
// database connection lease if a transaction is not still open.
// Arguments:
//   - in_transaction is true if we are still inside a transaction as indicated by the MySQL
//     status flags, or by context.  In this case the client<->connection association will be
//     retained; otherwise the lease will be released for other clients to use.
//   - more_results_exists is true if there are more result sets coming in the data stream
//     from the database (this is also indicated by a flag in the MySQL protocol).
void DatabaseConnection::finish_forwarding_query_to_client(bool in_transaction, bool more_results_exists) {
  ClientConnection * client_connection = leasing_client_connection;

  if(more_results_exists) {
    // If the SERVER_MORE_RESULTS_EXISTS flag was set in the resultset terminator
    // packet (either an OK packet or EOF packet), there is another entire resultset
    // right after this one.  Switch back to expecting another resultset; this query
    // is not finished yet.
    state = CONNECTION_STATE_WAITING_FOR_QUERY_RESPONSE;
    expected_packet_type = EXPECTING_RESULTSET_HEADER;
    return;
  }

  // Record the time at which the query finished for benchmarking purposes.
  gettimeofday(&leasing_client_connection->query_timings.query_finished, 0);

  // Remember what transaction state we're in as the query ends, in case
  // the next query leads to an ERR response.  Since the ERR packet doesn't
  // contain the transaction status flags, and errors don't actually rollback
  // the active transaction, this is the only way we can keep track of the
  // transaction state across errors.
  client_connection->in_transaction = in_transaction;

  // Reset database and client connection states back to normal
  // (since no query is in progress now).
  switch_to_ready_state();
  client_connection->switch_to_ready_state();

  // Increment the query counter tallies.
  pool->stats.queries_processed++;
  if(!in_transaction)
    pool->stats.transactions_completed++;

  // The various query_timings values recorded by the client connection during
  // this query are now a complete set; do something with them.
  client_connection->record_query_timings();
  
  // If the status flags indicate no transaction is in progress,
  // release the connection lease.  Otherwise, the client is in the middle
  // of a transaction and we have to hold onto the lease until it's done.
  if(in_transaction) {
    // If the client connection is in the pending-close state, we have to
    // abort the transaction that is in progress.  To do this, a ROLLBACK
    // query will be sent to the database backend.  Eventually once the rollback
    // finishes we'll get back to another invocation of this finish_forwarding
    // method but that time with in_transaction==false.
    // TODO: we may want an extra safeguard against an infinite loop in this case
    // (another boolean instance variable in DatabaseConnection).  I've never seen
    // this happen in practice but it potentially could if the ROLLBACK fails somehow.
    if(client_connection->is_closing) {
      log_debug_message("%s is closing its connection while in a database transaction; sending ROLLBACK to %s",
                        client_connection->description_string(), description_string());
      send_query_string("ROLLBACK");
    }
  }
  else {
    pool->release_leased_connection(this);

    // If the client connection is in the pending-close state, we're finally
    // able to close it for real now.
    if(client_connection->is_closing) {
      client_connection->really_close();
      return;  // NOTE: need an explicit return here since client_connection is deleted at this point.
    }
  }

  // Now that the query is done we can process more packets coming from the client.
  client_connection->start_accepting_input();
}


void DatabaseConnection::record_incoming_network_traffic(size_t bytes) {
  pool->stats.bytes_read_from_databases += bytes;
}


// See: http://dev.mysql.com/doc/internals/en/com-query-response.html
// TODO: This doesn't handle LOCAL_INFILE_Request yet.
// We can receive here one of the following:
//   - OK packet, indicating the query is already finished (no query results).
//   - ERR packet if something went wrong.
//   - A packet containing a length-encoded column_count, which means that more
//     ColumnDefinition packets are coming.
void DatabaseConnection::handle_resultset_header(PacketData packet_data) {
  // First forward the packet on to the client no matter what it actually contains.
  forward_packet_data(packet_data);

  // This is the first packet received in response to a database query;
  // record the time for benchmarking purposes.
  gettimeofday(&leasing_client_connection->query_timings.response_started_from_database, 0);

  if(packet_data.looks_like_ok_packet()) {
    // "OK" packet.  Decode the packet so that we can extract the status flags.
    OKPacket * ok_packet = (OKPacket *)packet_data.create_packet();
    ok_packet->extract_packet_fields();
    bool in_transaction = ok_packet->is_in_transaction();
    bool more_results_exists = ok_packet->more_results_exists();
    delete ok_packet;  // NOTE: this frees the packet_data.data too

    // log_debug_message("Query status flags from OK packet: %x", (int)status_flags);

    // The query is either completely done now, or there is another resultset coming
    // (depending on the more_results_exists status flag).  Either way we are done
    // forwarding this particular resultset to the client now.
    finish_forwarding_query_to_client(in_transaction, more_results_exists);
  }
  else if(packet_data.looks_like_err_packet()) {
    // ERR packet.  As far as I can tell, this doesn't cause an implicit transaction
    // rollback or commit, so just keep the existing transaction state.
    finish_forwarding_query_to_client(leasing_client_connection->in_transaction, false);
    packet_data.release_memory();
  }
  else if(packet_data.looks_like_eof_packet()) {
    // According to the MySQL protocol documentation, this shouldn't actually
    // happen here.  If it does, log it and ignore it.
    log_error_message("Received unexpected EOF from %s in resultset header packet.",
                      description_string());
    packet_data.release_memory();
  }
  else {
    // The packet contains a length-encoded integer with the field count.
    BinaryDecoder decoder(packet_data);
    current_result_set.field_count = decoder.read_length_encoded_int();

    // We should get a list of field description packets after this,
    // terminated by an EOF packet.
    expected_packet_type = EXPECTING_RESULTSET_FIELD_DESCRIPTIONS;
    packet_data.release_memory();
  }
}


// We've received one of these as part of a resultset header:
// http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-Protocol::ColumnDefinition41
// The proxy doesn't actually care about the content of this; it's simply forwarded onto the client.
void DatabaseConnection::handle_resultset_field_description(PacketData packet_data) {
  forward_packet_data(packet_data);

  if(packet_data.looks_like_eof_packet()) {
    // EOF packet received; we are done reading the field descriptions
    // and are now expecting the result rows.
    // This is the "if CLIENT_DEPRECATE_EOF isn't set, EOF_Packet" case from here:
    // http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-ProtocolText::Resultset
    expected_packet_type = EXPECTING_RESULTSET_ROWS;
  }
  else if(packet_data.looks_like_err_packet()) {
    // Error packet.  This shouldn't happen according to the MySQL protocol docs.
    log_error_message("Unexpected Error packet received from %s while reading resultset field descriptions",
                      description_string());
  }
  else {
    // Field description packet.  If we ever need to actually to parse these from
    // the proxy this is the place to do it.
  }

  packet_data.release_memory();
}


// http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-COM_QUERY_Response
// We're in the "ROW" part of the state diagram.
void DatabaseConnection::handle_resultset_row(PacketData packet_data) {
  forward_packet_data(packet_data);

  if(packet_data.looks_like_eof_packet()) {
    // EOF packet - all rows have been received.
    // Decode the EOF packet so that we can extract the status_flags.
    EOFPacket * eof_packet = (EOFPacket *)packet_data.create_packet();
    eof_packet->extract_packet_fields();
    bool in_transaction = eof_packet->is_in_transaction();
    bool more_results_exists = eof_packet->more_results_exists();
    delete eof_packet;  // this frees the packet_data.data too

    // log_message("Query status flags: %x", (int)status_flags);

    // Clean up and switch back into normal state.  If the more_results_exists flag
    // was indicated in the EOF packet, we'll instead switch back to reading another
    // resultset at this point.
    finish_forwarding_query_to_client(in_transaction, more_results_exists);
  }
  else if(packet_data.looks_like_err_packet()) {
    // ERR packet while reading rows.  This is an allowed condition
    // in the MySQL protocol.  I'm not sure if this aborts an in-progress
    // transaction, though.  For now, leave the transaction state unaltered,
    // but this needs to be looked at more.
    log_error_message("%s received Error packet while reading rows.", description_string());
    finish_forwarding_query_to_client(leasing_client_connection->in_transaction, false);
    packet_data.release_memory();
  }
  else {
    // Each "row" is just a list of length-encoded strings, or else 0xfb bytes to represent NULLs.
    // We don't currently do anything with this in the proxy besides blindly forwarding it on to the client.
    packet_data.release_memory();
  }
}


// See: http://dev.mysql.com/doc/internals/en/com-field-list-response.html
void DatabaseConnection::handle_field_list_response(PacketData packet_data) {
  forward_packet_data(packet_data);
  
  if(packet_data.looks_like_eof_packet()) {
    // EOF packet - all field descriptions have been received.
    // Decode the EOF packet so that we can extract the status_flags.
    EOFPacket * eof_packet = (EOFPacket *)packet_data.create_packet();
    eof_packet->extract_packet_fields();
    bool in_transaction = eof_packet->is_in_transaction();
    bool more_results_exists = eof_packet->more_results_exists();
    delete eof_packet;  // this frees the packet_data.data too

    finish_forwarding_query_to_client(in_transaction, more_results_exists);
  }
  else if(packet_data.looks_like_err_packet()) {
    // ERR packet while reading field descriptions.
    // Similar to the case when an ERR packet is received while reading query result
    // rows, I'm not sure if this aborts an in-progress transaction.  Need to check on this.
    log_error_message("%s received Error packet while reading field list.", description_string());
    finish_forwarding_query_to_client(leasing_client_connection->in_transaction, false);
    packet_data.release_memory();
  }
}


// We have received a handshake packet from the server.
// We should only get this when first connecting to the database,
// while we're in the WAITING_FOR_HANDSHAKE state.
void DatabaseConnection::handle_handshake_v10_packet(HandshakeV10Packet * packet) {
  if(state != CONNECTION_STATE_WAITING_FOR_HANDSHAKE) {
    log_error_message("%s received unexpected HandshakeV10 packet from server while not in WAITING_FOR_HANDSHAKE state.",
                      description_string());
    close();
    return;
  }

  // Compute the authentication response.  Currently only mysql_native_password auth method is supported.  
  if(strcmp(packet->auth_plugin_name, "mysql_native_password") != 0) {
    log_error_message("Only supporting mysql_native_password auth method for now; aborting");
    close();
    return;
  }

  // Make sure we have exactly 20 bytes in the auth_plugin_data field.
  // (in reality it's treated as 21 bytes because of the NUL terminator)
  if(packet->auth_plugin_data_length != SHA1_DIGEST_LENGTH+1) {
    log_error_message("Auth method is mysql_native_password, but auth_plugin_data_length != 21 (it's actually %d)",
                      (int)packet->auth_plugin_data_length);
    close();
    return;
  }

  // Generate the auth_response.
  uint8_t auth_response[50];  // Need 20 bytes + 1 byte for nul terminator.  Make sure the size of this is < 255.
  compute_mysql_native_password(auth_response, packet->auth_plugin_data, (const uint8_t *)pool->config->password);

  // Synthesize a HandshakeResponse packet.
  HandshakeResponse41Packet * response_packet = new HandshakeResponse41Packet;
  response_packet->data.sequence_number = packet->data.sequence_number + 1;
  response_packet->capability_flags = Server::default_capability_flags();
  response_packet->max_packet_size = 100*1024;  // 100k max, to keep worst-case memory usage down
  response_packet->character_set = 0x21;  // utf8_general_ci (TODO: make this configurable)
  response_packet->username = pool->config->username;
  memcpy(response_packet->auth_response, auth_response, sizeof(auth_response));
  if(strlen(pool->config->password) == 0)
    response_packet->auth_response_length = 0;  // i.e. "no password" mode
  else
    response_packet->auth_response_length = SHA1_DIGEST_LENGTH;
  response_packet->auth_plugin_name = packet->auth_plugin_name;
  response_packet->attributes_count = 0;
  response_packet->database_name = pool->config->actual_database_name;

  // Send the HandshakeResponse packet to the server.
  synthesize_and_send_packet(response_packet);
  delete response_packet;

  // Switch into AUTHENTICATING state, indicating that we are waiting for either an OKPacket
  // or ErrorPacket from the database server with the results of our authentication.
  state = CONNECTION_STATE_AUTHENTICATING;
  expected_packet_type = EXPECTING_PACKET_WITH_TYPE_CODE;
}


// The meaning of an "OK" packet received from the database varies depending
// on where we are in the MySQL protocol.
// TODO: it doesn't really, we should probably remove this
void DatabaseConnection::handle_ok_packet(OKPacket * packet) {
  switch(state) {
  case CONNECTION_STATE_AUTHENTICATING:
    handle_ok_packet_while_authenticating(packet);
    break;
  default:
    log_error_message("%s received OK packet from database while in an unexpected state (%d).",
                      description_string(), (int)state);
    // just discard the packet
    break;
  }
}


void DatabaseConnection::handle_ok_packet_while_authenticating(const OKPacket * packet) {
  // We have successfully completed the handshake (including selecting the initial database schema),
  // and are now ready to forward commands from clients.
  state = CONNECTION_STATE_READY;
  lease_state = LEASE_STATE_AVAILABLE;
  pool->check_pending_lease_requests();

  log_debug_message("%s established backend connection to %s:%s",
                    description_string(), pool->config->hostname, pool->config->actual_database_name);
}


void DatabaseConnection::handle_error_packet(ErrorPacket * packet) {
  switch(state) {
  case CONNECTION_STATE_WAITING_FOR_HANDSHAKE:
    handle_error_packet_while_waiting_for_handshake(packet);
    break;
  case CONNECTION_STATE_AUTHENTICATING:
    handle_error_packet_while_authenticating(packet);
    break;
  default:
    log_error_message("%s received Error packet while in an unexpected state (%d).", description_string(), (int)state);
    break;
  }
}


// Typically this happens when we overload MySQL's connection limit.
// In this case, if MySQL actually accepts our socket but has too many client connections
// already, it'll send us an ERR packet.
void DatabaseConnection::handle_error_packet_while_waiting_for_handshake(ErrorPacket * packet) {
  log_error_message("%s received error during connection: %s",
                    description_string(), packet->error_message);
  close();
}


// Authentication error, probably an invalid username or password.
void DatabaseConnection::handle_error_packet_while_authenticating(ErrorPacket * packet) {
  log_error_message("%s failed authentication with error: \"%s\".  Closing connection.",
                    description_string(), packet->error_message);
  close();
}


// Event callback for nonblocking connect() calls to the backend database.
// This could mean the connect either succeeded or failed.
static void connect_callback(evutil_socket_t fd, short what, void * arg) {
  DatabaseConnection * connection = (DatabaseConnection *)arg;
  
  // Retrieve the socket "error" code to determine whether the connect has succeeded.
  int error;
  socklen_t len = sizeof(error);
  getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);

  if(error) {
    close(connection->socket_fd);
    connection->state = CONNECTION_STATE_UNCONNECTED;
    log_error_message("Could not connect to database host \"%s\": %s.  Will try again later.",
                      connection->pool->config->hostname, strerror(error));
  }
  else {
    if(connection->consecutive_connection_failures > 0)
      log_message("Connected to %s in %0.3fms, after %d failed attempts.",
                  connection->description_string(),
                  (double)(connection->seconds_since_connect_started() * 1000.0),
                  (int)connection->consecutive_connection_failures);
    else
      log_message("Connected to %s in %0.3fms.",
                  connection->description_string(),
                  (double)(connection->seconds_since_connect_started() * 1000.0));
    connection->connection_established();
  }
}

