

#include "main.h"


ClientConnection::ClientConnection() {
  prev_connection = next_connection = 0;
  currently_leased_database_connection = 0;
  in_transaction = false;
  pending_lease_request = 0;
  ready_to_accept_input = false;
  close_when_output_finishes = false;
  packet_data_queue_head = packet_data_queue_tail = 0;
  packet_data_queue_size = 0;

  current_server->allocation_stats.client_connections++;
}


ClientConnection::~ClientConnection() {
  // Clean up any leftover queued packets.
  PacketDataWithLink * ptr, * next;
  for(ptr = packet_data_queue_head; ptr; ptr = next) {
    next = ptr->next;
    ptr->data.release_memory();
    delete ptr;
  }

  current_server->allocation_stats.client_connections--;
}


void ClientConnection::update_description() {
  char buf[1000], inet_buf[100];
  evutil_inet_ntop(AF_INET, &remote_address.sin_addr, inet_buf, sizeof(inet_buf));
  // NOTE: Could also show remote (ephemeral) port number here via remote_addr.sin_port.
  snprintf(buf, sizeof(buf), "[client %d from %s; %s]",
           (int)connection_id, inet_buf,
           (pool ? pool->config->apparent_database_name : "no pool selected"));
  set_description_string(buf);
}


// A connection from a client has been accepted; set up the bufferevent stuff
// and send the initial handshake.
void ClientConnection::connection_established() {
  established_at_time = time(0);
  update_description();
  log_debug_message("Accepted new connection: %s", description_string());
  create_bufferevent();
  current_server->client_stats.connections_accepted++;
}


// Client is closing the network socket from their end.
void ClientConnection::remote_closed_connection() {
  if(is_closing) {
    // We've already been notified by the client via a QUIT packet that they
    // want to close the connection.  Cleanup has already been done and we
    // don't have to do anything further here.
  } else { 
    // This client hasn't told us yet that it wants to close via a QUIT packet.
    // Instead, it's just closing the socket (or there has been a network error).
    // In this case, we still need to go through the whole "start closing" process
    // so that we can rollback any current database transaction for this client.
    close();
  }
}


// Start closing this client connection.  If the client is in the middle of a
// database operation, the connection is put into a pending-close state while the
// operation finishes, instead of being immediately closed.
void ClientConnection::close() {
  if(pool)
    pool->cancel_pending_lease_requests_for_client_connection(this);

  if(currently_leased_database_connection) {
    // Client connection is in the middle of a database interaction.
    // Flag it as being in the pending-closing state.  The database
    // connection will handle the eventual closing via the
    // finish_forwarding_query_to_client() method.
    is_closing = true;
    stop_accepting_input();  // Ignore anything further the client sends.

    // If the leased database connection is in READY state, that means that it's not
    // actually executing a query at the moment, but a transaction is still open.
    // This happens when a client explicitly opens a transaction with BEGIN.  We have
    // to get out of the transaction and the only way to do that is to issue a ROLLBACK
    // query to the database.  As part of the processing of the ROLLBACK query results,
    // the database connection will then close this client connection.
    if(currently_leased_database_connection->state == CONNECTION_STATE_READY) {
      log_message("%s is closing its connection while in a database transaction; sending ROLLBACK to database.",
                  description_string());
      currently_leased_database_connection->send_query_string("ROLLBACK");
    }
  }
  else
    really_close();
}


// The socket will be closed and the ClientConnection deleted from memory.
void ClientConnection::really_close() {
  log_debug_message("Closing %s", description_string());
  
  // Remove this connection from the server's master list of client connections.
  current_server->remove_client_connection(this);

  // Free connection's bufferevent (this also closes the socket, if not already closed,
  // due to BEV_OPT_CLOSE_ON_FREE).
  bufferevent_free(bufferevent);

  current_server->client_stats.connections_closed++;

  delete this;
}


// Check whether the client has taken too long with its database lease.
// This is used to implement the 'max_idle_connection_lease_time' and
// 'max_connection_lease_time' config options.
bool ClientConnection::has_exceeded_lease_timeout() const {
  if(!currently_leased_database_connection)
    return false;

  // Check to see if too much time has elapsed since last query activity.
  time_t current_time = time(0);
  int timeout;
  timeout = currently_leased_database_connection->pool->config->max_idle_connection_lease_time;
  if(timeout > 0 && current_time - lease_last_activity_time > timeout)
    return true;

  // Check to see if the lease has been held too long, regardless of query activity.
  timeout = currently_leased_database_connection->pool->config->max_connection_lease_time;
  if(timeout > 0 && current_time - lease_acquired_at_time > timeout)
    return true;

  return false;
}


void ClientConnection::record_outgoing_network_traffic(size_t bytes) {
  current_server->client_stats.bytes_sent_to_clients += bytes;
}


void ClientConnection::input_has_been_processed() {
  // If configured, impose the 'max_client_input_backlog' setting here.
  // If the client has too much data buffered explicitly in the packet_data_queue,
  // close the connection.
  if(global_config->max_client_input_backlog > 0 &&
     packet_data_queue_size > (size_t)global_config->max_client_input_backlog) {
    log_error_message("%s has exceeded the max_client_input_backlog size.  Closing the connection.",
                      description_string());
    close_when_output_finishes = true;
  }

  // If the connection is flagged as close_when_output_finishes, check the write buffer
  // size directly here and close the connection for real.  This deletes the actual connection
  // object, so it has to be the last thing to run in the event handler.
  if(close_when_output_finishes) {
    struct evbuffer * output_buffer = bufferevent_get_output(bufferevent);
    if(evbuffer_get_length(output_buffer) == 0)
      close();
  }
}


void ClientConnection::record_incoming_network_traffic(size_t bytes) {
  current_server->client_stats.bytes_read_from_clients += bytes;
}


// Overridden from the superclass to queue up incoming packets until we're ready to actually process them.
void ClientConnection::handle_received_packet_data(PacketData packet_data) {
  if(ready_to_accept_input)
    Connection::handle_received_packet_data(packet_data);
  else
    append_packet_data_to_queue(packet_data);
}


// Calling this indicates that the client connection is ready to process the next
// packet(s) received from the network.  Any data that was buffered while the connection
// was not ready to accept input will be immediately applied now.
void ClientConnection::start_accepting_input() {
  ready_to_accept_input = true;

  // Process queued packets if there are any.
  // NOTE: if any of the queued packets cause ready_to_accept_input to go false
  // again, further processing of the queue will be halted, to be picked up again
  // later once we are ready to accept input again.
  while(packet_data_queue_head && ready_to_accept_input) {
    // Dequeue the next packet from the list.
    PacketDataWithLink * ptr = packet_data_queue_head;
    PacketData data = ptr->data;
    packet_data_queue_head = ptr->next;
    if(packet_data_queue_head == 0)
      packet_data_queue_tail = 0;
    delete ptr;
    packet_data_queue_size -= data.length;
    handle_received_packet_data(data);
  }
}


void ClientConnection::stop_accepting_input() {
  ready_to_accept_input = false;
}


// Add data to the deferred input queue to be processed later.
void ClientConnection::append_packet_data_to_queue(PacketData data) {
  PacketDataWithLink * link = new PacketDataWithLink;
  link->data = data;
  link->next = 0;
  if(packet_data_queue_tail) {
    packet_data_queue_tail->next = link;
    packet_data_queue_tail = link;
  }
  else {
    packet_data_queue_head = link;
    packet_data_queue_tail = link;
  }
  packet_data_queue_size += data.length;
}


// A client connection has just been accepted, and the bufferevent stuff all set up.
// Send the client an initial handshake packet to start the authentication process.
void ClientConnection::send_initial_handshake_packet() {
  // Generate the random auth challenge string for the handshake.
  // Note that we have to keep this around in the connection so that we can
  // later compare it to what the client sends back in the Handshake Response.
  generate_secure_auth_challenge();

  // Build and send the handshake packet.
  HandshakeV10Packet * packet = new HandshakeV10Packet;
  packet->data.sequence_number = 0;
  packet->server_version = global_config->server_version;
  packet->connection_id = connection_id;
  packet->capability_flags = Server::default_capability_flags();
  packet->status_flags = 2;  // TODO: ???
  packet->character_set = 0xe0;
  strcpy((char *)packet->auth_plugin_data, (const char *)secure_auth_challenge);
  packet->auth_plugin_data_length = 21;
  packet->auth_plugin_name = "mysql_native_password";

  synthesize_and_send_packet(packet);
  delete packet;

  state = CONNECTION_STATE_AUTHENTICATING;

  // Since the Handshake Response packet we're expecting from the client doesn't have a typecode prefix
  // in the packet payload, make sure we expect this.  Once the handshake is received, we'll switch back
  // to expecting "normal" packets.
  expected_packet_type = EXPECTING_HANDSHAKE_RESPONSE;

  start_accepting_input();
}


// Send an Error packet.  This is an alternative to allocating your own ErrorPacket
// and using synthesize_and_send_packet().
//   - sql_state_string: the 5 byte "error code" field (e.g. "42000").  Leave it null to use "00000".
//   - packet_sequence_number: sequence number to use for the Error packet; this should be 1+ the sequence
//                             number of the packet that "generated" this error (or 0 if nothing did).
void ClientConnection::send_error_packet(const char * error_message, const char * sql_state_string,
                                         int packet_sequence_number) {
  ErrorPacket * packet = new ErrorPacket;
  packet->data.sequence_number = packet_sequence_number;
  if(sql_state_string) {
    strncpy(packet->sql_state, sql_state_string, 5);
    packet->sql_state[5] = '\0';
  }
  else
    strcpy(packet->sql_state, "00000");
  strncpy(packet->error_message, error_message, sizeof(packet->error_message));
  packet->error_message[sizeof(packet->error_message)-1] = '\0';
  synthesize_and_send_packet(packet);
  delete packet;
}


void ClientConnection::send_ok_packet(int packet_sequence_number) {
  OKPacket * packet = new OKPacket;
  uint16_t status_flags = 0;

  // TODO: support SF_SERVER_STATUS_IN_TRANS_READONLY here too.
  status_flags |= SF_SERVER_STATUS_AUTOCOMMIT;
  if(in_transaction)
    status_flags |= SF_SERVER_STATUS_IN_TRANS;
  
  packet->data.sequence_number = packet_sequence_number;
  packet->capability_flags = capability_flags;
  packet->affected_rows = 0;
  packet->last_insert_id = 0;
  packet->status_flags = status_flags;
  packet->warning_count = 0;
  strcpy(packet->readable_status_info, "");
  strcpy(packet->session_state_change_info, "");
  synthesize_and_send_packet(packet);
  delete packet;
}


// Generate a 20-byte challenge string for the MySQL "Secure Authentication" handshake.
// The challenge string will be stored into the 'secure_auth_challenge' instance variable.
// http://dev.mysql.com/doc/internals/en/secure-password-authentication.html#packet-Authentication::Native41
void ClientConnection::generate_secure_auth_challenge() {
  // Fill in the challenge with random alphanumeric characters [a-zA-Z0-9].
  // Strictly speaking, we should be able to use any binary values here,
  // but this keeps it legible in case we need to debug.
  loopi(SHA1_DIGEST_LENGTH) {
    int value = random() % 62;  // 26 uppercase, 26 lowercase, 10 digits
    uint8_t ch;
    if(value < 26) ch = 'a' + value;
    else if(value < 52) ch = 'A' + (value - 26);
    else ch = '0' + (value - 52);
    secure_auth_challenge[i] = (uint8_t)ch;
  }
  secure_auth_challenge[SHA1_DIGEST_LENGTH] = '\0';
}


// This is a notification that all buffered data has been sent to the client.
void ClientConnection::write_buffer_is_empty() {
  if(close_when_output_finishes)
    close();
}


// We have received an authentication handshake response packet from the client.
// Currently, we just always treat the authentication as valid.  If the client requested
// a particular database schema in the handshake response, select it now.
// A response packet will be sent to the client:
//   - valid schema (or no explicit schema) requested: OK packet
//   - invalid schema requested: Error packet
void ClientConnection::handle_handshake_response_41_packet(HandshakeResponse41Packet * packet) {
  // Record the capability flags from the client's handshake.
  capability_flags = packet->capability_flags;

  // If the client has specified an initial schema in the handshake response,
  // use that; otherwise use the default schema.
  const char * schema_name;
  if(packet->database_name && strlen(packet->database_name) > 0)
    schema_name = packet->database_name;
  else schema_name = global_config->default_apparent_database_name;

  // Select and authenticate against the requested initial schema.
  // NOTE: select_schema() sends an OK or Error packet back to the client.
  log_debug_message("%s has requested schema \"%s\" via handshake", description_string(), schema_name);
  bool auth_result =
    select_schema(schema_name, packet->username,
                  packet->auth_response, packet->data.sequence_number + 1);
  if(!auth_result)
    return;  // Abort handshake; client has been sent an error and will be closed.

  // Authentication and schema selection were successful.
  // We're now ready to handle real traffic for this client.
  switch_to_ready_state();
  start_accepting_input();
}


void ClientConnection::handle_query_packet(QueryPacket * packet) {
  if(state != CONNECTION_STATE_READY) {
    // This shouldn't happen unless the client is broken.
    log_error_message("Received query packet from %s when not in READY state.",
                      description_string());
    return;
  }

  {
    char buf[250] = "";
    loopi((int)packet->query_string_length) {
      if((size_t)i < sizeof(buf)-1) {
        buf[i] = packet->query_string[i];
        buf[i+1] = '\0';
      }
    }
    log_debug_message("%s query: \"%s\"", description_string(), buf);
  }

  start_database_query(packet, CONNECTION_STATE_WAITING_FOR_QUERY_RESPONSE,
                       EXPECTING_RESULTSET_HEADER);
}


void ClientConnection::handle_quit_packet(QuitPacket * packet) {
  // NOTE: we don't actually call close() on the connection yet; just flag it
  // as close_when_output_finishes.  This is because we are in the middle of
  // the input handling loop, and closing actually deletes the connection object.
  // The input handling loop will check the close_when_output_finishes flag itself
  // once the input buffer has been pumped.
  log_debug_message("Received QUIT packet from %s.", description_string());
  close_when_output_finishes = true;
}


// MySQL clients can use this to select the initial database schema they want to connect to.
// The proxy intercepts this and converts the requested schema to an internal ConnectionPool.
// NOTE: The "preferred" way is to specify the schema in the Handshake Response instead of
// using an InitDB packet.
void ClientConnection::handle_init_db_packet(InitDBPacket * packet) {
  log_debug_message("%s has requested schema \"%s\" via an InitDB packet",
                    description_string(), packet->schema_name);

  // If require_client_auth is configured, the proxy doesn't allow the client to switch
  // their schema at runtime once connected.  The initial schema has to be selected by the
  // client in the handshake response.
  if(global_config->require_client_auth) {
    // TODO: not really sure what the right error code for this is
    send_error_packet("Can't switch schemas at runtime with this proxy.", "42000",
                      packet->data.sequence_number + 1);
  }
  else
    select_schema(packet->schema_name, "", 0, packet->data.sequence_number + 1);
}


// This is treated similarly to a normal Query packet except that we
// expect a list of Field List Response packets terminated by an EOF packet.
// http://dev.mysql.com/doc/internals/en/com-field-list.html
void ClientConnection::handle_field_list_request_packet(FieldListRequestPacket * packet) {
  if(state != CONNECTION_STATE_READY) {
    log_error_message("Received field list request packet from %s when not in ready state.",
                      description_string());
    return;
  }

  start_database_query(packet, CONNECTION_STATE_WAITING_FOR_FIELD_LIST_RESPONSE,
                       EXPECTING_FIELD_LIST_RESPONSE);
}


// Respond to client PING packets directly from the proxy, without forwarding
// the ping to the backend database.
void ClientConnection::handle_ping_packet(PingPacket * packet) {
  send_ok_packet(packet->data.sequence_number + 1);
}


// Send the client a reply that mimics a native MySQL statistics response,
// but with stats values from the proxy.
// TODO: Try to fill this out with real info eventually.
void ClientConnection::handle_statistics_packet(StatisticsPacket * packet) {
  char buf[1000];
  snprintf(buf, sizeof(buf),
           "Uptime: %lu  Threads: %d  Questions: %lu  "
           "Slow queries: %llu  Opens: %llu  Flush tables: %lu  "
           "Open tables: %u  Queries per second avg: %u.%03u",
           (unsigned long)0, (int)0, (unsigned long)0,
           (unsigned long long)0, (unsigned long long)0, (unsigned long)0,
           (unsigned int)0, (unsigned int)0, (unsigned int)0);

  // The reply here isn't a real packet, it's just a "raw" packet with the
  // statistics string as the payload.
  PacketData packet_data;
  packet_data.data = (uint8_t *)buf;
  packet_data.length = strlen(buf) + 1;
  packet_data.sequence_number = packet->data.sequence_number + 1;
  send_packet_data(packet_data);
}


// http://dev.mysql.com/doc/internals/en/com-shutdown.html
// For now, we don't allow this from the proxy.  The client will just be sent an
// error packet.  In the future we may want to allow this to initiate the clean
// shutdown process in the proxy if given the right shutdown_type.
void ClientConnection::handle_shutdown_packet(ShutdownPacket * packet) {
  send_error_packet("Shutdown not allowed via proxy.", "42000",
                    packet->data.sequence_number + 1);
}


// http://dev.mysql.com/doc/internals/en/com-refresh.html
// For now just ignore these and send an OK packet back to the client.
// In the future, we may want to intercept this to forward the refresh
// command on to ALL backend database connections in the client's pool.
void ClientConnection::handle_refresh_packet(RefreshPacket * packet) {
  send_ok_packet(packet->data.sequence_number + 1);
}


// Various "unsupported" and obsolete packet types.  Just respond with an Error packet.
void ClientConnection::handle_unsupported_packet(UnsupportedPacket * packet) {
  char buf[100];
  snprintf(buf, sizeof(buf), "Unsupported packet type %d", (int)packet->packet_type);
  send_error_packet(buf, 0, packet->data.sequence_number + 1);
}


// A client is trying to authenticate against the given backend connection pool
// with a username and auth challenge response string.  Returns true if authentication
// suceeds, false if not.
bool ClientConnection::check_client_authentication(const ConnectionPool * pool,
                                                   const char * username,
                                                   uint8_t secure_auth_challenge_response[SHA1_DIGEST_LENGTH+1]) const {
  // If client authentication is not configured, "authentication" always succeeds.
  if(!global_config->require_client_auth)
    return true;

  // Make sure the username matches what is expected.
  if(strcmp(username, pool->config->username) != 0)
    return false;

  // Check the auth challenge response.  Note that the proxy-generated random auth challenge
  // string has already been stored in this->secure_auth_challenge.
  uint8_t expected_challenge_response[SHA1_DIGEST_LENGTH+1];
  DatabaseConnection::
    compute_mysql_native_password(expected_challenge_response, secure_auth_challenge,
                                  (const uint8_t *)pool->config->password);

  if(memcmp(expected_challenge_response, secure_auth_challenge_response, SHA1_DIGEST_LENGTH) != 0)
    return false;

  // Everything has checked out.
  return true;
}


// Switch the client to the requested 'schema' (i.e., database connection pool), if it exists.
// If the 'require_client_auth' flag has been specified in the config file, also validate the given
// secure_auth_challenge_response against the configured password for the requested schema.
// Returns true on success or false on failure.  An OK or Error packet will be sent back to the
// client using the given packet_sequence_number depending on the results.
bool ClientConnection::select_schema(const char * schema_name,
                                     const char * username,
                                     uint8_t secure_auth_challenge_response[SHA1_DIGEST_LENGTH+1],
                                     int packet_sequence_number) {
  // Try to find a DB pool that matches the database name the client wants.
  // Note that the client "sees" the apparent_database_name, while the
  // actual backend connections use the actual_database_name.  The proxy
  // maps between the two.  This is mainly done to support the case where
  // we have databases with the same database name but on different servers
  // (e.g. sharded databases).
  ConnectionPool * new_pool = current_server->
    find_connection_pool_with_apparent_database_name(schema_name);

  if(!new_pool) {
    // No pool found with this name.
    char buf[256];
    snprintf(buf, sizeof(buf), "Unknown database '%s'", schema_name);
    close_when_output_finishes = true;
    send_error_packet(buf, "42000", packet_sequence_number);
    return false;
  }

  // Check authentication.
  if(!check_client_authentication(new_pool, username, secure_auth_challenge_response)) {
    char buf[256];
    snprintf(buf, sizeof(buf), "Access denied for user '%s' and schema '%s'",
             username, schema_name);
    close_when_output_finishes = true;
    send_error_packet(buf, "42000", packet_sequence_number);
    log_message("%s failed authentication.", description_string());
    return false;
  }
  
  // Schema selection succeeded; send an OKPacket to the client.
  pool = new_pool;
  update_description();  // Changing the pool can change the connection description string.
  send_ok_packet(packet_sequence_number);
  
  return true;
}


// Acquire a database connection lease (if we don't have one already) and send the
// given packet to the database.  If we were able to send the packet immediately,
// switch into new_state.  We'll expect a response from the database of the type
// given by expected_packet_type.
void ClientConnection::start_database_query(Packet * packet, ConnectionState new_state,
                                            ExpectedPacketType expected_packet_type) {
  // Record query start time.
  gettimeofday(&query_timings.query_received_from_client, 0);
  
  // Try to get a DB connection lease if we don't have one already.
  DatabaseConnection * db_connection = currently_leased_database_connection;
  if(!db_connection)
    db_connection = pool->lease_connection_for_client(this);
  if(db_connection) {
    time_t current_time = time(0);

    // Record lease acquisition time for benchmarking.
    gettimeofday(&query_timings.lease_acquired, 0);
    
    // Record activity time for timeout purposes.
    lease_last_activity_time = current_time;
    
    // Forward the query packet to the DB connection, and record the time at which
    // the query was sent so that we can monitor for query timeouts on the database backend.
    db_connection->last_query_sent_at_time = current_time;
    db_connection->send_packet(packet);

    // Switch to the new state and start expecting the specified type of packets
    // from the database.
    // TODO: I don't like how this is duplicating the states between database and client connections.
    state = new_state;
    db_connection->state = new_state;
    db_connection->expected_packet_type = expected_packet_type;
  }
  else
    pool->add_pending_lease_request(this, packet);

  // Stop processing packets from the client until we get a response from the database.
  stop_accepting_input();
}


// The query_timings structure has been completely filled in now; do something with it.
void ClientConnection::record_query_timings() {
  struct timeval lease_wait_time, db_response_time, result_read_time, total_query_time;

  // Calculate the various intervals we want to report.
  timeval_subtract(&lease_wait_time, &query_timings.lease_acquired, &query_timings.query_received_from_client);
  timeval_subtract(&db_response_time, &query_timings.response_started_from_database, &query_timings.lease_acquired);
  timeval_subtract(&result_read_time, &query_timings.query_finished, &query_timings.response_started_from_database);
  timeval_subtract(&total_query_time, &query_timings.query_finished, &query_timings.query_received_from_client);

  // Accumulate the timings into the stats of the connection pool this
  // query was a part of.
  if(pool) {  // should always be true
    pool->stats.total_query_time += timeval_seconds(&total_query_time);
    pool->stats.lease_wait_time += timeval_seconds(&lease_wait_time);
    pool->stats.database_wait_time += timeval_seconds(&db_response_time);
    pool->stats.query_result_read_time += timeval_seconds(&result_read_time);
  }

  // log_debug_message("%s query timings: total=%0.3fs lease_wait=%0.3fs response_wait=%0.3fs result_read=%0.3fs",
  //                   description_string(),
  //                   timeval_seconds(&total_query_time), timeval_seconds(&lease_wait_time),
  //                   timeval_seconds(&db_response_time), timeval_seconds(&result_read_time));
}

