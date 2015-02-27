

enum ConnectionLeaseState {
  // Database backend has not yet been established and cannot be checked
  // out for use by clients.
  LEASE_STATE_UNAVAILABLE,
  
  // Database connection is "idle" and available for client leases.
  LEASE_STATE_AVAILABLE,

  // Database connection has been leased to a client connection.
  LEASE_STATE_IN_USE,

  // Database leases are temporarily suspended for this connection.
  // Currently this is used to implement 'simulate_busy_dbs' config option.
  LEASE_STATE_SUSPENDED
};


// Summary of an in-progress result set being read from the database.
class ResultSet {
public:
  uint64_t field_count;
  uint32_t row_count;

  // SF_SERVER_STATUS_* flags from the EOF packet received after the row data, if available
  uint32_t status_flags;

public:
  void reset() {
    field_count = 0;
    status_flags = 0;
    row_count = 0;
  }
};


// DatabaseConnection represents a network connection made from the proxy to a
// backend MySQL server.
class DatabaseConnection : public Connection {
public:
  // Index of this connection within our pool; 0...pool_size-1
  int connection_index;

  // Time at which we started the nonblocking connect() call.
  struct timeval connect_started_at_time;

  // Number of consecutive connection failures (connect timeouts, DNS errors, etc)
  // that we have seen for this database connection while it is trying to be established.
  // If this connection is established, this will be zero even if there were initially
  // errors trying to connect.
  int consecutive_connection_failures;

  // Time at which the most recent query packet was sent to the database backend.
  time_t last_query_sent_at_time;

  // Summary of the current resultset we are reading, if any.
  ResultSet current_result_set;

  // Connection lease state fields:
  ConnectionLeaseState lease_state;
  ClientConnection * leasing_client_connection;  // client connection which currently "owns" this lease, if any

public:
  // Lifecycle methods:
  DatabaseConnection();
  virtual ~DatabaseConnection();
  
  void perform_periodic_maintenance();
  void start_resolving_dns_for_connect();
  void start_connecting_to_remote_address();
  virtual void connection_established();
  virtual void remote_closed_connection();
  double seconds_since_connect_started();
  void close_if_connect_timeout_exceeded();
  void close_if_maximum_lifetime_exceeded();
  void close_if_query_timeout_exceeded();
  void close();

  // Utility methods:
  static void compute_mysql_native_password(uint8_t dest[SHA1_DIGEST_LENGTH + 1],
                                            const uint8_t random_data_from_server[SHA1_DIGEST_LENGTH + 1],
                                            const uint8_t * plaintext_password);

  // Testing support methods:
  void start_suspending_connection();
  void stop_suspending_connection();

  // Output-handling methods:
  virtual void record_outgoing_network_traffic(size_t bytes);
  void send_quit_packet();
  void send_query_string(const char * query_string);
  void forward_packet_data(PacketData packet_data);
  void finish_forwarding_query_to_client(bool in_transaction, bool more_results_exists);

  // Input-handling methods:
  virtual void input_has_been_processed() {}
  virtual void record_incoming_network_traffic(size_t bytes);
  virtual void handle_resultset_header(PacketData packet_data);
  virtual void handle_resultset_field_description(PacketData packet_data);
  virtual void handle_resultset_row(PacketData packet_data);
  virtual void handle_field_list_response(PacketData packet_data);
  virtual void handle_handshake_v10_packet(HandshakeV10Packet * packet);
  virtual void handle_handshake_response_41_packet(HandshakeResponse41Packet * packet) { not_yet_implemented(); }
  virtual void handle_ok_packet(OKPacket * packet);
  void handle_ok_packet_while_authenticating(const OKPacket * packet);
  virtual void handle_error_packet(ErrorPacket * packet);
  void handle_error_packet_while_waiting_for_handshake(ErrorPacket * packet);
  void handle_error_packet_while_authenticating(ErrorPacket * packet);
  virtual void handle_eof_packet(EOFPacket * packet) {}
  virtual void handle_query_packet(QueryPacket * packet) { not_yet_implemented(); }
  virtual void handle_quit_packet(QuitPacket * packet) { not_yet_implemented(); }
  virtual void handle_init_db_packet(InitDBPacket * packet) { not_yet_implemented(); }
  virtual void handle_field_list_request_packet(FieldListRequestPacket * packet) { not_yet_implemented(); }
  virtual void handle_ping_packet(PingPacket * packet) { not_yet_implemented(); }
  virtual void handle_statistics_packet(StatisticsPacket * packet) { not_yet_implemented(); }
  virtual void handle_shutdown_packet(ShutdownPacket * packet) { not_yet_implemented(); }
  virtual void handle_refresh_packet(RefreshPacket * packet) { not_yet_implemented(); }
  virtual void handle_unsupported_packet(UnsupportedPacket * packet) { not_yet_implemented(); }
};

