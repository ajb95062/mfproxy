

// TODO: maybe split this into separate ClientConnectionState and DatabaseConnectionState enums
enum ConnectionState {
  // Initial state; no connection has been made to the backend database yet.
  CONNECTION_STATE_UNCONNECTED = 0,

  // Waiting for async DNS resolution to complete.
  CONNECTION_STATE_WAITING_FOR_DNS,

  // Socket to database is being established.
  CONNECTION_STATE_CONNECTING,

  // Socket is connected; we are waiting for the DB to send a handshake packet.
  CONNECTION_STATE_WAITING_FOR_HANDSHAKE,

  // For connections to the database:
  //   Handshake packet has been received and we have sent the authentication packet
  //   in response.  Waiting for the server to send an OK packet in response.
  // For client connections to the proxy:
  //   Handshake packet has been sent to the client.  We are waiting for the client
  //   to respond with a handshake response packet.
  CONNECTION_STATE_AUTHENTICATING,

  // Authentication and DB selection was successful and we are ready to send commands.
  // This is the usual state for an established, but idle, connection.
  CONNECTION_STATE_READY,

  // A query has been sent and we're waiting for a response.
  CONNECTION_STATE_WAITING_FOR_QUERY_RESPONSE,

  // A field list request packet has been sent and we're waiting for a response.
  CONNECTION_STATE_WAITING_FOR_FIELD_LIST_RESPONSE
};


// TODO: maybe merge this enum with ConnectionState?
enum ExpectedPacketType {
  // We're expecting a "normal" packet with a 1-byte typecode field to arrive.
  EXPECTING_PACKET_WITH_TYPE_CODE = 1,

  // We're expecting a Handshake packet in response to an initial connection event.
  // Since the HandshakeV10 packet type code conflicts with the "ordinary" COM_PROCESS_INFO
  // packet structure (both start with 0x0a), we have to handle this specially.
  EXPECTING_HANDSHAKE,

  // We're expecting a Handshake Response packet (no typecode field), in response
  // to a previously-sent Handshake packet.
  EXPECTING_HANDSHAKE_RESPONSE,

  // We're expecting a Result Set header packet in response to a previously-sent Query packet.
  // This can be one of:
  //   - OK packet
  //   - ERR packet
  //   - pseudo-packet with the number of columns
  EXPECTING_RESULTSET_HEADER,

  // Expecting either ResultSet field descriptions, or a terminating EOF packet.
  EXPECTING_RESULTSET_FIELD_DESCRIPTIONS,

  // Expecting rows of data, or a terminating EOF packet.  
  EXPECTING_RESULTSET_ROWS,

  // Expecting a list of field descriptions, or a terminating EOF packet.
  EXPECTING_FIELD_LIST_RESPONSE
};


class Connection {
public:
  evutil_socket_t socket_fd;
  struct sockaddr_in remote_address;
  struct bufferevent * bufferevent;

  // Descriptive string to label this connection in log messages, etc.
  const char * description;

  ConnectionState state;

  // Time at which the connection's network socket was established/connected.
  // This is zero initially, and set to the current time upon successful socket connection.
  time_t established_at_time;

  // If this is true, the connection is scheduled to be closed and deleted as soon
  // as possible.  For example, if a client disconnects in the middle of a database
  // interaction, it will be placed into this state while the database finishes up
  // whatever it was doing.
  bool is_closing;

  // DB connection pool this connection is associated with.
  // For client connections, it's based on the database they select when they connect
  // (either as part of the handshake, or later via an InitDB packet or USE query).
  // For database connections, it's the connection pool the DB connection belongs to.
  ConnectionPool * pool;

  // For connections to the backend database, this is the connection_id given to us by the MySQL server.
  // For client connections to the proxy, this is a connection_id we assign.
  uint32_t connection_id;

  // Depending on the part of the MySQL protocol we're currently handling, we may receive packets
  // of different types.  We have to track what we are expecting explicitly, since due to quirks
  // of the protocol we can't always tell what kind of packet it is just by looking at the packet
  // payload.  For example, field list description "packets" don't have a packet type byte - the only
  // way to know what to expect is knowing that we will get these immediately after a query is sent
  // to the database.
  ExpectedPacketType expected_packet_type;

  // If true, we are in the process of reading the packet body (and expected_packet_length is populated).
  // If false, we are waiting for the 4-byte packet length header.
  bool reading_packet_body;

  // If reading_packet_body is true, these are the packet length and sequence number fields
  // that have already been read from the packet header.
  uint32_t expected_packet_length;  // this length excludes the 4 byte header itself
  int decoded_packet_sequence_number;

  // TODO: last_activity_at timestamp

public:
  // Lifecycle methods:
  Connection();
  virtual ~Connection();
  virtual void connection_established() = 0;
  virtual void remote_closed_connection() = 0;
  void create_bufferevent();

  // Utility methods:
  virtual const char * description_string() const;
  void set_description_string(const char * new_string);
  void switch_to_ready_state();

  // Output-handling methods:
  void synthesize_and_send_packet(Packet * packet);
  void send_packet(const Packet * packet) { send_packet_data(packet->data); }
  void send_packet_data(PacketData packet_data);
  virtual void record_outgoing_network_traffic(size_t bytes) = 0;
  virtual void write_buffer_is_empty() {}

  // Input-handling methods:
  void process_input();
  virtual void input_has_been_processed() = 0;
  virtual void record_incoming_network_traffic(size_t bytes) = 0;
  virtual void handle_received_packet_data(PacketData packet_data);
  void handle_packet(Packet * packet);
  void handle_unexpected_packet_data(PacketData packet_data);
  virtual void handle_handshake_response(PacketData packet_data);
  virtual void handle_resultset_header(PacketData packet_data) = 0;
  virtual void handle_resultset_field_description(PacketData packet_data) = 0;
  virtual void handle_resultset_row(PacketData packet_data) = 0;
  virtual void handle_field_list_response(PacketData packet_data) = 0;
  virtual void handle_handshake_v10_packet(HandshakeV10Packet * packet) = 0;
  virtual void handle_handshake_response_41_packet(HandshakeResponse41Packet * packet) = 0;
  virtual void handle_ok_packet(OKPacket * packet) = 0;
  virtual void handle_error_packet(ErrorPacket * packet) = 0;
  virtual void handle_eof_packet(EOFPacket * packet) = 0;
  virtual void handle_query_packet(QueryPacket * packet) = 0;
  virtual void handle_quit_packet(QuitPacket * packet) = 0;
  virtual void handle_init_db_packet(InitDBPacket * packet) = 0;
  virtual void handle_field_list_request_packet(FieldListRequestPacket * packet) = 0;
  virtual void handle_ping_packet(PingPacket * packet) = 0;
  virtual void handle_statistics_packet(StatisticsPacket * packet) = 0;
  virtual void handle_shutdown_packet(ShutdownPacket * packet) = 0;
  virtual void handle_refresh_packet(RefreshPacket * packet) = 0;
  virtual void handle_unsupported_packet(UnsupportedPacket * packet) = 0;
};

