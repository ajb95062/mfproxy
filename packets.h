

// Packets in the MySQL protocol.
// See: http://dev.mysql.com/doc/internals/en/client-server-protocol.html
//
// The main structures here are:
//   - PacketData, which represents an complete, unparsed packet from the data stream.
//   - Packet and subclasses, which can be "parsed" from PacketData and have a definite type.
//
// The MySQL protocol is a little wonky with some historical baggage so sometimes we need
// to jump through hoops to figure out what type each packet is; sometimes it depends on the
// exact point we are at inside the MySQL protocol.


// This represents a raw packet header plus payload.
// 'data' points to a buffer of exactly 'length' bytes.
struct PacketData {
  uint8_t * data;
  uint32_t length;
  int sequence_number;

public:
  PacketData() : data(0), length(0), sequence_number(0) {}

  // NOTE: Do not free *data in a ~PacketData() destructor.
  // We need to manage the memory explicitly via release_memory();
  // doing it in the destructor will cause problems.  For example,
  // PacketDataWithLink embeds a PacketData and we may want to delete
  // the link itself without necessarily freeing the referenced data buffer.

  void debug_print() const;
  void release_memory();
  Packet * create_packet() const;

  // Peek at the packet data to see whether it's an "OK" packet.
  bool looks_like_ok_packet() const { return data[0] == 0x00; }

  // Peek at the packet data to see whether it's an EOF packet.
  bool looks_like_eof_packet() const {
    return data[0] == 0xfe && length < 9;
    
    // NOTE: the length < 9 check is from this:
    //   http://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
    // which states:
    //   The EOF packet may appear in places where a Protocol::LengthEncodedInteger may appear.
    //   You must check whether the packet length is less than 9 to make sure that it is a EOF packet.
  }

  // Peek at the packet data to see whether it's an ERR packet.
  bool looks_like_err_packet() const { return data[0] == 0xff; }
};


// This is for when we need to string together multiple PacketDatas into a linked list.
// Currently this is used by PendingLeaseRequest to buffer up incoming packet data while
// a client is waiting for a database connection.
struct PacketDataWithLink {
  PacketData data;
  PacketDataWithLink * next;

public:
  PacketDataWithLink();
  ~PacketDataWithLink();
};


// Classes for all MySQL packet formats.
// Packet objects work one of two ways, depending on whether they're incoming or outgoing.
//
// Incoming packets:
// The binary packet payload is loaded into the 'data' field.  A call to extract_packet_fields()
// is made, which scans the payload and extracts fields into instance variables.  For things like
// string fields, this may create internal pointers into the data buffer.
//
// Outgoing (synthesized) packets:
// Initially, the 'data' field is null.  To synthesize an outgoing packet, fill in the
// packet fields (other than 'data', and 'packet_length'), then call synthesize_packet_payload().


// Abstract superclass for all MySQL packet types.
class Packet {
public:
  PacketData data;  // the raw packet payload

  // If this is set to true, it means that the packet has been placed into a pending
  // queue as part of a PendingLeaseRequest object.  That means that the packet should
  // not be deleted as part of the normal packet lifecycle.  Instead, the PendingLeaseRequest
  // system will be responsible for cleaning up the packet eventually.
  bool is_pending;

public:
  static void print_capability_flags(uint32_t capability_flags, FILE * output);
  static void print_bytes_as_hex(const uint8_t * data, size_t byte_count, FILE * output, const char * label = 0);

  Packet();
  virtual ~Packet();
  
  virtual const char * packet_type_name() const { return "Unknown"; }
  virtual void print_fields(FILE * output) {}
  virtual void extract_packet_fields() = 0;
  virtual void synthesize_packet_payload(BinaryEncoder * encoder) = 0;
  virtual void handle_by_connection(Connection * connection) = 0;
};

  
// http://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
class ErrorPacket : public Packet {
public:
  uint16_t error_code;
  char sql_state[10];
  char error_message[256];

public:
  virtual const char * packet_type_name() const { return "Error"; }
  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields();
};


// http://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
class OKPacket : public Packet {
public:
  uint32_t capability_flags;
  uint64_t affected_rows;
  uint64_t last_insert_id;
  uint16_t status_flags;
  uint16_t warning_count;
  char readable_status_info[256];
  char session_state_change_info[256];
  
public:
  virtual const char * packet_type_name() const { return "OK"; }
  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields();

  bool is_in_transaction() const;
  bool more_results_exists() const;
};


// http://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
class EOFPacket : public Packet {
public:
  uint16_t warning_count;
  uint16_t status_flags;

public:
  virtual const char * packet_type_name() const { return "EOF"; }
  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields();

  bool is_in_transaction() const;
  bool more_results_exists() const;
};


class HandshakeV10Packet : public Packet {
public:
  const char * server_version;
  uint8_t character_set;
  uint32_t connection_id;
  uint32_t capability_flags;
  uint32_t status_flags;
  uint8_t auth_plugin_data[50];  // max length is something like 24
  const char * auth_plugin_name;
  size_t auth_plugin_data_length;

public:
  virtual const char * packet_type_name() const { return "Handshake v10"; }
  virtual void print_fields(FILE * output);
  virtual void extract_packet_fields();
  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
};


// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse41
class HandshakeResponse41Packet : public Packet {
public:
  uint32_t capability_flags;
  uint32_t max_packet_size;
  uint8_t character_set;
  const char * username;
  uint8_t auth_response[256];  // must be >= 256
  uint64_t auth_response_length;  // length of auth_response in bytes (not including NUL terminator)
  const char * database_name;
  const char * auth_plugin_name;

  int attributes_count;  // number of elements in attribute_keys / attribute_values
  char ** attribute_keys;
  char ** attribute_values;

public:
  virtual const char * packet_type_name() const { return "Handshake Response v41"; }
  virtual void extract_packet_fields();
  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
};


// http://dev.mysql.com/doc/internals/en/com-query.html  
class QueryPacket : public Packet {
public:
  const char * query_string;  // NOTE: not necessary NUL-terminated; use the length field
  size_t query_string_length;

public:
  // helper method for is_begin_transaction_query() and related methods
  /*  static bool match_query_string(const char * query_string, size_t query_string_length,
                                 const char * search_string,
                                 char ** new_query_string_ptr = 0, size_t * new_query_string_length_ptr = 0); */
  
public:
  virtual const char * packet_type_name() const { return "Query"; }

  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields();
};


// http://dev.mysql.com/doc/internals/en/com-quit.html
class QuitPacket : public Packet {
public:
  virtual const char * packet_type_name() const { return "Quit"; }

  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields() {}
};


// Change the default schema of the connection
// http://dev.mysql.com/doc/internals/en/com-init-db.html
class InitDBPacket : public Packet {
public:
  char schema_name[256];
  
public:
  virtual const char * packet_type_name() const { return "InitDB"; }

  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields();
};


// Get the column definitions of a table
// http://dev.mysql.com/doc/internals/en/com-field-list.html
// NOTE: The proxy could intercept these to implement field info caching.
class FieldListRequestPacket : public Packet {
public:
  char * table_name;
  char field_wildcard[256];

public:
  virtual const char * packet_type_name() const { return "FieldListRequest"; }

  virtual void synthesize_packet_payload(BinaryEncoder * encoder) { not_yet_implemented(); }
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields();
};


// http://dev.mysql.com/doc/internals/en/com-ping.html
class PingPacket : public Packet {
public:
  virtual const char * packet_type_name() const { return "Ping"; }
  
  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields() {}
};


// http://dev.mysql.com/doc/internals/en/com-statistics.html
class StatisticsPacket : public Packet {
public:
  virtual const char * packet_type_name() const { return "Statistics"; }

  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields() {}
};


// http://dev.mysql.com/doc/internals/en/com-shutdown.html
class ShutdownPacket : public Packet {
public:
  uint8_t shutdown_type;
  
public:
  virtual const char * packet_type_name() const { return "Shutdown"; }

  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields();
};


// http://dev.mysql.com/doc/internals/en/com-refresh.html
class RefreshPacket : public Packet {
public:
  uint8_t subcommand;

public:
  virtual const char * packet_type_name() const { return "Refresh"; }

  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields();
};


// These represent unsupported and/or obsolete packets in the MySQL protocol.
// Even the MySQL engine itself doesn't support some of these packet types
// and when one arrives at the proxy we just respond with an Error packet.
//   COM_CREATE_DB
//   COM_DROP_DB
//   COM_DEBUG
//   COM_PROCESS_INFO
//   COM_SLEEP
//   COM_TIME
//   COM_DELAYED_INSERT
class UnsupportedPacket : public Packet {
public:
  uint8_t packet_type;

public:
  virtual const char * packet_type_name() const { return "Unsupported"; }

  virtual void synthesize_packet_payload(BinaryEncoder * encoder);
  virtual void handle_by_connection(Connection * connection);
  virtual void extract_packet_fields();
};
