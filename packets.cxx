

#include "main.h"


void PacketData::debug_print() const {
  fprintf(stderr, "*** Packet length=%d, sequence_number=%d\n",
          (int)length, (int)sequence_number);
  Packet::print_bytes_as_hex(data, length, stderr, "Packet payload");
}


void PacketData::release_memory() {
  if(data) {
    current_server->allocation_stats.packet_data_bytes -= length;
    delete [] data;
    data = 0;
  }
}


// Allocate a new Packet and inspect the first byte of the payload to determine
// the packet type.  The return value will be one of the Packet subclasses.
// If the packet type is invalid or unsupported, NULL will be returned here.
Packet * PacketData::create_packet() const {
  Packet * packet;

  if(length == 0) return 0;  // shouldn't happen
  switch(data[0]) {
  case 0x00: packet = new OKPacket; break;
  case 0x01: packet = new QuitPacket; break;
  case 0x02: packet = new InitDBPacket; break;
  case 0x03: packet = new QueryPacket; break;
  case 0x04: packet = new FieldListRequestPacket; break;
  case 0x05: packet = new HandshakeResponse41Packet; break;
  case 0x07: packet = new RefreshPacket; break;
  case 0x08: packet = new ShutdownPacket; break;
  case 0x09: packet = new StatisticsPacket; break;
  case 0x0e: packet = new PingPacket; break;
  case 0xfe: packet = new EOFPacket; break;
  case 0xff: packet = new ErrorPacket; break;
  default:   packet = new UnsupportedPacket; break;
  }

  packet->data = *this;
  return packet;
}


PacketDataWithLink::PacketDataWithLink() {
  current_server->allocation_stats.packet_data_links++;
}


PacketDataWithLink::~PacketDataWithLink() {
  current_server->allocation_stats.packet_data_links--;
}


// Diagnostic method; print a readable interpretation of capability_flags.
void Packet::print_capability_flags(uint32_t capability_flags, FILE * output) {
  static const struct {
    uint32_t flag_value;
    const char * description;
  } flag_info[] = {
    { CF_CLIENT_LONG_PASSWORD, "LONG_PASSWORD" },
    { CF_CLIENT_FOUND_ROWS, "FOUND_ROWS" },
    { CF_CLIENT_LONG_FLAG, "LONG_FLAG" },
    { CF_CLIENT_CONNECT_WITH_DB, "CONNECT_WITH_DB" },
    { CF_CLIENT_NO_SCHEMA, "NO_SCHEMA" },
    { CF_CLIENT_COMPRESS, "COMPRESS" },
    { CF_CLIENT_ODBC, "ODBC" },
    { CF_CLIENT_LOCAL_FILES, "LOCAL_FILES" },
    { CF_CLIENT_IGNORE_SPACE, "IGNORE_SPACE" },
    { CF_CLIENT_PROTOCOL_41, "PROTOCOL_41" },
    { CF_CLIENT_INTERACTIVE, "INTERACTIVE" },
    { CF_CLIENT_SSL, "SSL" },
    { CF_CLIENT_IGNORE_SIGPIPE, "IGNORE_SIGPIPE" },
    { CF_CLIENT_TRANSACTIONS, "TRANSACTIONS" },
    { CF_CLIENT_RESERVED, "RESERVED" },
    { CF_CLIENT_SECURE_CONNECTION, "SECURE_CONNECTION" },
    { CF_CLIENT_MULTI_STATEMENTS, "MULTI_STATEMENTS" },
    { CF_CLIENT_MULTI_RESULTS, "MULTI_RESULTS" },
    { CF_CLIENT_PS_MULTI_RESULTS, "PS_MULTI_RESULTS" },
    { CF_CLIENT_PLUGIN_AUTH, "PLUGIN_AUTH" },
    { CF_CLIENT_CONNECT_ATTRS, "CONNECT_ATTRS" },
    { CF_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, "PLUGIN_AUTH_LENENC_CLIENT_DATA" },
    { CF_CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS, "CAN_HANDLE_EXPIRED_PASSWORDS" },
    { CF_CLIENT_SESSION_TRACK, "SESSION_TRACK" },
    { CF_CLIENT_DEPRECATE_EOF, "DEPRECATE_EOF" },
    { CF_CLIENT_SSL_VERIFY_SERVER_CERT, "SSL_VERIFY_SERVER_CERT" },
    { CF_CLIENT_REMEMBER_OPTIONS, "REMEMBER_OPTIONS" }
  };

  fprintf(output, "  Capability flags hex value: %x\n", (int)capability_flags);
  fprintf(output, "  Flags:");
  loopi((int)arraysize(flag_info))
    if(capability_flags & flag_info[i].flag_value)
      fprintf(output, " %s", flag_info[i].description);
  fprintf(output, "\n");
}


// Debugging method.
void Packet::print_bytes_as_hex(const uint8_t * data, size_t byte_count, FILE * output, const char * label) {
  const int bytes_per_line = 16;

  if(label)
    fprintf(output, "Hex dump: %s\n", label);
  for(unsigned int base_offset = 0; base_offset < byte_count; base_offset += bytes_per_line) {
    fprintf(output, "%04x : ", base_offset);
    loopi(bytes_per_line) {
      unsigned int byte_index = base_offset + i;
      if(byte_index < byte_count) {
        int byte_value = data[byte_index];
        fprintf(output, "%02x ", byte_value);
      }
      else fprintf(output, "   ");
    }
    fprintf(output, "    ");
    loopi(bytes_per_line) {
      unsigned int byte_index = base_offset + i;
      if(byte_index < byte_count) {
        int byte_value = data[byte_index];
        if(isprint(byte_value))
          fputc(byte_value, output);
        else fputc('.', output);
      }
    }
    fprintf(output, "\n");
  }
}


Packet::Packet() {
  is_pending = false;
  current_server->allocation_stats.packets++;
}


Packet::~Packet() {
  data.release_memory();
  current_server->allocation_stats.packets--;
}


void ErrorPacket::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(0xff);
  encoder->write_int2(error_code);

  // if capabilities & CF_CLIENT_PROTOCOL_41 ... assume this is true for now
  encoder->write_byte('#');
  encoder->write_bytes((uint8_t *)sql_state, 5);

  encoder->write_nul_terminated_string(error_message);
}


void ErrorPacket::handle_by_connection(Connection * connection) {
  connection->handle_error_packet(this);
}


void ErrorPacket::extract_packet_fields() {
  BinaryDecoder decoder(data);

  decoder.skip_bytes(1);
  error_code = decoder.read_int2();

  uint8_t sql_state_marker = decoder.read_byte();
  if(sql_state_marker == '#') {
    // This # marker tells us there is a sql_state 5-byte code.
    // Otherwise the error message is just the rest of the packet.
    decoder.read_bytes((uint8_t *)sql_state, 5);
    sql_state[5] = '\0';
  }
  else {
    sql_state[0] = '\0';
    decoder.rewind();
  }
  decoder.copy_remaining_string((uint8_t *)error_message, sizeof(error_message));

  // log_error_message("Error code: %d, SQL state: \"%s\", message: \"%s\"",
  //                   (int)error_code, sql_state, error_message);
}


void OKPacket::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(0x00);
  encoder->write_length_encoded_int(affected_rows);
  encoder->write_length_encoded_int(last_insert_id);
  if(capability_flags & CF_CLIENT_PROTOCOL_41) {
    encoder->write_int2(status_flags);
    encoder->write_int2(warning_count);
  }
  else if(capability_flags & CF_CLIENT_TRANSACTIONS)
    encoder->write_int2(status_flags);

  if(capability_flags & CF_CLIENT_SESSION_TRACK) {
    encoder->write_length_encoded_string(readable_status_info);
    // TODO: what is this flag...
    // if(status_flags & SF_SERVER_SESSION_CHANGED)
    encoder->write_length_encoded_string(session_state_change_info);
  }
  else
    encoder->write_length_encoded_string(readable_status_info);
}


void OKPacket::handle_by_connection(Connection * connection) {
  connection->handle_ok_packet(this);
}


void OKPacket::extract_packet_fields() {
  BinaryDecoder decoder(data);

  decoder.skip_bytes(1);
  affected_rows = decoder.read_length_encoded_int();
  last_insert_id = decoder.read_length_encoded_int();

  // if(capability_flags & CF_CLIENT_PROTOCOL_41)  ... assume it's true for now
  status_flags = decoder.read_int2();
  warning_count = decoder.read_int2();

  if(decoder.has_more_data()) {
    decoder.copy_length_encoded_string((uint8_t *)readable_status_info, sizeof(readable_status_info));
    if(decoder.has_more_data())
      decoder.copy_length_encoded_string((uint8_t *)session_state_change_info, sizeof(session_state_change_info));
    else strcpy(session_state_change_info, "");
  }
}


bool OKPacket::is_in_transaction() const {
  return (status_flags & (SF_SERVER_STATUS_IN_TRANS |
                          SF_SERVER_STATUS_IN_TRANS_READONLY)) != 0;
}


bool OKPacket::more_results_exists() const {
  return (status_flags & SF_SERVER_MORE_RESULTS_EXISTS) != 0;
}


void EOFPacket::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(0xfe);
  encoder->write_int2(warning_count);
  encoder->write_int2(status_flags);
}


void EOFPacket::handle_by_connection(Connection * connection) {
  connection->handle_eof_packet(this);
}


void EOFPacket::extract_packet_fields() {
  BinaryDecoder decoder(data);

  decoder.skip_bytes(1);
  if(decoder.has_more_data())
    warning_count = decoder.read_int2();
  else warning_count = 0;
  if(decoder.has_more_data())
    status_flags = decoder.read_int2();
  else status_flags = 0;
}


bool EOFPacket::is_in_transaction() const {
  return (status_flags & (SF_SERVER_STATUS_IN_TRANS |
                          SF_SERVER_STATUS_IN_TRANS_READONLY)) != 0;
}


bool EOFPacket::more_results_exists() const {
  return (status_flags & SF_SERVER_MORE_RESULTS_EXISTS) != 0;
}


void HandshakeV10Packet::print_fields(FILE * output) {
  fprintf(output,
          "Server version: \"%s\"\n"
          "Character set: %x\n"
          "Connection ID: %d\n"
          "Capability flags: %x\n"
          "Status flags: %x\n"
          "Auth plugin data: \"%s\"\n"
          "Auth plugin name: \"%s\"\n",
          server_version, (unsigned int)character_set, (int)connection_id, (unsigned int)capability_flags,
          (unsigned int)status_flags, auth_plugin_data, auth_plugin_name);
}


void HandshakeV10Packet::extract_packet_fields() {
  BinaryDecoder decoder(data);

  auth_plugin_name = "unavailable";

  decoder.skip_bytes(1);  // protocol version field
  server_version = decoder.read_nul_terminated_string();
  connection_id = decoder.read_int4();
  decoder.read_bytes(auth_plugin_data, 8);
  auth_plugin_data_length = 8;
  decoder.skip_bytes(1);
  capability_flags = decoder.read_int2();

  if(decoder.has_more_data()) {
    character_set = decoder.read_int1();
    status_flags = decoder.read_int2();
    capability_flags |= ((uint32_t)decoder.read_int2()) << 16;
    if(capability_flags & CF_CLIENT_PLUGIN_AUTH)
      auth_plugin_data_length = decoder.read_int1();
    else decoder.skip_bytes(1);
    decoder.skip_bytes(10);
    if(capability_flags & CF_CLIENT_SECURE_CONNECTION) {
      int len = auth_plugin_data_length - 8;
      if(len > 13) len = 13;
      decoder.read_bytes(auth_plugin_data + 8, len);
    }
    if(capability_flags & CF_CLIENT_PLUGIN_AUTH)
      auth_plugin_name = decoder.read_nul_terminated_string();
  }
  else {
    character_set = 0;
    status_flags = 0;
  }
  auth_plugin_data[auth_plugin_data_length] = 0;  // NUL terminate string
}


void HandshakeV10Packet::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(0x0a);
  encoder->write_nul_terminated_string(server_version);
  encoder->write_int4(connection_id);
  encoder->write_bytes(auth_plugin_data, 8);
  encoder->write_zeroes(1);
  encoder->write_int2(capability_flags & 0xffff);
  encoder->write_int1(character_set);
  encoder->write_int2(status_flags);
  encoder->write_int2((capability_flags >> 16) & 0xffff);
  if(capability_flags & CF_CLIENT_PLUGIN_AUTH)
    encoder->write_int1(auth_plugin_data_length);
  else
    encoder->write_int1(0);
  encoder->write_zeroes(10);
  if(capability_flags & CF_CLIENT_SECURE_CONNECTION) {
    int len = auth_plugin_data_length - 8;
    if(len > 13) len = 13;
    encoder->write_bytes(auth_plugin_data + 8, len);
  }
  if(capability_flags & CF_CLIENT_PLUGIN_AUTH)
    encoder->write_nul_terminated_string(auth_plugin_name);
}


void HandshakeV10Packet::handle_by_connection(Connection * connection) {
  connection->handle_handshake_v10_packet(this);
}


// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
void HandshakeResponse41Packet::extract_packet_fields() {
  BinaryDecoder decoder(data);

  capability_flags = decoder.read_int4();
  max_packet_size = decoder.read_int4();
  character_set = decoder.read_int1();
  decoder.skip_bytes(23);
  username = decoder.read_nul_terminated_string();

  if(capability_flags & CF_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)
    auth_response_length = decoder.copy_length_encoded_string(auth_response, sizeof(auth_response));
  else if(capability_flags & CF_CLIENT_SECURE_CONNECTION) {
    auth_response_length = decoder.read_int1();
    decoder.read_bytes(auth_response, auth_response_length);
    auth_response[auth_response_length] = 0;
  }
  else
    auth_response_length = decoder.copy_nul_terminated_string(auth_response, sizeof(auth_response));

  if(capability_flags & CF_CLIENT_CONNECT_WITH_DB)
    database_name = decoder.read_nul_terminated_string();
  else
    database_name = 0;

  // TODO: still more fields to decode...
}


// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
void HandshakeResponse41Packet::synthesize_packet_payload(BinaryEncoder * encoder) {
  // Note that there is no typecode byte prefix for this kind of packet.
  encoder->write_int4(capability_flags);
  encoder->write_int4(max_packet_size);
  encoder->write_int1(character_set);
  encoder->write_zeroes(23);
  encoder->write_nul_terminated_string(username);

  // NOTE: This LENENC_CLIENT_DATA flag does not really seem to be implemented correctly on
  // the MySQL end.  It's not set even though it should be, I think.  This means we will probably
  // fall through to the CF_CLIENT_SECURE_CONNECTION below here - fortunately, as long as the
  // auth data is under 251 bytes (which it has to be as we only support the "native" auth method
  // which uses 20 bytes) the formats are compatible.
  if(capability_flags & CF_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
    // NOTE: Don't use write_length_encoded_string here, because we need to write an exact
    // number of bytes (which may include NUL characters).
    encoder->write_length_encoded_int(auth_response_length);
    encoder->write_bytes(auth_response, auth_response_length);
  }
  else if(capability_flags & CF_CLIENT_SECURE_CONNECTION) {
    int len = auth_response_length;
    if(len > 255) len = 255;
    encoder->write_int1(len);
    encoder->write_bytes(auth_response, len);
  }
  else
    encoder->write_nul_terminated_string((const char *)auth_response);

  if(capability_flags & CF_CLIENT_CONNECT_WITH_DB)
    encoder->write_nul_terminated_string(database_name);

  if(capability_flags & CF_CLIENT_PLUGIN_AUTH)
    encoder->write_nul_terminated_string(auth_plugin_name);

  if(capability_flags & CF_CLIENT_CONNECT_ATTRS) {
    // TODO: connect attributes documentation is a little ambiguous;
    // just dummying this out for now
    encoder->write_length_encoded_int(0);
  }
}


void HandshakeResponse41Packet::handle_by_connection(Connection * connection) {
  connection->handle_handshake_response_41_packet(this);
}


void QueryPacket::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(0x03);
  encoder->write_bytes((uint8_t *)query_string, query_string_length);
}


void QueryPacket::handle_by_connection(Connection * connection) {
  connection->handle_query_packet(this);
}


void QueryPacket::extract_packet_fields() {
  // For query packets, the entire payload, excluding the initial packet type code byte,
  // is the query string.  The query string is not necessarily NUL-terminated.
  query_string = (const char *)(data.data + 1);
  query_string_length = data.length - 1;
}


void QuitPacket::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(0x01);
}


void QuitPacket::handle_by_connection(Connection * connection) {
  connection->handle_quit_packet(this);
}


void InitDBPacket::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(0x02);
  encoder->write_bytes((uint8_t *)schema_name, strlen(schema_name));
}


void InitDBPacket::handle_by_connection(Connection * connection) {
  connection->handle_init_db_packet(this);
}


void InitDBPacket::extract_packet_fields() {
  BinaryDecoder decoder(data);

  decoder.skip_bytes(1);
  decoder.copy_remaining_string((uint8_t *)schema_name, sizeof(schema_name));
}


void FieldListRequestPacket::handle_by_connection(Connection * connection) {
  connection->handle_field_list_request_packet(this);
}


void FieldListRequestPacket::extract_packet_fields() {
  BinaryDecoder decoder(data);
  decoder.skip_bytes(1);
  table_name = decoder.read_nul_terminated_string();
  decoder.copy_remaining_string((uint8_t *)field_wildcard, sizeof(field_wildcard));
}


void PingPacket::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(0x0e);
}


void PingPacket::handle_by_connection(Connection * connection) {
  connection->handle_ping_packet(this);
}


void StatisticsPacket::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(0x09);
}


void StatisticsPacket::handle_by_connection(Connection * connection) {
  connection->handle_statistics_packet(this);
}


void ShutdownPacket::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(0x08);
  encoder->write_int1(shutdown_type);
}


void ShutdownPacket::handle_by_connection(Connection * connection) {
  connection->handle_shutdown_packet(this);
}


void ShutdownPacket::extract_packet_fields() {
  BinaryDecoder decoder(data);
  decoder.skip_bytes(1);
  if(decoder.has_more_data())
    shutdown_type = decoder.read_byte();
  else
    shutdown_type = 0x00;
}


void RefreshPacket::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(0x07);
  encoder->write_int1(subcommand);
}


void RefreshPacket::handle_by_connection(Connection * connection) {
  connection->handle_refresh_packet(this);
}


void RefreshPacket::extract_packet_fields() {
  BinaryDecoder decoder(data);
  decoder.skip_bytes(1);
  subcommand = decoder.read_byte();
}


// This isn't really used, just here for completeness.
void UnsupportedPacket::synthesize_packet_payload(BinaryEncoder * encoder) {
  encoder->write_int1(packet_type);
}


void UnsupportedPacket::handle_by_connection(Connection * connection) {
  connection->handle_unsupported_packet(this);
}


void UnsupportedPacket::extract_packet_fields() {
  BinaryDecoder decoder(data);
  packet_type = decoder.read_byte();
}


#if 0
// Static helper method for (very) basic query parsing.
// This looks for the (NUL-terminated) search_string at the beginning of the (*not* NUL-terminated)
// (query_string, query_string_length) data.  Initial whitespace in the query_string, if any, is skipped.
// The matching is case-insensitive.
// - If a match is found:
//   true is returned, and *new_query_string_ptr and *new_query_string_length_ptr, if they are supplied,
//   are updated with the revised query_string position and length pointing immediately after the matched string.
//   (the actual contents of the string are not modified).
// - If a match is not found:
//   false is returned and nothing else happens.
bool QueryPacket::match_query_string(const char * query_string, size_t query_string_length,
                                     const char * search_string,
                                     char ** new_query_string_ptr, size_t * new_query_string_length_ptr) {
  // Skip initial whitespace.
  while(query_string_length > 0 && isspace(*query_string)) {
    query_string_length--;
    query_string++;
  }

  // Perform case insensitive matching.
  while(query_string_length > 0 && *search_string != '\0') {
    if(tolower(*query_string) != tolower(*search_string))
      return false;  // Matching failed.
    query_string_length--;
    query_string++;
    search_string++;
  }

  if(*search_string == '\0') {
    // Entire search string has been matched, indicating success.
    if(new_query_string_ptr)
      *new_query_string_ptr = query_string;
    if(new_query_string_length_ptr)
      *new_query_string_length_ptr = query_string_length;
    return true;
  }
  else
    return false;
}
#endif

