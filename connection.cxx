

#include "main.h"


// Libevent bufferevent callbacks.  These are used for all connection types.
static void connection_read_callback(struct bufferevent * bufferevent, void * context);
static void connection_write_callback(struct bufferevent * bufferevent, void * context);
static void connection_event_callback(struct bufferevent * bufferevent, short event_type, void * context);


Connection::Connection() {
  socket_fd = -1;
  bufferevent = 0;
  description = 0;
  state = CONNECTION_STATE_UNCONNECTED;
  is_closing = false;
  established_at_time = 0;
  pool = 0;
  expected_packet_type = EXPECTING_PACKET_WITH_TYPE_CODE;
  reading_packet_body = false;
}


Connection::~Connection() {
  set_description_string(0);  // This frees it if needed.
}


// Set up the libevent 'bufferevent' object, which manages the read and write buffers.
// All connections regardless of type use the same callbacks; the differences between
// connection types are implemented via virtual methods of the connection.
void Connection::create_bufferevent() {
  bufferevent = bufferevent_socket_new(current_server->event_base, socket_fd, BEV_OPT_CLOSE_ON_FREE);
  bufferevent_setcb(bufferevent, connection_read_callback, connection_write_callback,
                    connection_event_callback, (void *)this);
  bufferevent_enable(bufferevent, EV_READ | EV_WRITE);
}


// Human-readable string to identify this connection.
const char * Connection::description_string() const {
  if(description)
    return description;
  else return "[unknown connection]";
}


void Connection::set_description_string(const char * new_string) {
  if(description) {
    current_server->allocation_stats.string_data_bytes -= strlen(description) + 1;
    delete [] description;
    description = 0;
  }
  if(new_string) {
    int len = strlen(new_string);
    char * s = new char[len + 1];
    strcpy(s, new_string);
    description = s;
    current_server->allocation_stats.string_data_bytes += len + 1;
  }
}


// This connection is now ready to accept a "normal" packet and is not
// in the middle of any other part of the protocol.
void Connection::switch_to_ready_state() {
  state = CONNECTION_STATE_READY;
  expected_packet_type = EXPECTING_PACKET_WITH_TYPE_CODE;
}


void Connection::synthesize_and_send_packet(Packet * packet) {
  BinaryEncoder encoder;
  uint8_t * binary_payload;
  size_t payload_length;

  // TODO: we could probably skip the convert_to_byte_array step by
  // just using bufferevent_write for each buffer chunk instead

  // Encode the packet payload.
  packet->synthesize_packet_payload(&encoder);

  // Convert to a linear byte array.
  binary_payload = encoder.convert_to_byte_array(&payload_length);

  packet->data.data = binary_payload;
  packet->data.length = payload_length;
  current_server->allocation_stats.packet_data_bytes += payload_length;

  send_packet(packet);
}


// Low-level packet sending routine.
// Queue a packet into this connection's write buffer.
// NOTE: if this connection is flagged as is_closing, the data will be
// silently discarded instead of actually being sent.
void Connection::send_packet_data(PacketData packet_data) {
  uint8_t packet_header[4];

  if(is_closing)
    return;

  // Create and send the packet header.
  packet_header[0] = packet_data.length & 0xff;
  packet_header[1] = (packet_data.length >> 8) & 0xff;
  packet_header[2] = (packet_data.length >> 16) & 0xff;
  packet_header[3] = packet_data.sequence_number & 0xff;
  bufferevent_write(bufferevent, packet_header, 4);

  // Send the packet payload.
  bufferevent_write(bufferevent, packet_data.data, packet_data.length);

  // Increment traffic statistics.
  record_outgoing_network_traffic(packet_data.length + 4);
}


// New data has arrived in the input buffer; process as much as we can of it.
void Connection::process_input() {
  struct evbuffer * input_buffer = bufferevent_get_input(bufferevent);

  while(true) {  // Loop until not enough available to do any more.
    if(!reading_packet_body && evbuffer_get_length(input_buffer) >= 4) {
      // 4-byte packet length header has been received; interpret the header fields and prepare
      // to read the rest of the packet.
      uint8_t buf[4];
      bufferevent_read(bufferevent, buf, 4);

      // Increment traffic statistics.
      record_incoming_network_traffic(4);

      // The 4-byte packet header contains:
      // byte 0: low 8 bits of packet length
      // byte 1: middle 8 bits of packet length
      // byte 2: high 8 bits of packet length
      // byte 3: packet sequence number
      expected_packet_length = 0;
      loopi(3) {
        expected_packet_length <<= 8;
        expected_packet_length |= buf[2-i];
      }
      decoded_packet_sequence_number = buf[3];
      reading_packet_body = true;
    }
    else if(reading_packet_body && evbuffer_get_length(input_buffer) >= expected_packet_length) {
      // A complete packet has been buffered; process it.
      // This hands off ownership of the 'packet_data.data' memory to handle_received_packet_data().
      PacketData packet_data;
      packet_data.length = expected_packet_length;
      packet_data.sequence_number = decoded_packet_sequence_number;
      packet_data.data = new uint8_t[expected_packet_length];
      current_server->allocation_stats.packet_data_bytes += expected_packet_length;
      bufferevent_read(bufferevent, packet_data.data, expected_packet_length);
      record_incoming_network_traffic(expected_packet_length);
      handle_received_packet_data(packet_data);
      reading_packet_body = false;
    }
    else
      break;  // Nothing left to do.
  }

  // Notify the connection that we've (maybe) processed some input.
  // Subclasses can override this.  This may wind up deleting this connection
  // so it has to be the last thing called here.
  input_has_been_processed();
}


// We've fully received a raw packet; handle it depending on the connection state.
// The memory pointed to by packet_data is now 'owned' by this method.
void Connection::handle_received_packet_data(PacketData packet_data) {
  Packet * packet;
  
  if(packet_data.length == 0) {
    // This shouldn't happen in normal operation.
    // This sanity check is here because we often have to examine the first
    // byte of the packet payload to determine what to do.
    log_error_message("Length 0 packet encountered from %s; skipping it.", description_string());
    packet_data.release_memory();
    return;
  }
  
  switch(expected_packet_type) {
  case EXPECTING_PACKET_WITH_TYPE_CODE:
    packet = packet_data.create_packet();
    if(packet)
      handle_packet(packet);
    else {
      // Invalid or unrecognized packet type.
      // An error has already been logged.
      packet_data.release_memory();
    }
    break;
  case EXPECTING_HANDSHAKE:
    // The packet may be an Error packet or a Handshake packet, depending on the initial byte.
    // If it's a Handshake packet, the ordinary packet_data.create_packet() call can't create it
    // because the initial byte conflicts with that of the COM_PROCESS_INFO packet.  So we create
    // it manually here in this special case.
    if(packet_data.looks_like_err_packet())
      packet = packet_data.create_packet();
    else {
      packet = new HandshakeV10Packet;
      packet->data = packet_data;
    }
    if(packet)
      handle_packet(packet);
    else packet_data.release_memory();
    break;
  case EXPECTING_HANDSHAKE_RESPONSE:
    handle_handshake_response(packet_data);
    break;
  case EXPECTING_RESULTSET_HEADER:
    handle_resultset_header(packet_data);
    break;
  case EXPECTING_RESULTSET_FIELD_DESCRIPTIONS:
    handle_resultset_field_description(packet_data);
    break;
  case EXPECTING_RESULTSET_ROWS:
    handle_resultset_row(packet_data);
    break;
  case EXPECTING_FIELD_LIST_RESPONSE:
    handle_field_list_response(packet_data);
    break;
  default:
    log_error_message("Invalid expected_packet_type state; shouldn't happen");
    packet_data.release_memory();
    break;
  }
}


// This shouldn't happen unless the protocol is violated (or there is a bug).
void Connection::handle_unexpected_packet_data(PacketData packet_data) {
  log_error_message("Received a packet while in an unexpected state");
  packet_data.release_memory();
}


// Have this connection "handle" the given packet.  This turns into a double-dispatch call
// via packet->handle_by_connection().
//
// Once this handle_packet() is called, the packet's memory is owned by this method.
// The packet will be deleted automatically after being handled, unless the handler
// sets packet->is_pending indicating that it has been put into a PendingLeaseRequest
// queue and should be retained.
void Connection::handle_packet(Packet * packet) {
  // Unpack the raw payload into instance variables as appropriate for the packet type.
  packet->extract_packet_fields();

  // Double-dispatch to the correct packet handler method for this packet type.
  packet->handle_by_connection(this);

  // Free the packet's memory (including payload bytes) unless deferred.
  if(!packet->is_pending)
    delete packet;
}


void Connection::handle_handshake_response(PacketData packet_data) {
  HandshakeResponse41Packet * packet = new HandshakeResponse41Packet;
  packet->data = packet_data;
  handle_packet(packet);
}


// New data has arrived on the connection.
static void connection_read_callback(struct bufferevent * bufferevent, void * context) {
  ((Connection *)context)->process_input();
}


// Low-water mark has been reached in the write buffer.
// In the current implementation, this means the write buffer is now completely empty.
static void connection_write_callback(struct bufferevent * bufferevent, void * context) {
  ((Connection *)context)->write_buffer_is_empty();
}


// Connection socket "event" has occurred.  These are generally when the remote end
// closes the connection or there is a network error.  Other event types we can just
// ignore here.
static void connection_event_callback(struct bufferevent * bufferevent, short event_type, void * context) {
  Connection * connection = (Connection *)context;

  if(event_type & BEV_EVENT_ERROR) {
    // Socket exception.  Log the error and treat it as a normal remote close.
    log_error_message("%s received socket exception %s: %s.  Closing the socket.",
                      connection->description_string(),
                      ((event_type & BEV_EVENT_READING) ? "while reading" :
                       ((event_type & BEV_EVENT_WRITING) ? "while writing" : "(read/write state unknown)")),
                      strerror((int)evutil_socket_geterror(connection->socket_fd)));
    connection->remote_closed_connection();
  }
  else if(event_type & BEV_EVENT_EOF) {
    // Connection closed from remote end.
    connection->remote_closed_connection();
  }
}

