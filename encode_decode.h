

// Encoder and decoder streams capable of dealing with the low-level objects
// in the MySQL protocol binary format.  These are described here:
// http://dev.mysql.com/doc/internals/en/basic-types.html


// A reusable (freelist-based) chunk of buffer storage for encoding packets.
// These are threaded into a global freelist for quick reuse.
class BinaryEncoderBufferChunk {
public:
  ~BinaryEncoderBufferChunk();

public:
  uint8_t * data;
  size_t size;  // capacity of 'data'
  size_t current_position;
  BinaryEncoderBufferChunk * next;
};


class BinaryEncoder {
public:
  // Linked list of buffer chunks; current_buffer_chunk is actually the
  // tail of the list.
  BinaryEncoderBufferChunk * buffer_chunk_list_head, * current_buffer_chunk;
  size_t bytes_written_so_far;
  
public:
  BinaryEncoder();
  ~BinaryEncoder();

  void write_byte(uint8_t b);
  void write_zeroes(int count);
  void write_bytes(const uint8_t * bytes, int count);

  // Fixed-length integers; in the MySQL protocol, these are stored
  // in little-endian format, opposite of "normal" network byte order.
  // http://dev.mysql.com/doc/internals/en/integer.html
  void write_int1(uint32_t value) { write_byte(value); }
  void write_int2(uint32_t value);
  void write_int3(uint32_t value);
  void write_int4(uint32_t value);
  void write_int6(uint64_t value);
  void write_int8(uint64_t value);

  // Length-encoded integer.
  void write_length_encoded_int(uint64_t value);

  // Strings.  The MySQL protocol has a few ways of representing strings.
  void write_nul_terminated_string(const char * s);
  void write_length_encoded_string(const char * s, size_t len);
  void write_length_encoded_string(const char * s) { write_length_encoded_string(s, strlen(s)); }

  // Linearize our linked list of buffer chunks into a contiguous array.
  uint8_t * convert_to_byte_array(size_t * length);
};


class BinaryDecoder {
public:
  const uint8_t * data;
  size_t data_length;
  size_t position;

public:
  BinaryDecoder(PacketData packet_data) { start_decoding_packet_data(packet_data); }

  void start_decoding_data(const uint8_t * new_data, size_t length);
  void start_decoding_packet_data(PacketData packet_data);

  bool has_more_data() { return position < data_length; }
  uint8_t read_byte();
  void read_bytes(uint8_t * buffer, int count);
  void skip_bytes(int n);
  void rewind();

  // Fixed-length integers.
  uint32_t read_int1() { return read_byte(); }
  uint32_t read_int2();
  uint32_t read_int3();
  uint32_t read_int4();
  uint64_t read_int6();
  uint64_t read_int8();

  // Length-encoded integer.
  uint64_t read_length_encoded_int();

  // Various string formats.
  char * read_nul_terminated_string();
  uint64_t copy_length_encoded_string(uint8_t * buf, size_t buflen);
  uint64_t copy_nul_terminated_string(uint8_t * buf, size_t buflen);
  void copy_remaining_string(uint8_t * buf, size_t buflen);
};

