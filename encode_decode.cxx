

#include "main.h"


// Freelist for buffer chunks.  This is managed explicitly since it's so high-turnover.
static BinaryEncoderBufferChunk * encoder_buffer_chunk_freelist = 0;


static BinaryEncoderBufferChunk * acquire_buffer_chunk();
static void release_buffer_chunk(BinaryEncoderBufferChunk * chunk);


static BinaryEncoderBufferChunk * acquire_buffer_chunk() {
  BinaryEncoderBufferChunk * chunk;
  
  if(encoder_buffer_chunk_freelist) {
    // Reuse a chunk from the freelist.
    chunk = encoder_buffer_chunk_freelist;
    encoder_buffer_chunk_freelist = chunk->next;
  }
  else {
    // Allocate a new chunk.
    chunk = new BinaryEncoderBufferChunk;
    chunk->size = 8000;  // arbitrary
    chunk->data = new uint8_t[chunk->size];
    if(!chunk->data)
      panic("Out of memory for buffer chunks!");
  }
    
  chunk->next = 0;
  chunk->current_position = 0;
  current_server->allocation_stats.encoder_buffer_chunks++;
  return chunk;
}


static void release_buffer_chunk(BinaryEncoderBufferChunk * chunk) {
  chunk->next = encoder_buffer_chunk_freelist;
  encoder_buffer_chunk_freelist = chunk;
  current_server->allocation_stats.encoder_buffer_chunks--;
}


// This is never actually invoked (we don't ever free these currently, only recycle them).
BinaryEncoderBufferChunk::~BinaryEncoderBufferChunk() {
  delete [] data;
}


BinaryEncoder::BinaryEncoder() {
  // Start off with an initial buffer chunk.
  current_buffer_chunk = buffer_chunk_list_head = acquire_buffer_chunk();
  bytes_written_so_far = 0;
}


BinaryEncoder::~BinaryEncoder() {
  while(buffer_chunk_list_head) {
    BinaryEncoderBufferChunk * next = buffer_chunk_list_head->next;
    release_buffer_chunk(buffer_chunk_list_head);
    buffer_chunk_list_head = next;
  }
  current_buffer_chunk = 0;
}


// Add a single byte to the buffer.  All the other encoding routines
// are written in terms of this.
void BinaryEncoder::write_byte(uint8_t b) {
  // Make sure we have space for at least 1 more byte.
  if(current_buffer_chunk->current_position == current_buffer_chunk->size) {
    // Current buffer chunk is full; get a new one and append it to the end of the linked list.
    BinaryEncoderBufferChunk * new_chunk = acquire_buffer_chunk();
    current_buffer_chunk->next = new_chunk;
    current_buffer_chunk = new_chunk;
  }

  // Write the byte.
  current_buffer_chunk->data[current_buffer_chunk->current_position++] = b;
  bytes_written_so_far++;
}


void BinaryEncoder::write_zeroes(int count) {
  loopi(count) write_byte(0);
}


void BinaryEncoder::write_bytes(const uint8_t * bytes, int count) {
  loopi(count) write_byte(bytes[i]);
}


void BinaryEncoder::write_int2(uint32_t value) {
  write_byte(value & 0xff);
  write_byte((value >> 8) & 0xff);
}


void BinaryEncoder::write_int3(uint32_t value) {
  write_byte(value & 0xff);
  write_byte((value >> 8) & 0xff);
  write_byte((value >> 16) & 0xff);
}


void BinaryEncoder::write_int4(uint32_t value) {
  write_byte(value & 0xff);
  write_byte((value >> 8) & 0xff);
  write_byte((value >> 16) & 0xff);
  write_byte((value >> 24) & 0xff);
}


void BinaryEncoder::write_int6(uint64_t value) {
  write_byte(value & 0xff);
  write_byte((value >> 8) & 0xff);
  write_byte((value >> 16) & 0xff);
  write_byte((value >> 24) & 0xff);
  write_byte((value >> 32) & 0xff);
  write_byte((value >> 40) & 0xff);
}


void BinaryEncoder::write_int8(uint64_t value) {
  write_byte(value & 0xff);
  write_byte((value >> 8) & 0xff);
  write_byte((value >> 16) & 0xff);
  write_byte((value >> 24) & 0xff);
  write_byte((value >> 32) & 0xff);
  write_byte((value >> 40) & 0xff);
  write_byte((value >> 48) & 0xff);
  write_byte((value >> 56) & 0xff);
}


// http://dev.mysql.com/doc/internals/en/integer.html
void BinaryEncoder::write_length_encoded_int(uint64_t value) {
  if(value < 251)
    write_int1(value);
  else if(value < 0x10000UL) {  // 2^16
    write_byte(0xfc);
    write_int2(value);
  }
  else if(value < 0x1000000UL) {  // 2^24
    write_byte(0xfd);
    write_int3(value);
  }
  else {
    write_byte(0xfe);
    write_int8(value);
  }
}


void BinaryEncoder::write_nul_terminated_string(const char * s) {
  while(*s)
    write_byte(*s++);
  write_byte(0);
}


void BinaryEncoder::write_length_encoded_string(const char * s, size_t len) {
  write_length_encoded_int(len);
  write_bytes((const uint8_t *)s, len);
}


// Returns a new dynamically allocated array containing all the accumulated
// data so far, and stores the total length in *length.
uint8_t * BinaryEncoder::convert_to_byte_array(size_t * length) {
  BinaryEncoderBufferChunk * chunk;
  size_t total_length, current_offset;
  uint8_t * buffer;
  
  // Calculate total length.
  total_length = 0;
  for(chunk = buffer_chunk_list_head; chunk; chunk = chunk->next)
    total_length += chunk->current_position;

  // Allocate the buffer and copy everything into it.
  buffer = new uint8_t[total_length ? total_length : 1];  // condition is to avoid 0-length allocations in pathological cases
  if(!buffer)
    panic("Out of memory for buffers!  Aborting");
  for(chunk = buffer_chunk_list_head, current_offset = 0;
      chunk;
      current_offset += chunk->current_position, chunk = chunk->next)
    memcpy(buffer + current_offset, chunk->data, chunk->current_position);
  
  *length = total_length;
  return buffer;
}


void BinaryDecoder::start_decoding_data(const uint8_t * new_data, size_t length) {
  data = new_data;
  data_length = length;
  position = 0;
}


void BinaryDecoder::start_decoding_packet_data(PacketData packet_data) {
  start_decoding_data(packet_data.data, packet_data.length);
}


uint8_t BinaryDecoder::read_byte() {
  if(position >= data_length) {
    // Out of bounds - shouldn't happen.
    log_error_message("Buffer overrun with BinaryDecoder!");
    return 0;
  }
  else return data[position++];
}


void BinaryDecoder::read_bytes(uint8_t * buffer, int count) {
  loopi(count) buffer[i] = read_byte();
}


void BinaryDecoder::skip_bytes(int n) {
  loopi(n) read_byte();
}


// Back up by the given number of bytes.
void BinaryDecoder::rewind() {
  if(position == 0) {
    log_error_message("Rewinding beyond beginning of stream in BinaryDecoder!");
    return;
  }
  position--;
}


uint32_t BinaryDecoder::read_int2() {
  uint32_t value = read_byte();
  return value | (((uint32_t)read_byte()) << 8);
}


uint32_t BinaryDecoder::read_int3() {
  uint32_t value = read_byte();
  value |= ((uint32_t)read_byte()) << 8;
  value |= ((uint32_t)read_byte()) << 16;
  return value;
}


uint32_t BinaryDecoder::read_int4() {
  uint32_t value = read_byte();
  value |= ((uint32_t)read_byte()) << 8;
  value |= ((uint32_t)read_byte()) << 16;
  value |= ((uint32_t)read_byte()) << 24;
  return value;
}


uint64_t BinaryDecoder::read_int6() {
  uint64_t value = read_byte();
  value |= ((uint64_t)read_byte()) << 8;
  value |= ((uint64_t)read_byte()) << 16;
  value |= ((uint64_t)read_byte()) << 24;
  value |= ((uint64_t)read_byte()) << 32;
  value |= ((uint64_t)read_byte()) << 40;
  return value;
}


uint64_t BinaryDecoder::read_int8() {
  uint64_t value = read_byte();
  value |= ((uint64_t)read_byte()) << 8;
  value |= ((uint64_t)read_byte()) << 16;
  value |= ((uint64_t)read_byte()) << 24;
  value |= ((uint64_t)read_byte()) << 32;
  value |= ((uint64_t)read_byte()) << 40;
  value |= ((uint64_t)read_byte()) << 48;
  value |= ((uint64_t)read_byte()) << 56;
  return value;
}


uint64_t BinaryDecoder::read_length_encoded_int() {
  uint8_t leading_byte = read_byte();
  if(leading_byte < 0xfb)
    return leading_byte;
  else if(leading_byte == 0xfc)
    return read_int2();
  else if(leading_byte == 0xfd)
    return read_int3();
  else if(leading_byte == 0xfe)
    return read_int8();
  else
    return 0;  // shouldn't happen
}


// NOTE: this returns a pointer into the interior of the data buffer,
// without allocating any memory.
char * BinaryDecoder::read_nul_terminated_string() {
  char * s = (char *)(data + position);
  while(read_byte() != 0)
    ;
  return s;
}


// Copy a length-encoded string into the given memory buffer and NUL terminate it.
// The string length (without terminating NUL) is returned.
uint64_t BinaryDecoder::copy_length_encoded_string(uint8_t * buf, size_t buflen) {
  uint64_t length = read_length_encoded_int();
  size_t i;
  for(i = 0; i < length; i++) {
    uint8_t byte = read_byte();
    if(i < buflen-1)
      buf[i] = byte;
  }
  buf[i] = 0;
  return i;
}


uint64_t BinaryDecoder::copy_nul_terminated_string(uint8_t * buf, size_t buflen) {
  uint8_t b;
  size_t i = 0;
  
  buf[0] = 0;
  while((b = read_byte()) != 0) {
    if(i+1 < buflen) {
      buf[i] = b;
      buf[i+1] = 0;
      i++;
    }
  }
  return i;
}


// Copy whatever is left in the packet into the given buffer (up to a maximum of buflen-1 bytes).
// 'buf' will be NUL-terminated even if what's in the packet is not.
// This type of string is notated as "string[EOF]" in the MySQL protocol documentation.
void BinaryDecoder::copy_remaining_string(uint8_t * buf, size_t buflen) {
  size_t byte_count = 0;
  while(has_more_data() && byte_count < buflen-1)
    buf[byte_count++] = read_byte();
  buf[byte_count] = 0;
}
