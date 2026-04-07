#ifdef USE_FIPS_BLE

#include "fips_fsp.h"
#include "fips_noise.h"
#include <cstring>

namespace esphome::fips_ble {

static uint8_t fsp_prefix_byte(uint8_t phase) { return (FSP_VERSION << 4) | (phase & 0x0F); }

static void fsp_prefix(uint8_t phase, uint8_t flags, uint16_t payload_len, uint8_t out[FSP_PREFIX_SIZE]) {
  out[0] = fsp_prefix_byte(phase);
  out[1] = flags;
  out[2] = static_cast<uint8_t>(payload_len & 0xFF);
  out[3] = static_cast<uint8_t>((payload_len >> 8) & 0xFF);
}

static bool fsp_check_prefix(const uint8_t *data, size_t len, uint8_t expected_phase) {
  if (len < FSP_PREFIX_SIZE)
    return false;
  if ((data[0] >> 4) != FSP_VERSION || (data[0] & 0x0F) != expected_phase)
    return false;
  return true;
}

static size_t write_le16(uint16_t val, uint8_t *out) {
  out[0] = static_cast<uint8_t>(val & 0xFF);
  out[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
  return 2;
}

size_t fsp_build_session_setup(uint8_t session_flags, const uint8_t *src_addr, const uint8_t *dst_addr,
                                 const uint8_t *handshake, size_t hs_len, uint8_t *out, size_t out_len) {
  size_t body_len = 1 + (2 + NODE_ADDR_SIZE) + (2 + NODE_ADDR_SIZE) + 2 + hs_len;
  size_t total = FSP_PREFIX_SIZE + body_len;
  if (out_len < total)
    return 0;

  fsp_prefix(FSP_PHASE_SESSION_SETUP, 0x00, static_cast<uint16_t>(body_len), out);
  size_t pos = FSP_PREFIX_SIZE;

  out[pos++] = session_flags;

  pos += write_le16(1, out + pos);
  std::memcpy(out + pos, src_addr, NODE_ADDR_SIZE);
  pos += NODE_ADDR_SIZE;

  pos += write_le16(1, out + pos);
  std::memcpy(out + pos, dst_addr, NODE_ADDR_SIZE);
  pos += NODE_ADDR_SIZE;

  pos += write_le16(static_cast<uint16_t>(hs_len), out + pos);
  std::memcpy(out + pos, handshake, hs_len);
  pos += hs_len;

  return pos;
}

size_t fsp_parse_session_setup(const uint8_t *data, size_t len, uint8_t &session_flags, const uint8_t *&hs_payload,
                                size_t &hs_len) {
  if (!fsp_check_prefix(data, len, FSP_PHASE_SESSION_SETUP))
    return 0;

  uint16_t payload_len = static_cast<uint16_t>(data[2]) | (static_cast<uint16_t>(data[3]) << 8);
  const uint8_t *body = data + FSP_PREFIX_SIZE;
  if (payload_len > len - FSP_PREFIX_SIZE)
    return 0;
  if (payload_len < 1)
    return 0;

  session_flags = body[0];
  size_t pos = 1;

  uint16_t src_count = static_cast<uint16_t>(body[pos]) | (static_cast<uint16_t>(body[pos + 1]) << 8);
  pos += 2 + src_count * NODE_ADDR_SIZE;
  if (payload_len < pos)
    return 0;

  uint16_t dst_count = static_cast<uint16_t>(body[pos]) | (static_cast<uint16_t>(body[pos + 1]) << 8);
  pos += 2 + dst_count * NODE_ADDR_SIZE;
  if (payload_len < pos + 2)
    return 0;

  uint16_t hs_len16 = static_cast<uint16_t>(body[pos]) | (static_cast<uint16_t>(body[pos + 1]) << 8);
  pos += 2;
  if (payload_len < pos + hs_len16)
    return 0;

  hs_payload = body + pos;
  hs_len = hs_len16;
  return pos + hs_len16;
}

size_t fsp_build_session_ack(const uint8_t *src_addr, const uint8_t *dst_addr, const uint8_t *handshake, size_t hs_len,
                              uint8_t *out, size_t out_len) {
  size_t body_len = 1 + (2 + NODE_ADDR_SIZE) + (2 + NODE_ADDR_SIZE) + 2 + hs_len;
  size_t total = FSP_PREFIX_SIZE + body_len;
  if (out_len < total)
    return 0;

  fsp_prefix(FSP_PHASE_SESSION_ACK, 0x00, static_cast<uint16_t>(body_len), out);
  size_t pos = FSP_PREFIX_SIZE;

  out[pos++] = 0x00;

  pos += write_le16(1, out + pos);
  std::memcpy(out + pos, src_addr, NODE_ADDR_SIZE);
  pos += NODE_ADDR_SIZE;

  pos += write_le16(1, out + pos);
  std::memcpy(out + pos, dst_addr, NODE_ADDR_SIZE);
  pos += NODE_ADDR_SIZE;

  pos += write_le16(static_cast<uint16_t>(hs_len), out + pos);
  std::memcpy(out + pos, handshake, hs_len);
  pos += hs_len;

  return pos;
}

size_t fsp_parse_session_ack(const uint8_t *data, size_t len, const uint8_t *&hs_payload, size_t &hs_len) {
  if (!fsp_check_prefix(data, len, FSP_PHASE_SESSION_ACK))
    return 0;

  uint16_t payload_len = static_cast<uint16_t>(data[2]) | (static_cast<uint16_t>(data[3]) << 8);
  const uint8_t *body = data + FSP_PREFIX_SIZE;
  if (payload_len > len - FSP_PREFIX_SIZE || payload_len < 1)
    return 0;

  size_t pos = 1;

  uint16_t src_count = static_cast<uint16_t>(body[pos]) | (static_cast<uint16_t>(body[pos + 1]) << 8);
  pos += 2 + src_count * NODE_ADDR_SIZE;
  if (payload_len < pos)
    return 0;

  uint16_t dst_count = static_cast<uint16_t>(body[pos]) | (static_cast<uint16_t>(body[pos + 1]) << 8);
  pos += 2 + dst_count * NODE_ADDR_SIZE;
  if (payload_len < pos + 2)
    return 0;

  uint16_t hs_len16 = static_cast<uint16_t>(body[pos]) | (static_cast<uint16_t>(body[pos + 1]) << 8);
  pos += 2;
  if (payload_len < pos + hs_len16)
    return 0;

  hs_payload = body + pos;
  hs_len = hs_len16;
  return pos + hs_len16;
}

size_t fsp_build_session_msg3(const uint8_t *handshake, size_t hs_len, uint8_t *out, size_t out_len) {
  size_t body_len = 1 + 2 + hs_len;
  size_t total = FSP_PREFIX_SIZE + body_len;
  if (out_len < total)
    return 0;

  fsp_prefix(FSP_PHASE_SESSION_MSG3, 0x00, static_cast<uint16_t>(body_len), out);
  size_t pos = FSP_PREFIX_SIZE;

  out[pos++] = 0x00;
  pos += write_le16(static_cast<uint16_t>(hs_len), out + pos);
  std::memcpy(out + pos, handshake, hs_len);
  pos += hs_len;

  return pos;
}

size_t fsp_parse_session_msg3(const uint8_t *data, size_t len, const uint8_t *&hs_payload, size_t &hs_len) {
  if (!fsp_check_prefix(data, len, FSP_PHASE_SESSION_MSG3))
    return 0;

  uint16_t payload_len = static_cast<uint16_t>(data[2]) | (static_cast<uint16_t>(data[3]) << 8);
  const uint8_t *body = data + FSP_PREFIX_SIZE;
  if (payload_len > len - FSP_PREFIX_SIZE || payload_len < 3)
    return 0;

  uint16_t hs_len16 = static_cast<uint16_t>(body[1]) | (static_cast<uint16_t>(body[2]) << 8);
  if (payload_len < 3 + hs_len16)
    return 0;

  hs_payload = body + 3;
  hs_len = hs_len16;
  return 3 + hs_len16;
}

void fsp_build_session_datagram_body(const uint8_t *src, const uint8_t *dst, uint8_t out[SESSION_DATAGRAM_BODY_SIZE]) {
  std::memset(out, 0, SESSION_DATAGRAM_BODY_SIZE);
  out[0] = 64;
  write_le16(1400, out + 1);
  std::memcpy(out + 3, src, NODE_ADDR_SIZE);
  std::memcpy(out + 19, dst, NODE_ADDR_SIZE);
}

bool fsp_parse_session_datagram(const uint8_t *data, size_t len, uint16_t &src_port, uint16_t &dst_port,
                                   const uint8_t *&payload, size_t &payload_len) {
  if (len < FSP_DATAGRAM_HEADER_SIZE)
    return false;
  src_port = static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
  dst_port = static_cast<uint16_t>(data[2]) | (static_cast<uint16_t>(data[3]) << 8);
  payload = data + FSP_DATAGRAM_HEADER_SIZE;
  payload_len = len - FSP_DATAGRAM_HEADER_SIZE;
  return true;
}

size_t fsp_build_data_message(uint64_t counter, uint32_t timestamp_ms, const uint8_t *payload, size_t payload_len,
                                const uint8_t *key, uint8_t *out, size_t out_len) {
  uint8_t inner[512];
  inner[0] = static_cast<uint8_t>(timestamp_ms & 0xFF);
  inner[1] = static_cast<uint8_t>((timestamp_ms >> 8) & 0xFF);
  inner[2] = static_cast<uint8_t>((timestamp_ms >> 16) & 0xFF);
  inner[3] = static_cast<uint8_t>((timestamp_ms >> 24) & 0xFF);
  inner[4] = FSP_MSG_DATA;
  inner[5] = 0x00;
  if (payload_len > 0) {
    std::memcpy(inner + FSP_INNER_HEADER_SIZE, payload, payload_len);
  }
  size_t inner_len = FSP_INNER_HEADER_SIZE + payload_len;

  uint8_t header[FSP_HEADER_SIZE];
  header[0] = fsp_prefix_byte(FSP_PHASE_ESTABLISHED);
  header[1] = 0x00;
  write_le16(static_cast<uint16_t>(inner_len + TAG_SIZE), header + 2);
  for (int i = 0; i < 8; i++) {
    header[4 + i] = static_cast<uint8_t>((counter >> (i * 8)) & 0xFF);
  }

  size_t ciphertext_len = aead_encrypt(key, counter, header, FSP_HEADER_SIZE, inner, inner_len, out + FSP_HEADER_SIZE);
  if (ciphertext_len == 0)
    return 0;

  return FSP_HEADER_SIZE + ciphertext_len;
}

bool fsp_parse_data_message(const uint8_t *key, const uint8_t *data, size_t len, uint8_t &flags, uint64_t &counter,
                               uint32_t &timestamp_ms, uint8_t &msg_type, const uint8_t *&payload,
                               size_t &payload_len) {
  if (len < FSP_ENCRYPTED_MIN_SIZE)
    return false;
  if ((data[0] >> 4) != FSP_VERSION || (data[0] & 0x0F) != FSP_PHASE_ESTABLISHED)
    return false;

  flags = data[1];
  counter = 0;
  for (int i = 0; i < 8; i++) {
    counter |= static_cast<uint64_t>(data[4 + i]) << (i * 8);
  }

  const uint8_t *ciphertext = data + FSP_HEADER_SIZE;
  size_t ct_len = len - FSP_HEADER_SIZE;

  uint8_t decrypted[512];
  size_t dec_len = aead_decrypt(key, counter, data, FSP_HEADER_SIZE, ciphertext, ct_len, decrypted);
  if (dec_len < FSP_INNER_HEADER_SIZE)
    return false;

  timestamp_ms = static_cast<uint32_t>(decrypted[0]) | (static_cast<uint32_t>(decrypted[1]) << 8) |
                 (static_cast<uint32_t>(decrypted[2]) << 16) | (static_cast<uint32_t>(decrypted[3]) << 24);
  msg_type = decrypted[4];
  payload = decrypted + FSP_INNER_HEADER_SIZE;
  payload_len = dec_len - FSP_INNER_HEADER_SIZE;
  return true;
}

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
