#ifdef USE_FIPS_BLE

#include "fips_fmp.h"
#include "fips_noise.h"
#include <cstring>

namespace esphome::fips_ble {

void fmp_build_prefix(uint8_t phase, uint8_t flags, uint16_t payload_len, uint8_t out[FMP_PREFIX_SIZE]) {
  out[0] = (FMP_VERSION << 4) | (phase & 0x0F);
  out[1] = flags;
  out[2] = static_cast<uint8_t>(payload_len & 0xFF);
  out[3] = static_cast<uint8_t>((payload_len >> 8) & 0xFF);
}

bool fmp_parse_prefix(const uint8_t *data, size_t len, uint8_t &phase, uint8_t &flags, uint16_t &payload_len) {
  if (len < FMP_PREFIX_SIZE)
    return false;
  uint8_t version = data[0] >> 4;
  if (version != FMP_VERSION)
    return false;
  phase = data[0] & 0x0F;
  flags = data[1];
  payload_len = static_cast<uint16_t>(data[2]) | (static_cast<uint16_t>(data[3]) << 8);
  return true;
}

size_t fmp_build_msg1(uint32_t sender_idx, const uint8_t *noise_payload, size_t noise_len, uint8_t *out, size_t out_len) {
  size_t needed = FMP_PREFIX_SIZE + FMP_IDX_SIZE + noise_len;
  if (out_len < needed)
    return 0;
  uint16_t payload_len = static_cast<uint16_t>(FMP_IDX_SIZE + noise_len);
  fmp_build_prefix(PHASE_MSG1, 0x00, payload_len, out);
  out[FMP_PREFIX_SIZE + 0] = static_cast<uint8_t>(sender_idx & 0xFF);
  out[FMP_PREFIX_SIZE + 1] = static_cast<uint8_t>((sender_idx >> 8) & 0xFF);
  out[FMP_PREFIX_SIZE + 2] = static_cast<uint8_t>((sender_idx >> 16) & 0xFF);
  out[FMP_PREFIX_SIZE + 3] = static_cast<uint8_t>((sender_idx >> 24) & 0xFF);
  std::memcpy(out + FMP_PREFIX_SIZE + FMP_IDX_SIZE, noise_payload, noise_len);
  return needed;
}

size_t fmp_build_msg2(uint32_t sender_idx, uint32_t receiver_idx, const uint8_t *noise_payload, size_t noise_len,
                       uint8_t *out, size_t out_len) {
  size_t needed = FMP_PREFIX_SIZE + FMP_IDX_SIZE * 2 + noise_len;
  if (out_len < needed)
    return 0;
  uint16_t payload_len = static_cast<uint16_t>(FMP_IDX_SIZE * 2 + noise_len);
  fmp_build_prefix(PHASE_MSG2, 0x00, payload_len, out);
  for (int i = 0; i < 4; i++) {
    out[FMP_PREFIX_SIZE + i] = static_cast<uint8_t>((sender_idx >> (i * 8)) & 0xFF);
    out[FMP_PREFIX_SIZE + FMP_IDX_SIZE + i] = static_cast<uint8_t>((receiver_idx >> (i * 8)) & 0xFF);
  }
  std::memcpy(out + FMP_PREFIX_SIZE + FMP_IDX_SIZE * 2, noise_payload, noise_len);
  return needed;
}

size_t fmp_build_established(uint32_t receiver_idx, uint64_t counter, uint8_t msg_type, uint32_t timestamp,
                              const uint8_t *inner_payload, size_t inner_len, const uint8_t *key, uint8_t *out,
                              size_t out_len) {
  size_t inner_total = FMP_INNER_HEADER_SIZE + inner_len;
  size_t encrypted_len = inner_total + TAG_SIZE;
  size_t total = FMP_PREFIX_SIZE + FMP_IDX_SIZE + 8 + encrypted_len;

  if (out_len < total)
    return 0;

  // payload_len = inner plaintext size only (NOT including idx/counter/tag)
  // FIPS calculate_frame_len: ESTABLISHED_HEADER_SIZE(16) + payload_len + TAG_SIZE(16)
  uint16_t payload_len = static_cast<uint16_t>(inner_total);
  fmp_build_prefix(PHASE_ESTABLISHED, 0x00, payload_len, out);
  size_t pos = FMP_PREFIX_SIZE;

  for (int i = 0; i < 4; i++) {
    out[pos + i] = static_cast<uint8_t>((receiver_idx >> (i * 8)) & 0xFF);
  }
  pos += FMP_IDX_SIZE;

  for (int i = 0; i < 8; i++) {
    out[pos + i] = static_cast<uint8_t>((counter >> (i * 8)) & 0xFF);
  }
  pos += 8;

  uint8_t outer_header[FMP_ENCRYPTED_HEADER_SIZE];
  std::memcpy(outer_header, out, pos);

  uint8_t inner[512];
  for (int i = 0; i < 4; i++) {
    inner[i] = static_cast<uint8_t>((timestamp >> (i * 8)) & 0xFF);
  }
  inner[4] = msg_type;
  if (inner_len > 0) {
    std::memcpy(inner + FMP_INNER_HEADER_SIZE, inner_payload, inner_len);
  }

  size_t enc_len = aead_encrypt(key, counter, outer_header, FMP_ENCRYPTED_HEADER_SIZE, inner, inner_total, out + pos);
  if (enc_len == 0)
    return 0;

  return total;
}

bool fmp_parse_message(const uint8_t *data, size_t len, FmpParsedMessage &msg) {
  uint8_t phase = 0, flags = 0;
  uint16_t payload_len = 0;
  if (!fmp_parse_prefix(data, len, phase, flags, payload_len))
    return false;

  const uint8_t *payload = data + FMP_PREFIX_SIZE;
  size_t payload_total = len - FMP_PREFIX_SIZE;

  msg.phase = static_cast<FmpPhase>(phase);
  msg.sender_idx = 0;
  msg.receiver_idx = 0;
  msg.counter = 0;
  msg.payload = nullptr;
  msg.payload_len = 0;

  switch (phase) {
    case PHASE_MSG1: {
      if (payload_total < FMP_IDX_SIZE)
        return false;
      msg.sender_idx = static_cast<uint32_t>(payload[0]) | (static_cast<uint32_t>(payload[1]) << 8) |
                    (static_cast<uint32_t>(payload[2]) << 16) | (static_cast<uint32_t>(payload[3]) << 24);
      msg.payload = payload + FMP_IDX_SIZE;
      msg.payload_len = payload_total - FMP_IDX_SIZE;
      return true;
    }
    case PHASE_MSG2: {
      if (payload_total < FMP_IDX_SIZE * 2)
        return false;
      msg.sender_idx = static_cast<uint32_t>(payload[0]) | (static_cast<uint32_t>(payload[1]) << 8) |
                    (static_cast<uint32_t>(payload[2]) << 16) | (static_cast<uint32_t>(payload[3]) << 24);
      msg.receiver_idx = static_cast<uint32_t>(payload[4]) | (static_cast<uint32_t>(payload[5]) << 8) |
                      (static_cast<uint32_t>(payload[6]) << 16) | (static_cast<uint32_t>(payload[7]) << 24);
      msg.payload = payload + FMP_IDX_SIZE * 2;
      msg.payload_len = payload_total - FMP_IDX_SIZE * 2;
      return true;
    }
    case PHASE_ESTABLISHED: {
      if (payload_total < FMP_IDX_SIZE + 8)
        return false;
      msg.receiver_idx = static_cast<uint32_t>(payload[0]) | (static_cast<uint32_t>(payload[1]) << 8) |
                      (static_cast<uint32_t>(payload[2]) << 16) | (static_cast<uint32_t>(payload[3]) << 24);
      msg.counter = 0;
      for (int i = 0; i < 8; i++) {
        msg.counter |= static_cast<uint64_t>(payload[FMP_IDX_SIZE + i]) << (i * 8);
      }
      msg.payload = payload + FMP_IDX_SIZE + 8;
      msg.payload_len = payload_total - FMP_IDX_SIZE - 8;
      return true;
    }
    default:
      return false;
  }
}

size_t fmp_decrypt_established(const uint8_t *key, uint64_t counter, const uint8_t *aad, size_t aad_len,
                             const uint8_t *ciphertext, size_t ct_len, uint8_t *out) {
  if (ct_len < TAG_SIZE + FMP_INNER_HEADER_SIZE)
    return 0;
  return aead_decrypt(key, counter, aad, aad_len, ciphertext, ct_len, out);
}

size_t fmp_calculate_frame_len(const uint8_t *prefix, size_t prefix_len) {
  if (prefix_len < FMP_PREFIX_SIZE)
    return 0;
  uint8_t version = prefix[0] >> 4;
  if (version != FMP_VERSION)
    return 0;
  uint8_t phase = prefix[0] & 0x0F;
  uint16_t payload_len = static_cast<uint16_t>(prefix[2]) | (static_cast<uint16_t>(prefix[3]) << 8);
  if (phase == PHASE_ESTABLISHED) {
    return FMP_ENCRYPTED_HEADER_SIZE + payload_len + TAG_SIZE;
  }
  return FMP_PREFIX_SIZE + payload_len;
}

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
