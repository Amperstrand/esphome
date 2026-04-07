#pragma once

#ifdef USE_FIPS_BLE

#include <array>
#include <cstdint>
#include <cstddef>

namespace esphome::fips_ble {

static constexpr uint8_t FMP_VERSION = 0;
static constexpr size_t FMP_PREFIX_SIZE = 4;
static constexpr size_t FMP_IDX_SIZE = 4;
static constexpr size_t FMP_ENCRYPTED_HEADER_SIZE = 16;
static constexpr size_t FMP_INNER_HEADER_SIZE = 5;
static constexpr size_t FMP_ENCRYPTED_MIN_SIZE = 32;

static constexpr size_t FMP_MSG1_WIRE_SIZE = 114;
static constexpr size_t FMP_MSG2_WIRE_SIZE = 69;

static constexpr uint8_t PHASE_ESTABLISHED = 0x00;
static constexpr uint8_t PHASE_MSG1 = 0x01;
static constexpr uint8_t PHASE_MSG2 = 0x02;

static constexpr uint8_t MSG_HEARTBEAT = 0x51;
static constexpr uint8_t MSG_SESSION_DATAGRAM = 0x00;
static constexpr uint8_t MSG_SENDER_REPORT = 0x01;
static constexpr uint8_t MSG_RECEIVER_REPORT = 0x02;
static constexpr uint8_t MSG_DISCONNECT = 0x50;

enum class FmpPhase : uint8_t { Established = 0x00, Msg1 = 0x01, Msg2 = 0x02, Unknown = 0xFF };

struct FmpParsedMessage {
  FmpPhase phase;
  uint32_t sender_idx;
  uint32_t receiver_idx;
  uint64_t counter;
  const uint8_t *payload;
  size_t payload_len;
};

void fmp_build_prefix(uint8_t phase, uint8_t flags, uint16_t payload_len, uint8_t out[FMP_PREFIX_SIZE]);

bool fmp_parse_prefix(const uint8_t *data, size_t len, uint8_t &phase, uint8_t &flags, uint16_t &payload_len);

size_t fmp_build_msg1(uint32_t sender_idx, const uint8_t *noise_payload, size_t noise_len, uint8_t *out, size_t out_len);

size_t fmp_build_msg2(uint32_t sender_idx, uint32_t receiver_idx, const uint8_t *noise_payload, size_t noise_len,
                       uint8_t *out, size_t out_len);

size_t fmp_build_established(uint32_t receiver_idx, uint64_t counter, uint8_t msg_type, uint32_t timestamp,
                              const uint8_t *inner_payload, size_t inner_len, const uint8_t *key, uint8_t *out,
                              size_t out_len);

bool fmp_parse_message(const uint8_t *data, size_t len, FmpParsedMessage &msg);

size_t fmp_decrypt_established(const uint8_t *key, const FmpParsedMessage &msg, uint8_t *out, size_t out_len);

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
