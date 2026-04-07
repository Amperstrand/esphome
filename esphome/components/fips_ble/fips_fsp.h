#pragma once

#ifdef USE_ESP32
#ifdef USE_FIPS_BLE

#include <array>
#include <cstdint>
#include <cstddef>

namespace esphome::fips_ble {

static constexpr uint8_t FSP_VERSION = 0;
static constexpr size_t FSP_PREFIX_SIZE = 4;
static constexpr size_t FSP_HEADER_SIZE = 12;
static constexpr size_t FSP_INNER_HEADER_SIZE = 6;
static constexpr size_t FSP_ENCRYPTED_MIN_SIZE = 28;
static constexpr size_t NODE_ADDR_SIZE = 16;

static constexpr uint8_t FSP_PHASE_ESTABLISHED = 0x00;
static constexpr uint8_t FSP_PHASE_SESSION_SETUP = 0x01;
static constexpr uint8_t FSP_PHASE_SESSION_ACK = 0x02;
static constexpr uint8_t FSP_PHASE_SESSION_MSG3 = 0x03;

static constexpr uint8_t FSP_MSG_DATA = 0x10;

static constexpr uint8_t FSP_FLAG_COORDS_PRESENT = 0x01;
static constexpr uint8_t FSP_FLAG_KEY_EPOCH = 0x02;

static constexpr size_t FSP_DATAGRAM_HEADER_SIZE = 4;
static constexpr size_t SESSION_DATAGRAM_BODY_SIZE = 35;
static constexpr size_t SESSION_DATAGRAM_HEADER_SIZE = 36;

static constexpr size_t XK_MSG1_SIZE = 33;
static constexpr size_t XK_MSG2_SIZE = 57;
static constexpr size_t XK_MSG3_SIZE = 73;

size_t fsp_build_session_setup(uint8_t session_flags, const uint8_t *src_addr, const uint8_t *dst_addr,
                                 const uint8_t *handshake, size_t hs_len, uint8_t *out, size_t out_len);

size_t fsp_parse_session_setup(const uint8_t *data, size_t len, uint8_t &session_flags, const uint8_t *&hs_payload,
                                size_t &hs_len);

size_t fsp_build_session_ack(const uint8_t *src_addr, const uint8_t *dst_addr, const uint8_t *handshake, size_t hs_len,
                              uint8_t *out, size_t out_len);

size_t fsp_parse_session_ack(const uint8_t *data, size_t len, const uint8_t *&hs_payload, size_t &hs_len);

size_t fsp_build_session_msg3(const uint8_t *handshake, size_t hs_len, uint8_t *out, size_t out_len);

size_t fsp_parse_session_msg3(const uint8_t *data, size_t len, const uint8_t *&hs_payload, size_t &hs_len);

void fsp_build_session_datagram_body(const uint8_t *src, const uint8_t *dst, uint8_t out[SESSION_DATAGRAM_BODY_SIZE]);

bool fsp_parse_session_datagram(const uint8_t *data, size_t len, uint16_t &src_port, uint16_t &dst_port,
                                   const uint8_t *&payload, size_t &payload_len);

size_t fsp_build_data_message(uint64_t counter, uint32_t timestamp_ms, const uint8_t *payload, size_t payload_len,
                                const uint8_t *key, uint8_t *out, size_t out_len);

bool fsp_parse_data_message(const uint8_t *key, const uint8_t *data, size_t len, uint8_t &flags, uint64_t &counter,
                               uint32_t &timestamp_ms, uint8_t &msg_type, const uint8_t *&payload,
                               size_t &payload_len);

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
#endif  // USE_ESP32
