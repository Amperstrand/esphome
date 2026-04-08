#ifdef USE_FIPS_BLE

#include "fips_ble_selftest.h"

#include "fips_noise.h"
#include "esphome/core/log.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace esphome::fips_ble {

static const char *const TAG = "fips_selftest";
static constexpr size_t MAX_SELFTEST_HEX_BYTES = MSG1_NOISE_SIZE;

template<size_t N> constexpr std::array<uint8_t, N> repeat_byte(uint8_t value) {
  std::array<uint8_t, N> out{};
  for (size_t i = 0; i < N; i++) {
    out[i] = value;
  }
  return out;
}

struct IKSelftestVector {
  const char *name;
  const uint8_t *initiator_eph_secret;
  const uint8_t *initiator_static_secret;
  const uint8_t *initiator_static_pub;
  const uint8_t *initiator_epoch;
  const uint8_t *responder_static_secret;
  const uint8_t *responder_static_pub;
  const uint8_t *responder_eph_secret;
  const uint8_t *responder_epoch;
  const char *expected_initiator_pub;
  const char *expected_initiator_epoch;
  const char *expected_msg1;
  const char *expected_msg2;
  const char *expected_send_key;
  const char *expected_recv_key;
};

static constexpr auto SECRET_00 = repeat_byte<PRIVKEY_SIZE>(0x00);
static constexpr auto SECRET_01 = repeat_byte<PRIVKEY_SIZE>(0x01);
static constexpr auto SECRET_02 = repeat_byte<PRIVKEY_SIZE>(0x02);
static constexpr auto SECRET_11 = repeat_byte<PRIVKEY_SIZE>(0x11);
static constexpr auto SECRET_22 = repeat_byte<PRIVKEY_SIZE>(0x22);

static constexpr std::array<uint8_t, PUBKEY_SIZE> ECDH_PUBKEY_01 = {
    0x02, 0x4d, 0x4b, 0x6c, 0xd1, 0x36, 0x10, 0x32, 0xca, 0x9b, 0xd2,
    0xae, 0xb9, 0xd9, 0x00, 0xaa, 0x4d, 0x45, 0xd9, 0xea, 0xd8, 0x0a,
    0xc9, 0x42, 0x33, 0x74, 0xc4, 0x51, 0xa7, 0x25, 0x4d, 0x07, 0x66,
};
static constexpr std::array<uint8_t, PUBKEY_SIZE> ECDH_PUBKEY_02 = {
    0x03, 0x1b, 0x84, 0xc5, 0x56, 0x7b, 0x12, 0x64, 0x40, 0x99, 0x5d,
    0x3e, 0xd5, 0xaa, 0xba, 0x05, 0x65, 0xd7, 0x1e, 0x18, 0x34, 0x60,
    0x48, 0x19, 0xff, 0x9c, 0x17, 0xf5, 0xe9, 0xd5, 0xdd, 0x07, 0x8f,
};
static constexpr std::array<uint8_t, 5> PLAINTEXT_HELLO = {0x68, 0x65, 0x6c, 0x6c, 0x6f};
static constexpr std::array<uint8_t, 20> PLAINTEXT_HANDSHAKE = {
    0x6e, 0x6f, 0x69, 0x73, 0x65, 0x20, 0x68, 0x61, 0x6e, 0x64,
    0x73, 0x68, 0x61, 0x6b, 0x65, 0x20, 0x74, 0x65, 0x73, 0x74,
};
static constexpr std::array<uint8_t, EPOCH_SIZE> EPOCH_01 = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static constexpr std::array<uint8_t, EPOCH_SIZE> EPOCH_02 = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static constexpr std::array<uint8_t, PRIVKEY_SIZE> IK2_INITIATOR_EPH_SECRET = {
    0x04, 0xb5, 0xe1, 0xc0, 0xdb, 0x6e, 0x59, 0xdf, 0xf5, 0xcd, 0x64,
    0xe2, 0xd4, 0xc9, 0xf3, 0xa6, 0x5a, 0x89, 0xb8, 0x4d, 0x0c, 0x23,
    0xf1, 0xa8, 0x2b, 0x7e, 0x6d, 0x4c, 0x0f, 0x1e, 0x2b, 0x3a,
};
static constexpr std::array<uint8_t, PRIVKEY_SIZE> IK2_INITIATOR_STATIC_SECRET = {
    0x3a, 0x7b, 0xd3, 0xe2, 0x36, 0x0a, 0x3d, 0x29, 0xee, 0xa4, 0x36,
    0xfc, 0xfb, 0x7e, 0x44, 0xc7, 0x35, 0xd1, 0x17, 0xc4, 0x2d, 0x1c,
    0x18, 0x35, 0x42, 0x0b, 0x6b, 0x99, 0x42, 0xdd, 0x4f, 0x1b,
};
static constexpr std::array<uint8_t, PUBKEY_SIZE> IK2_INITIATOR_STATIC_PUB = {
    0x02, 0x92, 0x76, 0x3c, 0xc6, 0xaf, 0x95, 0x7a, 0xcc, 0x81, 0x59,
    0xc3, 0xd0, 0xfb, 0xcd, 0x9f, 0x00, 0xe2, 0x0b, 0x42, 0x22, 0xc1,
    0xdc, 0xff, 0x07, 0x10, 0x71, 0x90, 0xff, 0x5f, 0x36, 0x67, 0xd8,
};
static constexpr std::array<uint8_t, PRIVKEY_SIZE> IK2_RESPONDER_STATIC_SECRET = {
    0x13, 0x2f, 0xc3, 0x6b, 0xb0, 0x4a, 0x1e, 0x72, 0x98, 0x58, 0x2f,
    0x84, 0xbe, 0x69, 0x47, 0x23, 0x54, 0x17, 0x0f, 0x40, 0xbe, 0xc7,
    0x39, 0x42, 0x7f, 0xa4, 0x6c, 0x13, 0x6a, 0x9a, 0x18, 0x2a,
};
static constexpr std::array<uint8_t, PUBKEY_SIZE> IK2_RESPONDER_STATIC_PUB = {
    0x03, 0x90, 0xf4, 0x40, 0x23, 0x29, 0x52, 0xb5, 0x14, 0xd5, 0x08,
    0x51, 0xff, 0x11, 0x0c, 0x72, 0xd5, 0xea, 0xc2, 0x05, 0xf7, 0xb6,
    0x45, 0x54, 0xa1, 0xe0, 0x14, 0x89, 0x28, 0x75, 0xb7, 0x5d, 0x4c,
};
static constexpr std::array<uint8_t, PRIVKEY_SIZE> IK2_RESPONDER_EPH_SECRET = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56,
    0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
    0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
};

static constexpr char ECDH_SHARED_SECRET_HEX[] = "442e7d713aece59b796393c4eb7deb384863209f6751a93d84faf8955d41a284";
static constexpr char AEAD_1_CIPHERTEXT_HEX[] = "f7628bd23adce962340b6fd6a0a4d1fe736f29456f";
static constexpr char AEAD_2_CIPHERTEXT_HEX[] =
    "6f4824a28b727ea36a9f1ae5cfcf3e729dee1c7b3254436b3794a1a6df417a06deb48417";
static constexpr char MIX_KEY_1_CK_HEX[] = "0d1e94c641dfd61a216ed04f1b390079459dea71ae4d466f574c260d1b6554db";
static constexpr char MIX_KEY_1_K_HEX[] = "b4069ed7a4a753cb5c779fb38a33dc02c63199ce58b6b7bf56286b844cacc358";
static constexpr char SPLIT_1_K1_HEX[] = "b5a5789af1d00c74773ef327dc63f0f11c7041252d4916c43a252b92e3358ad2";
static constexpr char SPLIT_1_K2_HEX[] = "72d7e204fba7b0ac19964ebcba5e88e3609cb8c3cafa4b940945df49da83680f";
static constexpr char IK1_MSG1_HEX[] =
    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa8fee0d0b0fdac4c25e04277d2b48007f780c1567c523b6aa1e4e0cbc1eb89014dd30e04afd519594cefac9d8e19b0ba43ea1e8919f3911117f9997bf69071d6e47aa4b049bfdf715d2";
static constexpr char IK1_MSG2_HEX[] =
    "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27603fb0cf0105b12cd1d7359597ee566c8de63d09ef2be9b2";
static constexpr char IK1_INITIATOR_PUB_HEX[] = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
static constexpr char IK1_SEND_KEY_HEX[] = "29dbc3c0d2b8689bee6b338fdd23b055e68b52a73111d4b455b1533ad778017c";
static constexpr char IK1_RECV_KEY_HEX[] = "cba6a8145471c1c5fa4d737d93a568ea9048d9cff688f3882f77a86c98a92afb";
static constexpr char IK2_MSG1_HEX[] =
    "0301fa63208ecf97557fa4b6ce5ff4f33b06fe2e4b7f2576d9311a8aa5807038a908ca027ddb9a5a2c532cc0e349c579f4164fb59e702149610923bd0a08a825d7ea0582b3b393e5e5eadbb809e1062c64c98af6be9de3c0e314389433a8bff63d39bebce4421ea0a6de";
static constexpr char IK2_MSG2_HEX[] =
    "02bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020dad632b11a071a437247279a63b258355d759694b79fbcef4";
static constexpr char IK2_INITIATOR_PUB_HEX[] = "0292763cc6af957acc8159c3d0fbcd9f00e20b4222c1dcff07107190ff5f3667d8";
static constexpr char EPOCH_01_HEX[] = "0100000000000000";
static constexpr char IK2_SEND_KEY_HEX[] = "51d787e6b04faf396172b234a302c29c535da249fa69e644af8785e9b973dbaa";
static constexpr char IK2_RECV_KEY_HEX[] = "2ebfeb3f6db07b4e0a8d1afe1336b0c91841346602997cff80b9a6066b0a1fd1";

static bool hex_char_to_nibble(char c, uint8_t &value) {
  if (c >= '0' && c <= '9') {
    value = static_cast<uint8_t>(c - '0');
    return true;
  }
  if (c >= 'a' && c <= 'f') {
    value = static_cast<uint8_t>(c - 'a' + 10);
    return true;
  }
  if (c >= 'A' && c <= 'F') {
    value = static_cast<uint8_t>(c - 'A' + 10);
    return true;
  }
  return false;
}

static size_t hex_length(const char *hex) {
  size_t len = 0;
  while (hex[len] != '\0') {
    len++;
  }
  return len;
}

static bool parse_hex_string(const char *hex, uint8_t *out, size_t out_len) {
  const size_t len = hex_length(hex);
  if ((len % 2) != 0 || (len / 2) != out_len) {
    return false;
  }

  for (size_t i = 0; i < out_len; i++) {
    uint8_t hi = 0;
    uint8_t lo = 0;
    if (!hex_char_to_nibble(hex[i * 2], hi) || !hex_char_to_nibble(hex[i * 2 + 1], lo)) {
      return false;
    }
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

static void bytes_to_hex(const uint8_t *data, size_t len, char *out) {
  static constexpr char HEX_DIGITS[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = HEX_DIGITS[(data[i] >> 4) & 0x0F];
    out[i * 2 + 1] = HEX_DIGITS[data[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

static bool check_condition(const char *name, bool condition) {
  if (condition) {
    ESP_LOGI(TAG, "PASS: %s", name);
    return true;
  }

  ESP_LOGE(TAG, "FAIL: %s", name);
  return false;
}

static bool check_hex(const char *name, const uint8_t *actual, size_t actual_len, const char *expected_hex) {
  uint8_t expected[MAX_SELFTEST_HEX_BYTES];
  const size_t expected_hex_len = hex_length(expected_hex);
  if ((expected_hex_len % 2) != 0) {
    ESP_LOGE(TAG, "FAIL: %s: invalid expected hex", name);
    return false;
  }

  const size_t expected_len = expected_hex_len / 2;
  if (expected_len > MAX_SELFTEST_HEX_BYTES || actual_len != expected_len ||
      !parse_hex_string(expected_hex, expected, expected_len)) {
    char actual_hex[MAX_SELFTEST_HEX_BYTES * 2 + 1];
    bytes_to_hex(actual, actual_len <= MAX_SELFTEST_HEX_BYTES ? actual_len : MAX_SELFTEST_HEX_BYTES, actual_hex);
    ESP_LOGE(TAG, "FAIL: %s: expected=%s actual=%s", name, expected_hex, actual_hex);
    return false;
  }

  if (std::memcmp(actual, expected, expected_len) != 0) {
    char actual_hex[MAX_SELFTEST_HEX_BYTES * 2 + 1];
    bytes_to_hex(actual, actual_len, actual_hex);
    ESP_LOGE(TAG, "FAIL: %s: expected=%s actual=%s", name, expected_hex, actual_hex);
    return false;
  }

  ESP_LOGI(TAG, "PASS: %s", name);
  return true;
}

static void record_test(bool ok, size_t &passed, size_t &total) {
  total++;
  if (ok) {
    passed++;
  }
}

static bool run_ik_test(const IKSelftestVector &vector, size_t &passed, size_t &total) {
  bool all_ok = true;
  const bool is_ik_1 = vector.name[3] == '1';
  const char *init_name = is_ik_1 ? "ik-1.init" : "ik-2.init";
  const char *msg1_name = is_ik_1 ? "ik-1.msg1" : "ik-2.msg1";
  const char *responder_init_name = is_ik_1 ? "ik-1.responder_init" : "ik-2.responder_init";
  const char *read_message1_name = is_ik_1 ? "ik-1.read_message1" : "ik-2.read_message1";
  const char *initiator_pub_name = is_ik_1 ? "ik-1.initiator_pub" : "ik-2.initiator_pub";
  const char *initiator_epoch_name = is_ik_1 ? "ik-1.initiator_epoch" : "ik-2.initiator_epoch";
  const char *msg2_name = is_ik_1 ? "ik-1.msg2" : "ik-2.msg2";
  const char *read_message2_name = is_ik_1 ? "ik-1.read_message2" : "ik-2.read_message2";
  const char *send_key_name = is_ik_1 ? "ik-1.send_key" : "ik-2.send_key";
  const char *recv_key_name = is_ik_1 ? "ik-1.recv_key" : "ik-2.recv_key";
  const char *responder_send_key_name = is_ik_1 ? "ik-1.responder_send_key" : "ik-2.responder_send_key";
  const char *responder_recv_key_name = is_ik_1 ? "ik-1.responder_recv_key" : "ik-2.responder_recv_key";

  NoiseIKInitiator initiator;
  bool ok = initiator.init(vector.initiator_eph_secret, vector.initiator_static_secret, vector.responder_static_pub);
  record_test(check_condition(init_name, ok), passed, total);
  all_ok = all_ok && ok;
  if (!ok) {
    return false;
  }

  uint8_t msg1[MSG1_NOISE_SIZE];
  const size_t msg1_len = initiator.write_message1(vector.initiator_static_pub, vector.initiator_epoch, msg1);
  if (msg1_len != MSG1_NOISE_SIZE) {
    ok = check_condition(msg1_name, false);
  } else {
    ok = check_hex(msg1_name, msg1, msg1_len, vector.expected_msg1);
  }
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  NoiseIKResponder responder;
  ok = responder.init(vector.responder_static_secret, vector.responder_static_pub, msg1);
  record_test(check_condition(responder_init_name, ok), passed, total);
  all_ok = all_ok && ok;
  if (!ok) {
    return false;
  }

  uint8_t initiator_pub[PUBKEY_SIZE];
  uint8_t initiator_epoch[EPOCH_SIZE];
  ok = responder.read_message1(msg1 + PUBKEY_SIZE, msg1_len - PUBKEY_SIZE, initiator_pub, initiator_epoch);
  record_test(check_condition(read_message1_name, ok), passed, total);
  all_ok = all_ok && ok;
  if (!ok) {
    return false;
  }

  ok = check_hex(initiator_pub_name, initiator_pub, PUBKEY_SIZE, vector.expected_initiator_pub) &&
       check_hex(initiator_epoch_name, initiator_epoch, EPOCH_SIZE, vector.expected_initiator_epoch);
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  uint8_t msg2[MSG2_NOISE_SIZE];
  const size_t msg2_len = responder.write_message2(vector.responder_eph_secret, vector.responder_epoch, msg2);
  if (msg2_len != MSG2_NOISE_SIZE) {
    ok = check_condition(msg2_name, false);
  } else {
    ok = check_hex(msg2_name, msg2, msg2_len, vector.expected_msg2);
  }
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  ok = initiator.read_message2(msg2, msg2_len);
  record_test(check_condition(read_message2_name, ok), passed, total);
  all_ok = all_ok && ok;
  if (!ok) {
    return false;
  }

  const TransportState initiator_state = initiator.finalize();
  ok = check_hex(send_key_name, initiator_state.send_key.data(), HASH_SIZE, vector.expected_send_key) &&
       check_hex(recv_key_name, initiator_state.recv_key.data(), HASH_SIZE, vector.expected_recv_key);
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  const TransportState responder_state = responder.finalize();
  ok = check_hex(responder_send_key_name, responder_state.send_key.data(), HASH_SIZE, vector.expected_recv_key) &&
       check_hex(responder_recv_key_name, responder_state.recv_key.data(), HASH_SIZE, vector.expected_send_key);
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  return all_ok;
}

bool run_fips_selftest() {
  size_t passed = 0;
  size_t total = 0;
  bool all_ok = true;

  uint8_t shared_secret[HASH_SIZE];
  bool ok = x_only_ecdh(SECRET_01.data(), ECDH_PUBKEY_02.data(), shared_secret) &&
            check_hex("ecdh-1", shared_secret, HASH_SIZE, ECDH_SHARED_SECRET_HEX);
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  ok = x_only_ecdh(SECRET_02.data(), ECDH_PUBKEY_01.data(), shared_secret) &&
       check_hex("ecdh-2", shared_secret, HASH_SIZE, ECDH_SHARED_SECRET_HEX);
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  uint8_t aead_out_1[PLAINTEXT_HELLO.size() + TAG_SIZE];
  size_t aead_len_1 =
      aead_encrypt(SECRET_00.data(), 0, nullptr, 0, PLAINTEXT_HELLO.data(), PLAINTEXT_HELLO.size(), aead_out_1);
  ok = aead_len_1 == sizeof(aead_out_1) && check_hex("aead-1.encrypt", aead_out_1, aead_len_1, AEAD_1_CIPHERTEXT_HEX);
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  uint8_t aead_plain_1[PLAINTEXT_HELLO.size()];
  size_t plain_len_1 = aead_decrypt(SECRET_00.data(), 0, nullptr, 0, aead_out_1, aead_len_1, aead_plain_1);
  ok = plain_len_1 == PLAINTEXT_HELLO.size() &&
       std::memcmp(aead_plain_1, PLAINTEXT_HELLO.data(), PLAINTEXT_HELLO.size()) == 0 &&
       check_hex("aead-1.decrypt", aead_plain_1, plain_len_1, "68656c6c6f");
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  uint8_t aead_out_2[PLAINTEXT_HANDSHAKE.size() + TAG_SIZE];
  size_t aead_len_2 = aead_encrypt(SECRET_01.data(), 0, nullptr, 0, PLAINTEXT_HANDSHAKE.data(),
                                   PLAINTEXT_HANDSHAKE.size(), aead_out_2);
  ok = aead_len_2 == sizeof(aead_out_2) &&
       check_hex("aead-2.encrypt", aead_out_2, aead_len_2, AEAD_2_CIPHERTEXT_HEX);
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  uint8_t aead_plain_2[PLAINTEXT_HANDSHAKE.size()];
  size_t plain_len_2 = aead_decrypt(SECRET_01.data(), 0, nullptr, 0, aead_out_2, aead_len_2, aead_plain_2);
  ok = plain_len_2 == PLAINTEXT_HANDSHAKE.size() &&
       std::memcmp(aead_plain_2, PLAINTEXT_HANDSHAKE.data(), PLAINTEXT_HANDSHAKE.size()) == 0 &&
       check_hex("aead-2.decrypt", aead_plain_2, plain_len_2, "6e6f6973652068616e647368616b652074657374");
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  uint8_t new_ck[HASH_SIZE];
  uint8_t new_k[HASH_SIZE];
  mix_key(SECRET_01.data(), SECRET_02.data(), new_ck, new_k);
  ok = check_hex("mix_key-1.ck", new_ck, HASH_SIZE, MIX_KEY_1_CK_HEX) &&
       check_hex("mix_key-1.k", new_k, HASH_SIZE, MIX_KEY_1_K_HEX);
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  uint8_t split_k1[HASH_SIZE];
  uint8_t split_k2[HASH_SIZE];
  split(SECRET_01.data(), split_k1, split_k2);
  ok = check_hex("split-1.k1", split_k1, HASH_SIZE, SPLIT_1_K1_HEX) &&
       check_hex("split-1.k2", split_k2, HASH_SIZE, SPLIT_1_K2_HEX);
  record_test(ok, passed, total);
  all_ok = all_ok && ok;

  static constexpr IKSelftestVector IK1_VECTOR = {
      "ik-1",        SECRET_11.data(), SECRET_01.data(), ECDH_PUBKEY_02.data(), EPOCH_01.data(),
      SECRET_02.data(), ECDH_PUBKEY_01.data(), SECRET_22.data(), EPOCH_02.data(), IK1_INITIATOR_PUB_HEX,
      EPOCH_01_HEX,   IK1_MSG1_HEX, IK1_MSG2_HEX, IK1_SEND_KEY_HEX, IK1_RECV_KEY_HEX,
  };
  ok = run_ik_test(IK1_VECTOR, passed, total);
  all_ok = all_ok && ok;

  static constexpr IKSelftestVector IK2_VECTOR = {
      "ik-2",
      IK2_INITIATOR_EPH_SECRET.data(),
      IK2_INITIATOR_STATIC_SECRET.data(),
      IK2_INITIATOR_STATIC_PUB.data(),
      EPOCH_01.data(),
      IK2_RESPONDER_STATIC_SECRET.data(),
      IK2_RESPONDER_STATIC_PUB.data(),
      IK2_RESPONDER_EPH_SECRET.data(),
      EPOCH_02.data(),
      IK2_INITIATOR_PUB_HEX,
      EPOCH_01_HEX,
      IK2_MSG1_HEX,
      IK2_MSG2_HEX,
      IK2_SEND_KEY_HEX,
      IK2_RECV_KEY_HEX,
  };
  ok = run_ik_test(IK2_VECTOR, passed, total);
  all_ok = all_ok && ok;

  ESP_LOGI(TAG, "Results: %u/%u passed", static_cast<unsigned>(passed), static_cast<unsigned>(total));
  return all_ok;
}

}

#endif
