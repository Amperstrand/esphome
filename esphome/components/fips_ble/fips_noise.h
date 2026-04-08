#pragma once

#ifdef USE_FIPS_BLE

#include <array>
#include <cstdint>

#include <mbedtls/chachapoly.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

namespace esphome::fips_ble {

static constexpr size_t PUBKEY_SIZE = 33;
static constexpr size_t PRIVKEY_SIZE = 32;
static constexpr size_t HASH_SIZE = 32;
static constexpr size_t TAG_SIZE = 16;
static constexpr size_t EPOCH_SIZE = 8;
static constexpr size_t NONCE_SIZE = 12;

static constexpr size_t MSG1_NOISE_SIZE = 106;
static constexpr size_t MSG2_NOISE_SIZE = 57;
static constexpr size_t XK_MSG1_NOISE_SIZE = 33;
static constexpr size_t XK_MSG2_NOISE_SIZE = 57;
static constexpr size_t XK_MSG3_NOISE_SIZE = 73;

struct TransportState {
  std::array<uint8_t, 32> send_key{};
  std::array<uint8_t, 32> recv_key{};
  uint64_t send_nonce{0};
  uint64_t recv_nonce{0};
};

// DH output: SHA256(shared_secret_point.x_coordinate)
bool x_only_ecdh(const uint8_t *secret_key, const uint8_t *pub_key, uint8_t *out);

// Compute compressed secp256k1 public key from secret key
bool ecdh_pubkey(const uint8_t *secret_key, uint8_t *pub_out);

// SHA256(h || data)
void hash_concat(const uint8_t *h, const uint8_t *data, size_t data_len, uint8_t *out);

// SHA256(data)
void hash_one(const uint8_t *data, size_t len, uint8_t *out);

// HKDF-SHA256(ck, ikm) -> (new_ck, k)
void mix_key(const uint8_t *ck, const uint8_t *ikm, uint8_t *new_ck, uint8_t *k);

void split(const uint8_t *ck, uint8_t *k1, uint8_t *k2);

// ChaCha20-Poly1305 encrypt. Returns total size (plaintext_len + 16)
size_t aead_encrypt(const uint8_t *key, uint64_t nonce_ctr, const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t pt_len, uint8_t *out);

// ChaCha20-Poly1305 decrypt. Returns plaintext_len on success, 0 on failure
size_t aead_decrypt(const uint8_t *key, uint64_t nonce_ctr, const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ct_len, uint8_t *out);

class NoiseIKInitiator {
 public:
  bool init(const uint8_t *eph_secret, const uint8_t *s_secret, const uint8_t *rs_pub);
  size_t write_message1(const uint8_t *my_static_pub, const uint8_t *epoch, uint8_t *out);
  bool read_message2(const uint8_t *data, size_t len);
  TransportState finalize();

 protected:
  std::array<uint8_t, HASH_SIZE> h_{};
  std::array<uint8_t, HASH_SIZE> ck_{};
  std::array<uint8_t, HASH_SIZE> k_{};
  std::array<uint8_t, PRIVKEY_SIZE> e_priv_{};
  std::array<uint8_t, PUBKEY_SIZE> e_pub_{};
  std::array<uint8_t, PRIVKEY_SIZE> s_priv_{};
  std::array<uint8_t, PUBKEY_SIZE> s_pub_{};
  std::array<uint8_t, PUBKEY_SIZE> rs_{};
  uint64_t n_{0};
};

void node_addr_from_pubkey(const uint8_t *pubkey, uint8_t *addr);

class NoiseIKResponder {
 public:
  bool init(const uint8_t *s_secret, const uint8_t *s_pub, const uint8_t *peer_e_pub);
  bool read_message1(const uint8_t *data, size_t len, uint8_t *out_initiator_pub, uint8_t *out_epoch);
  size_t write_message2(const uint8_t *re_eph_secret, const uint8_t *epoch, uint8_t *out);
  TransportState finalize();

 protected:
  std::array<uint8_t, HASH_SIZE> h_{};
  std::array<uint8_t, HASH_SIZE> ck_{};
  std::array<uint8_t, HASH_SIZE> k_{};
  std::array<uint8_t, PRIVKEY_SIZE> s_priv_{};
  std::array<uint8_t, PUBKEY_SIZE> peer_e_pub_{};
  uint64_t n_{0};
};

class NoiseXKResponder {
 public:
  bool init(const uint8_t *s_secret, const uint8_t *ei_pub);
  bool read_message1(const uint8_t *data, size_t len);
  size_t write_message2(const uint8_t *re_eph_secret, const uint8_t *epoch, uint8_t *out);
  bool read_message3(const uint8_t *data, size_t len);
  TransportState finalize();

 protected:
  std::array<uint8_t, HASH_SIZE> h_{};
  std::array<uint8_t, HASH_SIZE> ck_{};
  std::array<uint8_t, HASH_SIZE> k_{};
  std::array<uint8_t, PRIVKEY_SIZE> re_priv_{};
  std::array<uint8_t, PUBKEY_SIZE> re_pub_{};
  std::array<uint8_t, PRIVKEY_SIZE> s_priv_{};
  std::array<uint8_t, PUBKEY_SIZE> s_pub_{};
  std::array<uint8_t, PUBKEY_SIZE> ei_pub_{};
  uint64_t n_{0};
  bool has_read_msg3_{false};
};

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
