#ifdef USE_FIPS_BLE

#include "fips_noise.h"
#include "esphome/core/log.h"
#include <cstring>
#include <mbedtls/chachapoly.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <esp_random.h>

namespace esphome::fips_ble {

static const char *const TAG = "fips_ble.noise";

static int fips_rng(void *ctx, unsigned char *buf, size_t len) {
  esp_fill_random(buf, len);
  (void) ctx;
  return 0;
}

static const uint8_t PROTOCOL_NAME_IK[] = "Noise_IK_secp256k1_ChaChaPoly_SHA256";
static constexpr size_t PROTOCOL_NAME_IK_LEN = 37;
static const uint8_t PROTOCOL_NAME_XK[] = "Noise_XK_secp256k1_ChaChaPoly_SHA256";
static constexpr size_t PROTOCOL_NAME_XK_LEN = 37;

bool x_only_ecdh(const uint8_t *secret_key, const uint8_t *pub_key, uint8_t *out) {
  mbedtls_ecp_group group;
  mbedtls_ecp_point pub_point;
  mbedtls_mpi z;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&pub_point);
  mbedtls_mpi_init(&z);
  mbedtls_mpi_init(&d);

  int ret = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
  if (ret != 0)
    goto cleanup;

  ret = mbedtls_ecp_point_read_binary(&group, &pub_point, pub_key, PUBKEY_SIZE);
  if (ret != 0)
    goto cleanup;

  ret = mbedtls_mpi_read_binary(&d, secret_key, PRIVKEY_SIZE);
  if (ret != 0)
    goto cleanup;

  ret = mbedtls_ecdh_compute_shared(&group, &z, &pub_point, &d, fips_rng, nullptr);
  if (ret != 0)
    goto cleanup;

  {
    uint8_t x_bytes[32];
    ret = mbedtls_mpi_write_binary(&z, x_bytes, 32);
    if (ret != 0)
      goto cleanup;
    hash_one(x_bytes, 32, out);
    ret = 0;
  }

cleanup:
  mbedtls_ecp_group_free(&group);
  mbedtls_ecp_point_free(&pub_point);
  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&d);
  return ret == 0;
}

bool ecdh_pubkey(const uint8_t *secret_key, uint8_t *pub_out) {
  mbedtls_ecp_group group;
  mbedtls_ecp_point point;
  mbedtls_mpi d;

  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&point);
  mbedtls_mpi_init(&d);

  int ret = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256K1);
  if (ret != 0) {
    ESP_LOGE(TAG, "ecp_group_load secp256k1 failed: -0x%04x", -ret);
    goto cleanup;
  }

  ret = mbedtls_mpi_read_binary(&d, secret_key, PRIVKEY_SIZE);
  if (ret != 0) {
    ESP_LOGE(TAG, "mpi_read_binary failed: -0x%04x", -ret);
    goto cleanup;
  }

  ret = mbedtls_ecp_mul(&group, &point, &d, &group.G, fips_rng, nullptr);
  if (ret != 0) {
    ESP_LOGE(TAG, "ecp_mul failed: -0x%04x", -ret);
    goto cleanup;
  }

  {
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&group, &point, MBEDTLS_ECP_PF_COMPRESSED, &olen, pub_out,
                                         PUBKEY_SIZE);
    if (ret != 0 || olen != PUBKEY_SIZE)
      goto cleanup;
  }

  ret = 0;

cleanup:
  mbedtls_ecp_group_free(&group);
  mbedtls_ecp_point_free(&point);
  mbedtls_mpi_free(&d);
  return ret == 0;
}

void hash_concat(const uint8_t *h, const uint8_t *data, size_t data_len, uint8_t *out) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, h, HASH_SIZE);
  mbedtls_sha256_update(&ctx, data, data_len);
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
}

void hash_one(const uint8_t *data, size_t len, uint8_t *out) {
  mbedtls_sha256(data, len, out, 0);
}

void mix_key(const uint8_t *ck, const uint8_t *ikm, uint8_t *new_ck, uint8_t *k) {
  uint8_t okm[64];
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_hkdf(md, ck, HASH_SIZE, ikm, HASH_SIZE, nullptr, 0, okm, 64);
  std::memcpy(new_ck, okm, HASH_SIZE);
  std::memcpy(k, okm + HASH_SIZE, HASH_SIZE);
}

void split(const uint8_t *ck, uint8_t *k1, uint8_t *k2) {
  uint8_t prk[HASH_SIZE];
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(md, ck, HASH_SIZE, nullptr, 0, prk);
  uint8_t okm[64];
  mbedtls_hkdf_expand(md, prk, HASH_SIZE, nullptr, 0, okm, 64);
  std::memcpy(k1, okm, HASH_SIZE);
  std::memcpy(k2, okm + HASH_SIZE, HASH_SIZE);
}

static void make_nonce(uint64_t ctr, uint8_t nonce[NONCE_SIZE]) {
  std::memset(nonce, 0, 4);
  for (int i = 0; i < 8; i++) {
    nonce[4 + i] = static_cast<uint8_t>(ctr >> (i * 8));
  }
}

size_t aead_encrypt(const uint8_t *key, uint64_t nonce_ctr, const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t pt_len, uint8_t *out) {
  mbedtls_chachapoly_context ctx;
  mbedtls_chachapoly_init(&ctx);

  int ret = mbedtls_chachapoly_setkey(&ctx, key);
  if (ret != 0) {
    mbedtls_chachapoly_free(&ctx);
    return 0;
  }

  uint8_t nonce[NONCE_SIZE];
  make_nonce(nonce_ctr, nonce);

  uint8_t tag[TAG_SIZE];
  ret = mbedtls_chachapoly_encrypt_and_tag(&ctx, pt_len, nonce, aad, aad_len, plaintext, out, tag);
  mbedtls_chachapoly_free(&ctx);

  if (ret != 0)
    return 0;

  std::memcpy(out + pt_len, tag, TAG_SIZE);
  return pt_len + TAG_SIZE;
}

size_t aead_decrypt(const uint8_t *key, uint64_t nonce_ctr, const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ct_len, uint8_t *out) {
  if (ct_len < TAG_SIZE + 1)
    return 0;

  size_t pt_len = ct_len - TAG_SIZE;

  mbedtls_chachapoly_context ctx;
  mbedtls_chachapoly_init(&ctx);

  int ret = mbedtls_chachapoly_setkey(&ctx, key);
  if (ret != 0) {
    mbedtls_chachapoly_free(&ctx);
    return 0;
  }

  uint8_t nonce[NONCE_SIZE];
  make_nonce(nonce_ctr, nonce);

  ret = mbedtls_chachapoly_auth_decrypt(&ctx, pt_len, nonce, aad, aad_len, ciphertext + pt_len,
                                        ciphertext, out);
  mbedtls_chachapoly_free(&ctx);

  if (ret != 0)
    return 0;

  return pt_len;
}

bool NoiseIKInitiator::init(const uint8_t *eph_secret, const uint8_t *s_secret, const uint8_t *rs_pub) {
  if (!ecdh_pubkey(eph_secret, this->e_pub_.data()))
    return false;

  std::memcpy(this->e_priv_.data(), eph_secret, PRIVKEY_SIZE);
  std::memcpy(this->s_priv_.data(), s_secret, PRIVKEY_SIZE);
  std::memcpy(this->rs_.data(), rs_pub, PUBKEY_SIZE);
  this->k_.fill(0);

  hash_one(PROTOCOL_NAME_IK, PROTOCOL_NAME_IK_LEN, this->h_.data());
  std::memcpy(this->ck_.data(), this->h_.data(), HASH_SIZE);

  std::array<uint8_t, PUBKEY_SIZE> normalized_rs;
  std::memcpy(normalized_rs.data(), rs_pub, PUBKEY_SIZE);
  normalized_rs[0] = 0x02;

  hash_concat(this->h_.data(), normalized_rs.data(), PUBKEY_SIZE, this->h_.data());
  this->n_ = 0;
  return true;
}

size_t NoiseIKInitiator::write_message1(const uint8_t *my_static_pub, const uint8_t *epoch, uint8_t *out) {
  size_t pos = 0;

  std::memcpy(out, this->e_pub_.data(), PUBKEY_SIZE);
  pos += PUBKEY_SIZE;
  hash_concat(this->h_.data(), this->e_pub_.data(), PUBKEY_SIZE, this->h_.data());

  uint8_t dh[HASH_SIZE];
  x_only_ecdh(this->e_priv_.data(), this->rs_.data(), dh);
  uint8_t new_ck[HASH_SIZE];
  mix_key(this->ck_.data(), dh, new_ck, this->k_.data());
  std::memcpy(this->ck_.data(), new_ck, HASH_SIZE);
  this->n_ = 0;

  size_t enc_len = aead_encrypt(this->k_.data(), this->n_, nullptr, 0, my_static_pub, PUBKEY_SIZE, out + pos);
  this->n_++;
  hash_concat(this->h_.data(), out + pos, enc_len, this->h_.data());
  pos += enc_len;

  uint8_t ss_dh[HASH_SIZE];
  x_only_ecdh(this->s_priv_.data(), this->rs_.data(), ss_dh);
  mix_key(this->ck_.data(), ss_dh, new_ck, this->k_.data());
  std::memcpy(this->ck_.data(), new_ck, HASH_SIZE);
  this->n_ = 0;

  enc_len = aead_encrypt(this->k_.data(), this->n_, nullptr, 0, epoch, EPOCH_SIZE, out + pos);
  this->n_++;
  hash_concat(this->h_.data(), out + pos, enc_len, this->h_.data());
  pos += enc_len;

  return pos;
}

bool NoiseIKInitiator::read_message2(const uint8_t *data, size_t len) {
  size_t expected = PUBKEY_SIZE + EPOCH_SIZE + TAG_SIZE;
  if (len != expected)
    return false;

  size_t pos = 0;

  hash_concat(this->h_.data(), data, PUBKEY_SIZE, this->h_.data());
  pos += PUBKEY_SIZE;

  uint8_t dh[HASH_SIZE], new_ck[HASH_SIZE];
  x_only_ecdh(this->e_priv_.data(), data, dh);
  mix_key(this->ck_.data(), dh, new_ck, this->k_.data());
  std::memcpy(this->ck_.data(), new_ck, HASH_SIZE);
  this->n_ = 0;

  uint8_t se_dh[HASH_SIZE];
  x_only_ecdh(this->e_priv_.data(), this->rs_.data(), se_dh);
  mix_key(this->ck_.data(), se_dh, new_ck, this->k_.data());
  std::memcpy(this->ck_.data(), new_ck, HASH_SIZE);
  this->n_ = 0;

  uint8_t epoch_buf[EPOCH_SIZE];
  size_t dec_len = aead_decrypt(this->k_.data(), this->n_, nullptr, 0, data + pos, EPOCH_SIZE + TAG_SIZE, epoch_buf);
  if (dec_len != EPOCH_SIZE)
    return false;
  this->n_++;
  hash_concat(this->h_.data(), data + pos, EPOCH_SIZE + TAG_SIZE, this->h_.data());

  return true;
}

TransportState NoiseIKInitiator::finalize() {
  uint8_t k1[HASH_SIZE], k2[HASH_SIZE];
  split(this->ck_.data(), k1, k2);

  TransportState state;
  std::memcpy(state.send_key.data(), k1, HASH_SIZE);
  std::memcpy(state.recv_key.data(), k2, HASH_SIZE);
  return state;
}

void node_addr_from_pubkey(const uint8_t *pubkey, uint8_t *addr) {
  uint8_t x_only[32];
  std::memcpy(x_only, pubkey + 1, 32);
  hash_one(x_only, 32, addr);
}

bool NoiseIKResponder::init(const uint8_t *s_secret, const uint8_t *s_pub, const uint8_t *peer_e_pub) {
  std::memcpy(this->s_priv_.data(), s_secret, PRIVKEY_SIZE);
  std::memcpy(this->peer_e_pub_.data(), peer_e_pub, PUBKEY_SIZE);
  this->k_.fill(0);

  hash_one(PROTOCOL_NAME_IK, PROTOCOL_NAME_IK_LEN, this->h_.data());
  std::memcpy(this->ck_.data(), this->h_.data(), HASH_SIZE);

  std::array<uint8_t, PUBKEY_SIZE> normalized_s;
  std::memcpy(normalized_s.data(), s_pub, PUBKEY_SIZE);
  normalized_s[0] = 0x02;
  hash_concat(this->h_.data(), normalized_s.data(), PUBKEY_SIZE, this->h_.data());

  hash_concat(this->h_.data(), peer_e_pub, PUBKEY_SIZE, this->h_.data());

  uint8_t dh[HASH_SIZE];
  x_only_ecdh(this->s_priv_.data(), peer_e_pub, dh);
  uint8_t new_ck[HASH_SIZE];
  mix_key(this->ck_.data(), dh, new_ck, this->k_.data());
  std::memcpy(this->ck_.data(), new_ck, HASH_SIZE);
  this->n_ = 0;

  return true;
}

bool NoiseIKResponder::read_message1(const uint8_t *data, size_t len, uint8_t *out_initiator_pub,
                                     uint8_t *out_epoch) {
  size_t expected = (PUBKEY_SIZE + TAG_SIZE) + (EPOCH_SIZE + TAG_SIZE);
  if (len != expected)
    return false;

  size_t pos = 0;

  uint8_t initiator_pub[PUBKEY_SIZE];
  size_t dec_len =
      aead_decrypt(this->k_.data(), this->n_, nullptr, 0, data, PUBKEY_SIZE + TAG_SIZE, initiator_pub);
  if (dec_len != PUBKEY_SIZE)
    return false;
  this->n_++;
  std::memcpy(out_initiator_pub, initiator_pub, PUBKEY_SIZE);
  hash_concat(this->h_.data(), data, PUBKEY_SIZE + TAG_SIZE, this->h_.data());
  pos += PUBKEY_SIZE + TAG_SIZE;

  uint8_t dh[HASH_SIZE], new_ck[HASH_SIZE];
  x_only_ecdh(this->s_priv_.data(), initiator_pub, dh);
  mix_key(this->ck_.data(), dh, new_ck, this->k_.data());
  std::memcpy(this->ck_.data(), new_ck, HASH_SIZE);
  this->n_ = 0;

  dec_len = aead_decrypt(this->k_.data(), this->n_, nullptr, 0, data + pos, EPOCH_SIZE + TAG_SIZE, out_epoch);
  if (dec_len != EPOCH_SIZE)
    return false;
  this->n_++;
  hash_concat(this->h_.data(), data + pos, EPOCH_SIZE + TAG_SIZE, this->h_.data());

  return true;
}

size_t NoiseIKResponder::write_message2(const uint8_t *re_eph_secret, const uint8_t *epoch, uint8_t *out) {
  std::array<uint8_t, PUBKEY_SIZE> re_pub;
  if (!ecdh_pubkey(re_eph_secret, re_pub.data()))
    return 0;

  std::array<uint8_t, PRIVKEY_SIZE> re_priv;
  std::memcpy(re_priv.data(), re_eph_secret, PRIVKEY_SIZE);

  size_t pos = 0;
  std::memcpy(out, re_pub.data(), PUBKEY_SIZE);
  pos += PUBKEY_SIZE;
  hash_concat(this->h_.data(), re_pub.data(), PUBKEY_SIZE, this->h_.data());

  uint8_t dh[HASH_SIZE], new_ck[HASH_SIZE];
  x_only_ecdh(re_priv.data(), this->peer_e_pub_.data(), dh);
  mix_key(this->ck_.data(), dh, new_ck, this->k_.data());
  std::memcpy(this->ck_.data(), new_ck, HASH_SIZE);
  this->n_ = 0;

  x_only_ecdh(this->s_priv_.data(), this->peer_e_pub_.data(), dh);
  mix_key(this->ck_.data(), dh, new_ck, this->k_.data());
  std::memcpy(this->ck_.data(), new_ck, HASH_SIZE);
  this->n_ = 0;

  size_t enc_len = aead_encrypt(this->k_.data(), this->n_, nullptr, 0, epoch, EPOCH_SIZE, out + pos);
  this->n_++;
  hash_concat(this->h_.data(), out + pos, enc_len, this->h_.data());
  pos += enc_len;

  return pos;
}

TransportState NoiseIKResponder::finalize() {
  uint8_t k1[HASH_SIZE], k2[HASH_SIZE];
  split(this->ck_.data(), k1, k2);

  TransportState state;
  std::memcpy(state.recv_key.data(), k1, HASH_SIZE);
  std::memcpy(state.send_key.data(), k2, HASH_SIZE);
  return state;
}

bool NoiseXKResponder::init(const uint8_t *s_secret, const uint8_t *ei_pub) {
  std::memcpy(this->s_priv_.data(), s_secret, PRIVKEY_SIZE);
  std::memcpy(this->ei_pub_.data(), ei_pub, PUBKEY_SIZE);

  hash_one(PROTOCOL_NAME_XK, PROTOCOL_NAME_XK_LEN, this->h_.data());
  std::memcpy(this->ck_.data(), this->h_.data(), HASH_SIZE);

  uint8_t s_pub[PUBKEY_SIZE];
  if (!ecdh_pubkey(s_secret, s_pub))
    return false;
  s_pub[0] = 0x02;
  std::memcpy(this->s_pub_.data(), s_pub, PUBKEY_SIZE);
  hash_concat(this->h_.data(), s_pub, PUBKEY_SIZE, this->h_.data());

  hash_concat(this->h_.data(), ei_pub, PUBKEY_SIZE, this->h_.data());

  uint8_t dh[HASH_SIZE];
  x_only_ecdh(s_secret, ei_pub, dh);
  uint8_t new_ck[HASH_SIZE];
  mix_key(this->ck_.data(), dh, new_ck, this->k_.data());
  std::memcpy(this->ck_.data(), new_ck, HASH_SIZE);
  this->n_ = 0;

  this->has_read_msg3_ = false;
  return true;
}

bool NoiseXKResponder::read_message1(const uint8_t *data, size_t len) {
  return len == XK_MSG1_NOISE_SIZE;
}

size_t NoiseXKResponder::write_message2(const uint8_t *re_eph_secret, const uint8_t *epoch, uint8_t *out) {
  std::memcpy(this->re_priv_.data(), re_eph_secret, PRIVKEY_SIZE);

  uint8_t re_pub[PUBKEY_SIZE];
  if (!ecdh_pubkey(re_eph_secret, re_pub))
    return 0;
  std::memcpy(this->re_pub_.data(), re_pub, PUBKEY_SIZE);

  size_t pos = 0;

  std::memcpy(out, re_pub, PUBKEY_SIZE);
  pos += PUBKEY_SIZE;
  hash_concat(this->h_.data(), re_pub, PUBKEY_SIZE, this->h_.data());

  uint8_t dh[HASH_SIZE], new_ck[HASH_SIZE];
  x_only_ecdh(this->re_priv_.data(), this->ei_pub_.data(), dh);
  mix_key(this->ck_.data(), dh, new_ck, this->k_.data());
  std::memcpy(this->ck_.data(), new_ck, HASH_SIZE);
  this->n_ = 0;

  size_t enc_len = aead_encrypt(this->k_.data(), this->n_, nullptr, 0, epoch, EPOCH_SIZE, out + pos);
  this->n_++;
  hash_concat(this->h_.data(), out + pos, enc_len, this->h_.data());
  pos += enc_len;

  return pos;
}

bool NoiseXKResponder::read_message3(const uint8_t *data, size_t len) {
  size_t expected = (PUBKEY_SIZE + TAG_SIZE) + (EPOCH_SIZE + TAG_SIZE);
  if (len != expected)
    return false;

  size_t pos = 0;

  uint8_t static_buf[PUBKEY_SIZE];
  size_t dec_len =
      aead_decrypt(this->k_.data(), this->n_, nullptr, 0, data, PUBKEY_SIZE + TAG_SIZE, static_buf);
  if (dec_len != PUBKEY_SIZE)
    return false;
  this->n_++;
  hash_concat(this->h_.data(), data, PUBKEY_SIZE + TAG_SIZE, this->h_.data());
  pos += PUBKEY_SIZE + TAG_SIZE;

  uint8_t se_dh[HASH_SIZE], new_ck[HASH_SIZE];
  x_only_ecdh(this->re_priv_.data(), static_buf, se_dh);
  mix_key(this->ck_.data(), se_dh, new_ck, this->k_.data());
  std::memcpy(this->ck_.data(), new_ck, HASH_SIZE);
  this->n_ = 0;

  uint8_t epoch_buf[EPOCH_SIZE];
  dec_len = aead_decrypt(this->k_.data(), this->n_, nullptr, 0, data + pos, EPOCH_SIZE + TAG_SIZE, epoch_buf);
  if (dec_len != EPOCH_SIZE)
    return false;
  this->n_++;
  hash_concat(this->h_.data(), data + pos, EPOCH_SIZE + TAG_SIZE, this->h_.data());

  this->has_read_msg3_ = true;
  return true;
}

TransportState NoiseXKResponder::finalize() {
  uint8_t k1[HASH_SIZE], k2[HASH_SIZE];
  split(this->ck_.data(), k1, k2);

  TransportState state;
  std::memcpy(state.recv_key.data(), k1, HASH_SIZE);
  std::memcpy(state.send_key.data(), k2, HASH_SIZE);
  return state;
}

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
