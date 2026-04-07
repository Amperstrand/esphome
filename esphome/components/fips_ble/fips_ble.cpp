#ifdef USE_FIPS_BLE

#include "fips_ble.h"

#include <cstring>

#include "esphome/core/application.h"
#include "esphome/core/helpers.h"
#include "fips_fsp.h"

#include <esp_random.h>
#include <nimble/nimble_port.h>
#include <nimble/nimble_port_freertos.h>
#include <host/ble_hs.h>
#include <host/ble_gap.h>
#include <host/util/util.h>
#include <services/gap/ble_svc_gap.h>

extern "C" {
void ble_store_config_init(void);
}

namespace esphome::fips_ble {

static FipsBleComponent *g_instance{nullptr};

float FipsBleComponent::get_setup_priority() const { return setup_priority::BLUETOOTH; }

void FipsBleComponent::ble_sync_cb() {
  if (g_instance == nullptr)
    return;
  g_instance->transition(FipsState::WAITING_PEER);
}

void FipsBleComponent::ble_host_task_fn(void *param) {
  nimble_port_run();
  nimble_port_freertos_deinit();
}

bool FipsBleComponent::parse_hex(const std::string &hex, uint8_t *out, size_t expected_len) {
  if (hex.length() != expected_len * 2)
    return false;
  for (size_t i = 0; i < expected_len; i++) {
    uint8_t byte = 0;
    for (size_t j = 0; j < 2; j++) {
      char c = hex[i * 2 + j];
      if (c >= '0' && c <= '9')
        byte |= (c - '0') << (4 - j * 4);
      else if (c >= 'a' && c <= 'f')
        byte |= (c - 'a' + 10) << (4 - j * 4);
      else if (c >= 'A' && c <= 'F')
        byte |= (c - 'A' + 10) << (4 - j * 4);
      else
        return false;
    }
    out[i] = byte;
  }
  return true;
}

void FipsBleComponent::transition(FipsState new_state) {
  if (this->state_ == new_state)
    return;
  ESP_LOGI(TAG, "state: %d -> %d", static_cast<int>(this->state_), static_cast<int>(new_state));
  this->state_ = new_state;
  this->last_activity_ = millis();
}

void FipsBleComponent::setup() {
  g_instance = this;

  if (!this->parse_hex(this->identity_secret_hex_, this->identity_secret_.data(), PRIVKEY_SIZE)) {
    ESP_LOGE(TAG, "invalid identity_secret");
    this->mark_failed();
    return;
  }

  if (!this->parse_hex(this->peer_pub_key_hex_, this->peer_pub_.data(), PUBKEY_SIZE)) {
    ESP_LOGE(TAG, "invalid peer_public_key");
    this->mark_failed();
    return;
  }

  if (!ecdh_pubkey(this->identity_secret_.data(), this->identity_pub_.data())) {
    ESP_LOGE(TAG, "failed to derive identity pubkey");
    this->mark_failed();
    return;
  }

  esp_fill_random(this->eph_secret_.data(), PRIVKEY_SIZE);
  while (!ecdh_pubkey(this->eph_secret_.data(), this->eph_secret_.data())) {
    esp_fill_random(this->eph_secret_.data(), PRIVKEY_SIZE);
  }

  esp_err_t ret = nimble_port_init();
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "nimble_port_init failed: %d", ret);
    this->mark_failed();
    return;
  }

  ble_hs_cfg.sync_cb = FipsBleComponent::ble_sync_cb;
  ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_NO_IO;

  std::array<uint8_t, 20> name_buf;
  const char *app_name = App.get_name().c_str();
  size_t name_len = std::strlen(app_name);
  if (name_len > 19)
    name_len = 19;
  std::memcpy(name_buf.data(), app_name, name_len);
  name_buf[name_len] = '\0';
  ble_svc_gap_device_name_set(reinterpret_cast<const char *>(name_buf.data()));

  ble_store_config_init();
  nimble_port_freertos_init(FipsBleComponent::ble_host_task_fn);

  this->tcp_proxy_.setup(&this->l2cap_, this->api_port_);
}

void FipsBleComponent::loop() {
  if (this->state_ == FipsState::WAITING_PEER && !this->l2cap_setup_done_) {
    this->l2cap_.set_peer_pub(this->peer_pub_.data());
    this->l2cap_.set_own_pub(this->identity_pub_.data());
    if (this->l2cap_.setup()) {
      this->l2cap_setup_done_ = true;
    }
  }

  this->l2cap_.loop();

  if (this->state_ == FipsState::WAITING_PEER && this->l2cap_.is_ready()) {
    this->transition(FipsState::LINK_HANDSHAKE);
    this->start_link_handshake();
  }

  if (this->state_ == FipsState::LINK_HANDSHAKE) {
    uint32_t now = millis();
    if (now - this->last_msg1_sent_ > MSG1_RESEND_MS) {
      if (this->msg1_resend_count_ < MSG1_RESEND_MAX) {
        this->send_msg1();
      } else {
        this->handle_error("handshake timeout");
      }
    }
  }

  if (this->state_ == FipsState::LINK_ESTABLISHED || this->state_ == FipsState::LINK_HANDSHAKE) {
    this->handle_received_data();
  }

  if (this->state_ == FipsState::LINK_ESTABLISHED) {
    uint32_t now = millis();
    if (now - this->last_hb_sent_ > HB_INTERVAL_MS) {
      this->send_heartbeat();
      this->last_hb_sent_ = now;
    }
    if (now - this->last_activity_ > RECV_TIMEOUT_MS) {
      this->handle_error("recv timeout");
    }
    this->tcp_proxy_.loop();
  }

  if (this->state_ == FipsState::ERROR) {
    delay(3000);
    this->l2cap_.setup();
    this->rx_buf_len_ = 0;
    this->rx_buf_pos_ = 0;
    this->msg1_resend_count_ = 0;
    this->transition(FipsState::WAITING_PEER);
  }
}

void FipsBleComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "FIPS BLE:");
  ESP_LOGCONFIG(TAG, "  Peer pubkey: %02x%02x..%02x%02x", this->peer_pub_[0], this->peer_pub_[1],
                this->peer_pub_[30], this->peer_pub_[31]);
  ESP_LOGCONFIG(TAG, "  API port: %d", this->api_port_);
}

bool FipsBleComponent::start_link_handshake() {
  this->epoch_++;
  this->msg1_resend_count_ = 0;
  this->send_counter_ = 0;
  this->recv_counter_ = 0;
  this->rx_buf_len_ = 0;
  this->rx_buf_pos_ = 0;
  return this->send_msg1();
}

bool FipsBleComponent::send_msg1() {
  NoiseIKInitiator noise_ik;
  if (!noise_ik.init(this->eph_secret_.data(), this->identity_secret_.data(), this->peer_pub_.data())) {
    ESP_LOGE(TAG, "noise IK init failed");
    return false;
  }

  std::array<uint8_t, EPOCH_SIZE> epoch{};
  for (int i = 0; i < 8; i++) {
    epoch[i] = static_cast<uint8_t>((this->epoch_ >> (i * 8)) & 0xFF);
  }

  uint8_t noise_out[256];
  size_t noise_len = noise_ik.write_message1(this->identity_pub_.data(), epoch.data(), noise_out);
  if (noise_len == 0) {
    ESP_LOGE(TAG, "write_message1 failed");
    return false;
  }

  this->msg1_len_ = fmp_build_msg1(0, noise_out, noise_len, this->msg1_buf_, sizeof(this->msg1_buf_));
  if (this->msg1_len_ == 0) {
    ESP_LOGE(TAG, "fmp_build_msg1 failed");
    return false;
  }

  if (!this->l2cap_.send(this->msg1_buf_, this->msg1_len_)) {
    ESP_LOGE(TAG, "failed to send msg1");
    return false;
  }

  this->last_msg1_sent_ = millis();
  this->msg1_resend_count_++;
  ESP_LOGI(TAG, "MSG1 sent (attempt %u)", this->msg1_resend_count_);
  return true;
}

bool FipsBleComponent::handle_received_data() {
  uint8_t buf[RECV_BUF_SIZE];
  int n = this->l2cap_.recv(buf, sizeof(buf));
  if (n <= 0)
    return false;

  if (this->rx_buf_len_ + static_cast<size_t>(n) > RECV_BUF_SIZE) {
    this->rx_buf_len_ = 0;
    this->rx_buf_pos_ = 0;
    return false;
  }

  std::memcpy(this->rx_buf_.data() + this->rx_buf_len_, buf, static_cast<size_t>(n));
  this->rx_buf_len_ += static_cast<size_t>(n);

  while (this->rx_buf_pos_ < this->rx_buf_len_) {
    size_t frame_len = fmp_calculate_frame_len(this->rx_buf_.data() + this->rx_buf_pos_,
                                                this->rx_buf_len_ - this->rx_buf_pos_);
    if (frame_len == 0 || frame_len > this->rx_buf_len_ - this->rx_buf_pos_) {
      this->rx_buf_pos_ = this->rx_buf_len_;
      break;
    }

    bool ok = this->process_fmp_frame(this->rx_buf_.data() + this->rx_buf_pos_, frame_len);
    this->rx_buf_pos_ += frame_len;
    if (!ok)
      return false;
  }

  if (this->rx_buf_pos_ >= this->rx_buf_len_) {
    this->rx_buf_len_ = 0;
    this->rx_buf_pos_ = 0;
  }
  return true;
}

bool FipsBleComponent::process_fmp_frame(const uint8_t *data, size_t len) {
  FmpParsedMessage msg;
  if (!fmp_parse_message(data, len, msg))
    return true;

  switch (msg.phase) {
    case FmpPhase::Msg2: {
      if (this->state_ != FipsState::LINK_HANDSHAKE)
        return true;

      NoiseIKInitiator noise_ik;
      if (!noise_ik.init(this->eph_secret_.data(), this->identity_secret_.data(), this->peer_pub_.data()))
        return false;

      if (!noise_ik.read_message2(msg.payload, msg.payload_len)) {
        ESP_LOGE(TAG, "read_message2 failed");
        return false;
      }

      TransportState ts = noise_ik.finalize();
      this->send_key_ = ts.send_key;
      this->recv_key_ = ts.recv_key;
      this->peer_idx_ = msg.sender_idx;

      ESP_LOGI(TAG, "link established, peer_idx=%u", this->peer_idx_);
      this->transition(FipsState::LINK_ESTABLISHED);
      return true;
    }

    case FmpPhase::Msg1: {
      if (this->state_ != FipsState::LINK_HANDSHAKE)
        return true;

      std::array<uint8_t, PUBKEY_SIZE> my_x_only;
      std::memcpy(my_x_only.data(), this->identity_pub_.data() + 1, 32);

      std::array<uint8_t, PUBKEY_SIZE> peer_x_only;
      std::memcpy(peer_x_only.data(), this->peer_pub_.data() + 1, 32);

      if (std::memcmp(my_x_only.data(), peer_x_only.data(), 32) >= 0)
        return true;

      if (msg.payload_len < PUBKEY_SIZE)
        return true;

      std::array<uint8_t, PUBKEY_SIZE> peer_e_pub;
      std::memcpy(peer_e_pub.data(), msg.payload, PUBKEY_SIZE);

      NoiseIKInitiator responder;
      if (!responder.init(this->eph_secret_.data(), this->identity_secret_.data(), this->peer_pub_.data()))
        return false;

      uint8_t noise_out[128];
      size_t noise_len = responder.write_message1(this->identity_pub_.data(), nullptr, noise_out);
      if (noise_len == 0)
        return false;

      uint8_t msg2_buf[256];
      size_t msg2_len = fmp_build_msg2(0, msg.sender_idx, noise_out, noise_len, msg2_buf, sizeof(msg2_buf));
      if (msg2_len == 0)
        return false;

      this->l2cap_.send(msg2_buf, msg2_len);

      TransportState ts = responder.finalize();
      this->send_key_ = ts.recv_key;
      this->recv_key_ = ts.send_key;
      this->peer_idx_ = msg.sender_idx;

      ESP_LOGI(TAG, "link established (responder), peer_idx=%u", this->peer_idx_);
      this->transition(FipsState::LINK_ESTABLISHED);
      return true;
    }

    case FmpPhase::Established: {
      if (this->state_ != FipsState::LINK_ESTABLISHED)
        return true;

      this->recv_counter_ = msg.counter;
      this->last_activity_ = millis();

      const uint8_t *ciphertext = msg.payload;
      size_t ct_len = msg.payload_len;

      uint8_t decrypted[512];
      size_t dec_len = fmp_decrypt_established(this->recv_key_.data(), msg.counter, data,
                                               FMP_ENCRYPTED_HEADER_SIZE, ciphertext, ct_len, decrypted);
      if (dec_len < FMP_INNER_HEADER_SIZE) {
        ESP_LOGW(TAG, "decrypt failed or too short");
        return true;
      }

      uint8_t msg_type = decrypted[4];
      size_t payload_len = dec_len - FMP_INNER_HEADER_SIZE;
      const uint8_t *payload = decrypted + FMP_INNER_HEADER_SIZE;

      if (msg_type == MSG_HEARTBEAT) {
        ESP_LOGD(TAG, "heartbeat received");
        return true;
      }

      if (msg_type == MSG_DISCONNECT) {
        ESP_LOGI(TAG, "peer disconnect");
        this->handle_error("peer disconnect");
        return true;
      }

      if (msg_type == MSG_SESSION_DATAGRAM && payload_len > 0) {
        uint16_t src_port = static_cast<uint16_t>(payload[0]) | (static_cast<uint16_t>(payload[1]) << 8);
        uint16_t dst_port = 0;
        const uint8_t *datagram_payload = nullptr;
        size_t datagram_len = 0;
        fsp_parse_session_datagram(payload, payload_len, src_port, dst_port, datagram_payload, datagram_len);

        if (dst_port == this->api_port_ && datagram_payload != nullptr && datagram_len > 0) {
          this->tcp_proxy_.forward_to_tcp(datagram_payload, datagram_len);
        }
      }

      return true;
    }

    default:
      return true;
  }
}

void FipsBleComponent::send_heartbeat() {
  this->send_established_msg(MSG_HEARTBEAT, nullptr, 0);
}

void FipsBleComponent::send_established_msg(uint8_t msg_type, const uint8_t *payload, size_t payload_len) {
  uint8_t out[512];
  uint32_t ts = millis() & 0xFFFFFFFF;
  size_t len = fmp_build_established(this->peer_idx_, this->send_counter_, msg_type, ts, payload, payload_len,
                                     this->send_key_.data(), out, sizeof(out));
  if (len > 0) {
    this->l2cap_.send(out, len);
    this->send_counter_++;
  }
}

void FipsBleComponent::handle_error(const char *reason) {
  ESP_LOGW(TAG, "error: %s, reconnecting...", reason);
  this->transition(FipsState::ERROR);
}

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
