#pragma once

#ifdef USE_FIPS_BLE

#include "fips_ble_l2cap.h"
#include "fips_fmp.h"
#include "fips_noise.h"
#include "fips_tcp_proxy.h"
#include "esphome/core/component.h"
#include "esphome/core/log.h"

#include <array>
#include <cstdint>

namespace esphome::fips_ble {

static const char *const TAG = "fips_ble";

static constexpr uint32_t HB_INTERVAL_MS = 10000;
static constexpr uint32_t RECV_TIMEOUT_MS = 30000;
static constexpr uint32_t MSG1_RESEND_MS = 3000;
static constexpr uint32_t MSG1_RESEND_MAX = 10;
static constexpr uint8_t MAX_COMPETING_MSG1 = 3;
static constexpr size_t RECV_BUF_SIZE = 1500;

enum class FipsState : uint8_t {
  IDLE = 0,
  BLE_SETUP,
  WAITING_PEER,
  LINK_HANDSHAKE,
  LINK_ESTABLISHED,
  ERROR,
};

class FipsBleComponent : public Component {
 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override;

  void set_identity_secret(const std::string &secret) { this->identity_secret_hex_ = secret; }
  void set_peer_public_key(const std::string &pub_key) { this->peer_pub_key_hex_ = pub_key; }
  void set_api_port(uint16_t port) { this->api_port_ = port; }
  void set_selftest(bool selftest) { this->selftest_ = selftest; }

 protected:
  void ble_host_task(void *param);
  static void ble_sync_cb(void);
  static void ble_host_task_fn(void *param);

  bool parse_hex(const std::string &hex, uint8_t *out, size_t expected_len);
  void transition(FipsState new_state);

  bool start_link_handshake();
  bool send_msg1();
  bool handle_received_data();
  bool process_fmp_frame(const uint8_t *data, size_t len);
  void send_heartbeat();
  void send_established_msg(uint8_t msg_type, const uint8_t *payload, size_t payload_len);
  void handle_error(const char *reason);
  bool run_selftest_();

  FipsBleL2cap l2cap_{};
  FipsTcpProxy tcp_proxy_{};
  FipsState state_{FipsState::IDLE};
  bool l2cap_setup_done_{false};
  bool selftest_{false};

  std::string identity_secret_hex_{};
  std::string peer_pub_key_hex_{};

  std::array<uint8_t, PRIVKEY_SIZE> identity_secret_{};
  std::array<uint8_t, PUBKEY_SIZE> identity_pub_{};
  std::array<uint8_t, PUBKEY_SIZE> peer_pub_{};
  std::array<uint8_t, PRIVKEY_SIZE> eph_secret_{};
  uint16_t api_port_{6053};

  std::array<uint8_t, HASH_SIZE> send_key_{};
  std::array<uint8_t, HASH_SIZE> recv_key_{};
  uint64_t send_counter_{0};
  uint64_t recv_counter_{0};
  uint32_t peer_idx_{0};
  uint64_t epoch_{0};

  std::array<uint8_t, RECV_BUF_SIZE> rx_buf_{};
  size_t rx_buf_len_{0};
  size_t rx_buf_pos_{0};

  uint8_t msg1_buf_[256];
  size_t msg1_len_{0};
  uint32_t last_msg1_sent_{0};
  uint32_t msg1_resend_count_{0};
  uint8_t competing_msg1_count_{0};
  uint32_t last_activity_{0};
  uint32_t last_hb_sent_{0};
};

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
