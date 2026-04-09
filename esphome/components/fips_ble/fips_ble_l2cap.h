#pragma once

#ifdef USE_FIPS_BLE

#include <array>
#include <cstdint>
#include <cstddef>
#include <cstring>

#include "fips_noise.h"

struct ble_gap_event;
struct ble_l2cap_event;
struct ble_l2cap_chan;
struct os_mbuf;

namespace esphome::fips_ble {

static constexpr uint16_t FIPS_L2CAP_PSM = 133;
static constexpr uint16_t FIPS_L2CAP_MTU = 512;
static constexpr size_t L2CAP_FRAME_CAP = 512;

static constexpr uint8_t FIPS_SERVICE_UUID[16] = {
    0x4c, 0x8f, 0x64, 0x40, 0xcc, 0xc9, 0x87, 0x9f,
    0xc0, 0x42, 0xc5, 0x2c, 0x90, 0xb7, 0x90, 0x9c,
};

static constexpr uint8_t FIPS_CAPS_UUID[2] = {0x46, 0x49};

enum class L2capState : uint8_t {
  IDLE = 0,
  ADVERTISING,
  BLE_CONNECTED,
  L2CAP_CONNECTED,
  PUBKEY_EXCHANGED,
  READY,
  DISCONNECTED,
};

class FipsBleL2cap {
 public:
  bool setup();
  void loop();

  bool is_ready() const { return this->state_ == L2capState::READY; }
  L2capState get_state() const { return this->state_; }

  void set_peer_pub(const uint8_t *pub) { std::memcpy(this->peer_pub_.data(), pub, PUBKEY_SIZE); }
  void set_own_pub(const uint8_t *pub) { std::memcpy(this->own_pub_.data(), pub, PUBKEY_SIZE); }

  bool send(const uint8_t *data, size_t len);
  int recv(uint8_t *buf, size_t buf_len);

  const uint8_t *get_peer_pub() const { return this->peer_pub_.data(); }
  uint16_t get_conn_handle() const { return this->conn_handle_; }
  uint16_t get_peer_mtu() const { return this->peer_mtu_; }

 protected:
  static int gap_event_cb(struct ble_gap_event *event, void *arg);
  static int l2cap_event_cb(struct ble_l2cap_event *event, void *arg);

  void start_advertising();
  void on_gap_connect(uint16_t conn_handle, int status);
  void on_gap_disconnect(uint16_t conn_handle, int reason);
  void on_l2cap_accept(uint16_t conn_handle, uint16_t peer_sdu_size, struct ble_l2cap_chan *chan);
  void on_l2cap_connected(int status, uint16_t conn_handle, struct ble_l2cap_chan *chan);
  void on_l2cap_disconnected(uint16_t conn_handle, struct ble_l2cap_chan *chan);
  void on_l2cap_data_received(struct ble_l2cap_chan *chan, struct os_mbuf *sdu_rx);

  bool send_raw(const uint8_t *data, size_t len);
  struct os_mbuf *alloc_sdu_tx();

  L2capState state_{L2capState::IDLE};
  uint16_t conn_handle_{0};
  struct ble_l2cap_chan *l2cap_chan_{nullptr};
  uint16_t peer_mtu_{0};
  uint8_t own_addr_type_{0};
  uint32_t last_activity_{0};

  std::array<uint8_t, 33> peer_pub_{};
  std::array<uint8_t, 33> own_pub_{};

  std::array<uint8_t, L2CAP_FRAME_CAP> rx_buf_{};
  size_t rx_buf_len_{0};
  size_t rx_buf_pos_{0};
  bool rx_frame_ready_{false};
  size_t rx_frame_len_{0};

  uint32_t pubkey_exchange_start_{0};
  uint32_t disconnect_time_{0};
  bool pubkey_sent_{false};
  bool pubkey_recv_{false};
};

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
