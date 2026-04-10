#pragma once

#ifdef USE_FIPS_BLE

#include <cstdint>
#include <cstddef>

namespace esphome::fips_ble {

static constexpr size_t TCP_PROXY_BUF_SIZE = 512;
static constexpr size_t MAX_TCP_CLIENTS = 2;

class FipsBleL2cap;

class FipsTcpProxy {
 public:
  void setup(FipsBleL2cap *l2cap, uint16_t listen_port);
  void loop();
  void stop();
  void forward_to_tcp(const uint8_t *data, size_t len);
  bool has_pending_outbound() const { return this->pending_outbound_len_ > 0; }
  const uint8_t *pending_outbound_data() const { return this->pending_outbound_; }
  size_t pending_outbound_length() const { return this->pending_outbound_len_; }
  void clear_pending_outbound() { this->pending_outbound_len_ = 0; }

 protected:
  bool listen_on(uint16_t port);
  void accept_client();
  void forward_tcp_to_fips();

  FipsBleL2cap *l2cap_{nullptr};
  int listen_fd_{-1};
  int client_fds_[MAX_TCP_CLIENTS]{};
  uint16_t listen_port_{6053};
  bool tcp_setup_done_{false};
  uint8_t pending_outbound_[TCP_PROXY_BUF_SIZE]{};
  size_t pending_outbound_len_{0};
};

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
