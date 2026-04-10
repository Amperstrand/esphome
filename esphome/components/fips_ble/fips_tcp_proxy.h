#pragma once

#ifdef USE_FIPS_BLE

#include <cstdint>
#include <cstddef>

namespace esphome::fips_ble {

static constexpr size_t TCP_PROXY_BUF_SIZE = 512;

class FipsBleL2cap;

class FipsTcpProxy {
 public:
  void setup(FipsBleL2cap *l2cap, uint16_t api_port);
  void loop();
  void stop();
  void forward_to_tcp(const uint8_t *data, size_t len);
  bool has_pending_outbound() const { return this->pending_outbound_len_ > 0; }
  const uint8_t *pending_outbound_data() const { return this->pending_outbound_; }
  size_t pending_outbound_length() const { return this->pending_outbound_len_; }
  void clear_pending_outbound() { this->pending_outbound_len_ = 0; }

 protected:
  bool connect_to_api();
  void read_from_api();
  void disconnect_api();

  FipsBleL2cap *l2cap_{nullptr};
  int api_fd_{-1};
  uint16_t api_port_{6053};
  uint8_t pending_outbound_[TCP_PROXY_BUF_SIZE]{};
  size_t pending_outbound_len_{0};
};

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
