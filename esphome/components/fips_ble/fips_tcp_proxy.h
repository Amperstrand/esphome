#pragma once

#ifdef USE_ESP32
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

 protected:
  bool listen_on(uint16_t port);
  void accept_client();
  void forward_tcp_to_fips(int client_fd);
  void forward_fips_to_tcp();

  FipsBleL2cap *l2cap_{nullptr};
  int listen_fd_{-1};
  int client_fds_[MAX_TCP_CLIENTS]{};
  uint16_t listen_port_{6053};
};

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
#endif  // USE_ESP32
