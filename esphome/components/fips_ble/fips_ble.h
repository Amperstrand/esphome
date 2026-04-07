#pragma once

#ifdef USE_ESP32
#ifdef USE_FIPS_BLE

#include "esphome/core/component.h"
#include "esphome/core/log.h"

namespace esphome::fips_ble {

static const char *const TAG = "fips_ble";

class FipsBleComponent : public Component {
 public:
  void setup() override;
  void loop() override;
  void dump_config() override;

  void set_identity_secret(const std::string &secret) { this->identity_secret_ = secret; }
  void set_peer_public_key(const std::string &pub_key) { this->peer_public_key_ = pub_key; }
  void set_ble_address(const std::array<uint8_t, 6> &addr) { this->ble_address_ = addr; }
  void set_api_port(uint16_t port) { this->api_port_ = port; }

 protected:
  std::string identity_secret_{};
  std::string peer_public_key_{};
  std::array<uint8_t, 6> ble_address_{};
  uint16_t api_port_{6053};
};

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
#endif  // USE_ESP32
