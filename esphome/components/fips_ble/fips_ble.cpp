#ifdef USE_ESP32
#ifdef USE_FIPS_BLE

#include "fips_ble.h"
#include "esphome/core/log.h"

namespace esphome::fips_ble {

void FipsBleComponent::setup() {
  ESP_LOGCONFIG(TAG, "Setting up FIPS BLE...");
  ESP_LOGD(TAG, "  Peer BLE address: %02X:%02X:%02X:%02X:%02X:%02X", this->ble_address_[0],
           this->ble_address_[1], this->ble_address_[2], this->ble_address_[3], this->ble_address_[4],
           this->ble_address_[5]);
  ESP_LOGD(TAG, "  API port: %u", this->api_port_);
  this->mark_setup();
}

void FipsBleComponent::loop() {}

void FipsBleComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "FIPS BLE:");
  ESP_LOGD(TAG, "  Identity secret: %s***", this->identity_secret_.substr(0, 8).c_str());
  ESP_LOGD(TAG, "  Peer public key: %s...", this->peer_public_key_.substr(0, 16).c_str());
  ESP_LOGD(TAG, "  BLE address: %02X:%02X:%02X:%02X:%02X:%02X", this->ble_address_[0],
           this->ble_address_[1], this->ble_address_[2], this->ble_address_[3], this->ble_address_[4],
           this->ble_address_[5]);
  ESP_LOGD(TAG, "  API port: %u", this->api_port_);
}

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
#endif  // USE_ESP32
