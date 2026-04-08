#pragma once
#ifdef USE_FIPS_BLE
namespace esphome::fips_ble {
bool run_fips_selftest();
}
#endif
