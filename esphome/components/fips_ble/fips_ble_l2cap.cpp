#ifdef USE_ESP32
#ifdef USE_FIPS_BLE

#include "fips_ble_l2cap.h"
#include "fips_noise.h"
#include "esphome/core/log.h"

#include <cstring>

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/util/util.h"
#include "host/ble_l2cap.h"
#include "services/gap/ble_svc_gap.h"
#include "os/os_mbuf.h"
#include "os/os_mempool.h"

extern "C" {
void ble_store_config_init(void);
}

namespace esphome {

static const char *const TAG = "fips_ble.l2cap";

static FipsBleL2cap *g_l2cap_instance{nullptr};

static constexpr uint32_t ACTIVITY_TIMEOUT_MS = 30000;
static constexpr uint32_t PUBKEY_EXCHANGE_TIMEOUT_MS = 5000;

}  // namespace esphome

using namespace esphome::fips_ble;

bool FipsBleL2cap::setup() {
  g_l2cap_instance = this;

  int rc = os_mempool_init(&this->sdu_mempool_, L2CAP_RX_BUF_COUNT, FIPS_L2CAP_MTU,
                           this->sdu_mem_, "fips_coc");
  if (rc != 0) {
    ESP_LOGE(TAG, "os_mempool_init failed: %d", rc);
    return false;
  }

  rc = os_mbuf_pool_init(&this->sdu_pool_, &this->sdu_mempool_, FIPS_L2CAP_MTU, L2CAP_RX_BUF_COUNT);
  if (rc != 0) {
    ESP_LOGE(TAG, "os_mbuf_pool_init failed: %d", rc);
    return false;
  }

  rc = ble_hs_util_ensure_addr(0);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_hs_util_ensure_addr failed: %d", rc);
    return false;
  }

  rc = ble_hs_id_infer_auto(0, &this->own_addr_type_);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: %d", rc);
    return false;
  }

  uint8_t addr_val[6] = {0};
  ble_hs_id_copy_addr(this->own_addr_type_, addr_val, nullptr);
  ESP_LOGI(TAG, "BLE address: %02x:%02x:%02x:%02x:%02x:%02x", addr_val[0], addr_val[1], addr_val[2],
           addr_val[3], addr_val[4], addr_val[5]);

  this->start_advertising();
  return true;
}

void FipsBleL2cap::start_advertising() {
  struct ble_gap_adv_params adv_params;
  struct ble_hs_adv_fields fields;
  int rc;

  std::memset(&fields, 0, sizeof(fields));
  fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
  fields.tx_pwr_lvl_is_present = 1;
  fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;

  const char *name = ble_svc_gap_device_name();
  fields.name = (uint8_t *) name;
  fields.name_len = strlen(name);
  fields.name_is_complete = 1;

  ble_uuid128_t fips_uuid;
  std::memcpy(fips_uuid.value, FIPS_SERVICE_UUID, 16);
  fields.uuids128 = &fips_uuid;
  fields.num_uuids128 = 1;
  fields.uuids128_is_complete = 1;

  rc = ble_gap_adv_set_fields(&fields);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: %d", rc);
    return;
  }

  struct ble_hs_adv_fields scan_fields;
  std::memset(&scan_fields, 0, sizeof(scan_fields));
  uint8_t caps = 0x01;
  scan_fields.svc_data_uuid16 = (ble_uuid16_t[]){{0x4649}};
  scan_fields.num_svc_data_uuid16 = 1;
  scan_fields.svc_data_uuid16_len = 1;
  scan_fields.transport = BLE_GAP_ADV_TRANSPORT_TYPE_LE;

  std::memset(&adv_params, 0, sizeof(adv_params));
  adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
  adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

  rc = ble_gap_adv_start(this->own_addr_type_, nullptr, BLE_HS_FOREVER, &adv_params,
                         FipsBleL2cap::gap_event_cb, this);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
    return;
  }

  this->state_ = L2capState::ADVERTISING;
  ESP_LOGI(TAG, "advertising started");
}

void FipsBleL2cap::loop() {
  if (this->state_ == L2capState::DISCONNECTED) {
    this->l2cap_chan_ = nullptr;
    this->conn_handle_ = 0;
    this->rx_buf_len_ = 0;
    this->rx_buf_pos_ = 0;
    this->rx_frame_ready_ = false;
    this->start_advertising();
    return;
  }

  if (this->state_ != L2capState::READY)
    return;
}

bool FipsBleL2cap::send(const uint8_t *data, size_t len) {
  if (this->state_ != L2capState::READY || this->l2cap_chan_ == nullptr)
    return false;

  if (len > this->peer_mtu_)
    return false;

  uint16_t frame_len = static_cast<uint16_t>(2 + len);
  if (frame_len > this->peer_mtu_)
    return false;

  struct os_mbuf *sdu_tx = os_mbuf_get_pkthdr(&this->sdu_pool_, 0);
  if (sdu_tx == nullptr) {
    ESP_LOGE(TAG, "os_mbuf_get_pkthdr failed for send");
    return false;
  }

  uint8_t hdr[2];
  hdr[0] = static_cast<uint8_t>(len & 0xFF);
  hdr[1] = static_cast<uint8_t>((len >> 8) & 0xFF);

  int rc = os_mbuf_append(sdu_tx, hdr, 2);
  if (rc == 0 && len > 0)
    rc = os_mbuf_append(sdu_tx, data, len);

  if (rc != 0) {
    os_mbuf_free_chain(sdu_tx);
    ESP_LOGE(TAG, "os_mbuf_append failed: %d", rc);
    return false;
  }

  rc = ble_l2cap_send(this->l2cap_chan_, sdu_tx);
  if (rc == BLE_HS_ESTALLED) {
    ESP_LOGW(TAG, "L2CAP send stalled");
    os_mbuf_free_chain(sdu_tx);
    return false;
  }
  if (rc != 0) {
    os_mbuf_free_chain(sdu_tx);
    ESP_LOGE(TAG, "ble_l2cap_send failed: %d", rc);
    return false;
  }

  this->last_activity_ = millis();
  return true;
}

bool FipsBleL2cap::send_raw(const uint8_t *data, size_t len) {
  if (this->l2cap_chan_ == nullptr)
    return false;
  if (len > this->peer_mtu_)
    return false;

  struct os_mbuf *sdu_tx = os_mbuf_get_pkthdr(&this->sdu_pool_, 0);
  if (sdu_tx == nullptr)
    return false;

  int rc = os_mbuf_append(sdu_tx, data, len);
  if (rc != 0) {
    os_mbuf_free_chain(sdu_tx);
    return false;
  }

  rc = ble_l2cap_send(this->l2cap_chan_, sdu_tx);
  if (rc != 0) {
    os_mbuf_free_chain(sdu_tx);
    return false;
  }

  this->last_activity_ = millis();
  return true;
}

int FipsBleL2cap::recv(uint8_t *buf, size_t buf_len) {
  if (!this->rx_frame_ready_)
    return -1;

  size_t copy_len = this->rx_frame_len_;
  if (copy_len > buf_len)
    copy_len = buf_len;

  std::memcpy(buf, this->rx_buf_.data() + 2, copy_len);

  this->rx_buf_pos_ += 2 + this->rx_frame_len_;
  this->rx_frame_ready_ = false;
  this->rx_frame_len_ = 0;

  if (this->rx_buf_pos_ >= this->rx_buf_len_) {
    this->rx_buf_len_ = 0;
    this->rx_buf_pos_ = 0;
  }

  return static_cast<int>(copy_len);
}

void FipsBleL2cap::on_gap_connect(uint16_t conn_handle, int status) {
  if (status != 0) {
    ESP_LOGE(TAG, "BLE connection failed: %d", status);
    this->start_advertising();
    return;
  }

  this->conn_handle_ = conn_handle;
  this->state_ = L2capState::BLE_CONNECTED;
  ESP_LOGI(TAG, "BLE connected, handle=%d", conn_handle);

  int rc = ble_l2cap_create_server(FIPS_L2CAP_PSM, FIPS_L2CAP_MTU, FipsBleL2cap::l2cap_event_cb, this);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_l2cap_create_server failed: %d", rc);
  }
}

void FipsBleL2cap::on_gap_disconnect(uint16_t conn_handle, int reason) {
  ESP_LOGI(TAG, "BLE disconnected, handle=%d, reason=%d", conn_handle, reason);
  this->conn_handle_ = 0;
  this->l2cap_chan_ = nullptr;
  this->state_ = L2capState::DISCONNECTED;
}

void FipsBleL2cap::on_l2cap_accept(uint16_t conn_handle, uint16_t peer_sdu_size, struct ble_l2cap_chan *chan) {
  ESP_LOGI(TAG, "L2CAP CoC accept, peer_mtu=%d", peer_sdu_size);
  this->peer_mtu_ = peer_sdu_size;

  struct os_mbuf *sdu_rx = os_mbuf_get_pkthdr(&this->sdu_pool_, 0);
  if (sdu_rx == nullptr) {
    ESP_LOGE(TAG, "os_mbuf_get_pkthdr failed for accept");
    return;
  }

  int rc = ble_l2cap_recv_ready(chan, sdu_rx);
  if (rc != 0) {
    os_mbuf_free_chain(sdu_rx);
    ESP_LOGE(TAG, "ble_l2cap_recv_ready failed: %d", rc);
  }
}

void FipsBleL2cap::on_l2cap_connected(int status, uint16_t conn_handle, struct ble_l2cap_chan *chan) {
  if (status != 0) {
    ESP_LOGE(TAG, "L2CAP CoC connect failed: %d", status);
    return;
  }

  this->l2cap_chan_ = chan;
  this->state_ = L2capState::L2CAP_CONNECTED;

  struct ble_l2cap_chan_info chan_info;
  if (ble_l2cap_get_chan_info(chan, &chan_info) == 0) {
    ESP_LOGI(TAG, "L2CAP connected, psm=0x%02x, our_mtu=%d, peer_mtu=%d", chan_info.psm,
             chan_info.our_coc_mtu, chan_info.peer_coc_mtu);
    this->peer_mtu_ = chan_info.peer_coc_mtu;
  }

  if (this->do_pubkey_exchange()) {
    this->state_ = L2capState::READY;
    ESP_LOGI(TAG, "L2CAP transport ready");
  } else {
    ESP_LOGE(TAG, "pubkey exchange failed");
    this->state_ = L2capState::DISCONNECTED;
  }
}

void FipsBleL2cap::on_l2cap_disconnected(uint16_t conn_handle, struct ble_l2cap_chan *chan) {
  ESP_LOGI(TAG, "L2CAP CoC disconnected");
  this->l2cap_chan_ = nullptr;
  this->state_ = L2capState::DISCONNECTED;
}

void FipsBleL2cap::on_l2cap_data_received(struct ble_l2cap_chan *chan, struct os_mbuf *sdu_rx) {
  if (sdu_rx == nullptr) {
    this->on_l2cap_accept(this->conn_handle_, this->peer_mtu_, chan);
    return;
  }

  size_t total_len = 0;
  struct os_mbuf *cur = sdu_rx;
  while (cur != nullptr) {
    total_len += cur->om_len;
    cur = SLIST_NEXT(cur, om_next);
  }

  if (this->rx_buf_len_ + total_len > L2CAP_FRAME_CAP) {
    this->rx_buf_len_ = 0;
    this->rx_buf_pos_ = 0;
    this->rx_frame_ready_ = false;
    os_mbuf_free_chain(sdu_rx);
    this->on_l2cap_accept(this->conn_handle_, this->peer_mtu_, chan);
    return;
  }

  cur = sdu_rx;
  while (cur != nullptr) {
    if (cur->om_len > 0) {
      std::memcpy(this->rx_buf_.data() + this->rx_buf_len_, cur->om_data, cur->om_len);
      this->rx_buf_len_ += cur->om_len;
    }
    cur = SLIST_NEXT(cur, om_next);
  }

  os_mbuf_free_chain(sdu_rx);
  this->last_activity_ = millis();

  while (this->rx_buf_pos_ + 2 <= this->rx_buf_len_) {
    uint16_t payload_len = static_cast<uint16_t>(this->rx_buf_[this->rx_buf_pos_]) |
                           (static_cast<uint16_t>(this->rx_buf_[this->rx_buf_pos_ + 1]) << 8);

    if (payload_len == 0 || payload_len > 1500) {
      this->rx_buf_pos_ = this->rx_buf_len_;
      break;
    }

    if (this->rx_buf_pos_ + 2 + payload_len > this->rx_buf_len_)
      break;

    this->rx_frame_ready_ = true;
    this->rx_frame_len_ = payload_len;
    break;
  }

  this->on_l2cap_accept(this->conn_handle_, this->peer_mtu_, chan);
}

bool FipsBleL2cap::do_pubkey_exchange() {
  std::array<uint8_t, PRIVKEY_SIZE> secret{};
  ecdh_pubkey(secret.data(), this->peer_pub_.data());

  std::array<uint8_t, 33> tx;
  tx[0] = 0x00;
  std::memcpy(tx.data() + 1, this->peer_pub_.data() + 1, 32);

  if (!this->send_raw(tx.data(), 33)) {
    ESP_LOGE(TAG, "failed to send pubkey");
    return false;
  }

  uint32_t start = millis();
  while (millis() - start < PUBKEY_EXCHANGE_TIMEOUT_MS) {
    if (this->rx_frame_ready_ && this->rx_frame_len_ == 33) {
      uint8_t prefix = this->rx_buf_[this->rx_buf_pos_ + 2];
      if (prefix == 0x00) {
        this->peer_pub_[0] = 0x02;
        std::memcpy(this->peer_pub_.data() + 1, this->rx_buf_.data() + this->rx_buf_pos_ + 3, 32);
        this->rx_buf_pos_ += 2 + 33;
        this->rx_frame_ready_ = false;
        this->rx_frame_len_ = 0;
        if (this->rx_buf_pos_ >= this->rx_buf_len_) {
          this->rx_buf_len_ = 0;
          this->rx_buf_pos_ = 0;
        }
        ESP_LOGI(TAG, "pubkey exchange OK");
        return true;
      }
    }
    delay(10);
  }

  ESP_LOGE(TAG, "pubkey exchange timeout");
  return false;
}

int FipsBleL2cap::gap_event_cb(struct ble_gap_event *event, void *arg) {
  auto *instance = static_cast<FipsBleL2cap *>(arg);
  if (instance == nullptr)
    return 0;

  switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
      instance->on_gap_connect(event->connect.conn_handle, event->connect.status);
      return 0;

    case BLE_GAP_EVENT_DISCONNECT:
      instance->on_gap_disconnect(event->disconnect.conn_handle, event->disconnect.reason);
      return 0;

    case BLE_GAP_EVENT_ADV_COMPLETE:
      ESP_LOGD(TAG, "advertising complete, reason=%d", event->adv_complete.reason);
      instance->start_advertising();
      return 0;

    case BLE_GAP_EVENT_CONN_UPDATE:
      return 0;

    case BLE_GAP_EVENT_CONN_UPDATE_REQ:
      return 0;

    default:
      return 0;
  }
}

int FipsBleL2cap::l2cap_event_cb(struct ble_l2cap_event *event, void *arg) {
  auto *instance = static_cast<FipsBleL2cap *>(arg);
  if (instance == nullptr)
    return 0;

  switch (event->type) {
    case BLE_L2CAP_EVENT_COC_ACCEPT:
      instance->on_l2cap_accept(event->accept.conn_handle, event->accept.peer_sdu_size, event->accept.chan);
      return 0;

    case BLE_L2CAP_EVENT_COC_CONNECTED:
      instance->on_l2cap_connected(event->connect.status, event->connect.conn_handle, event->connect.chan);
      return 0;

    case BLE_L2CAP_EVENT_COC_DISCONNECTED:
      instance->on_l2cap_disconnected(event->disconnect.conn_handle, event->disconnect.chan);
      return 0;

    case BLE_L2CAP_EVENT_COC_DATA_RECEIVED:
      instance->on_l2cap_data_received(event->receive.chan, event->receive.sdu_rx);
      return 0;

    case BLE_L2CAP_EVENT_COC_TX_UNSTALLED:
      ESP_LOGD(TAG, "L2CAP tx unstalled");
      return 0;

    default:
      return 0;
  }
}

#endif  // USE_FIPS_BLE
#endif  // USE_ESP32
