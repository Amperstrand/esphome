#ifdef USE_FIPS_BLE

#include "fips_ble_l2cap.h"
#include "fips_noise.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"

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

namespace esphome::fips_ble {

using esphome::delay;
using esphome::millis;

static const char *const TAG = "fips_ble.l2cap";

static FipsBleL2cap *g_l2cap_instance{nullptr};

static constexpr uint32_t L2CAP_RX_BUF_COUNT = 20;

static constexpr uint32_t ACTIVITY_TIMEOUT_MS = 30000;
static constexpr uint32_t PUBKEY_EXCHANGE_TIMEOUT_MS = 5000;

static os_membuf_t s_sdu_mem[OS_MEMPOOL_SIZE(L2CAP_RX_BUF_COUNT, FIPS_L2CAP_MTU)];
static struct os_mempool s_sdu_mempool;
static struct os_mbuf_pool s_sdu_pool;

bool FipsBleL2cap::setup() {
  g_l2cap_instance = this;

  int rc = os_mempool_init(&s_sdu_mempool, L2CAP_RX_BUF_COUNT, FIPS_L2CAP_MTU, s_sdu_mem, "fips_coc");
  if (rc != 0) {
    ESP_LOGE(TAG, "os_mempool_init failed: %d", rc);
    return false;
  }

  rc = os_mbuf_pool_init(&s_sdu_pool, &s_sdu_mempool, FIPS_L2CAP_MTU, L2CAP_RX_BUF_COUNT);
  if (rc != 0) {
    ESP_LOGE(TAG, "os_mbuf_pool_init failed: %d", rc);
    return false;
  }

  rc = ble_hs_util_ensure_addr(0);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_hs_util_ensure_addr failed: %d", rc);
    return false;
  }

  uint8_t static_rnd[6] = {0x64, 0xE8, 0x33, 0x72, 0x01, 0xE6};
  rc = ble_hs_id_set_rnd(static_rnd);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_hs_id_set_rnd failed: %d", rc);
    return false;
  }

  this->own_addr_type_ = BLE_ADDR_RANDOM;
  uint8_t addr_val[6] = {0};
  ble_hs_id_copy_addr(this->own_addr_type_, addr_val, nullptr);
  ESP_LOGI(TAG, "BLE address: %02x:%02x:%02x:%02x:%02x:%02x (random)", addr_val[0], addr_val[1], addr_val[2],
            addr_val[3], addr_val[4], addr_val[5]);

  rc = ble_l2cap_create_server(FIPS_L2CAP_PSM, FIPS_L2CAP_MTU, FipsBleL2cap::l2cap_event_cb, this);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_l2cap_create_server failed: %d", rc);
    return false;
  }

  this->start_advertising();
  return true;
}

void FipsBleL2cap::start_advertising() {
  struct ble_gap_adv_params adv_params;
  struct ble_hs_adv_fields fields;
  struct ble_hs_adv_fields sr_fields;
  ble_addr_t wl_addr;
  int rc;

  std::memset(&fields, 0, sizeof(fields));
  fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

  ble_uuid128_t fips_uuid = BLE_UUID128_INIT(
      0x4c, 0x8f, 0x64, 0x40, 0xcc, 0xc9, 0x87, 0x9f,
      0xc0, 0x42, 0xc5, 0x2c, 0x90, 0xb7, 0x90, 0x9c);
  fields.uuids128 = &fips_uuid;
  fields.num_uuids128 = 1;
  fields.uuids128_is_complete = 1;

  rc = ble_gap_adv_set_fields(&fields);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: %d", rc);
    return;
  }

  std::memset(&sr_fields, 0, sizeof(sr_fields));
  const char *name = ble_svc_gap_device_name();
  sr_fields.name = (uint8_t *) name;
  sr_fields.name_len = strlen(name);
  sr_fields.name_is_complete = 1;
  sr_fields.tx_pwr_lvl_is_present = 1;
  sr_fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;

  rc = ble_gap_adv_rsp_set_fields(&sr_fields);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_gap_adv_rsp_set_fields failed: %d", rc);
    return;
  }

  std::memset(&adv_params, 0, sizeof(adv_params));
  adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
  adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

  if (this->has_peer_mac_) {
    std::memset(&wl_addr, 0, sizeof(wl_addr));
    wl_addr.type = BLE_ADDR_PUBLIC;
    std::memcpy(wl_addr.val, this->allowed_peer_mac_.data(), this->allowed_peer_mac_.size());

    rc = ble_gap_wl_set(&wl_addr, 1);
    if (rc != 0) {
      ESP_LOGW(TAG, "ble_gap_wl_set failed: %d, falling back to no-filter", rc);
    } else {
      adv_params.filter_policy = BLE_HCI_ADV_FILT_CONN;
      ESP_LOGI(TAG, "BLE whitelist set: only %02x:%02x:%02x:%02x:%02x:%02x can connect", wl_addr.val[5],
               wl_addr.val[4], wl_addr.val[3], wl_addr.val[2], wl_addr.val[1], wl_addr.val[0]);
    }
  }

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
    this->rx_frame_len_ = 0;
    this->peer_caps_ = 0;
    if (this->disconnect_time_ == 0) {
      this->disconnect_time_ = millis();
    }
    if (millis() - this->disconnect_time_ >= 500) {
      this->disconnect_time_ = 0;
      this->start_advertising();
    }
    return;
  }

  if (this->state_ == L2capState::L2CAP_CONNECTED) {
    if (millis() - this->pubkey_exchange_start_ > PUBKEY_EXCHANGE_TIMEOUT_MS) {
      ESP_LOGE(TAG, "pubkey exchange timeout");
      this->state_ = L2capState::DISCONNECTED;
      return;
    }

    if (!this->pubkey_recv_ && this->rx_frame_ready_ && this->rx_frame_len_ >= 33) {
      uint8_t prefix = this->rx_buf_[this->rx_buf_pos_ + 2];
      if (prefix == 0x00) {
        this->peer_pub_[0] = 0x02;
        std::memcpy(this->peer_pub_.data() + 1, this->rx_buf_.data() + this->rx_buf_pos_ + 3, 32);
        if (this->rx_frame_len_ >= 34) {
          this->peer_caps_ = this->rx_buf_[this->rx_buf_pos_ + 35];
        }
        this->rx_buf_pos_ += 2 + this->rx_frame_len_;
        this->rx_frame_ready_ = false;
        this->rx_frame_len_ = 0;
        if (this->rx_buf_pos_ >= this->rx_buf_len_) {
          this->rx_buf_len_ = 0;
          this->rx_buf_pos_ = 0;
        }
        this->pubkey_recv_ = true;
      }
    }

    if (this->pubkey_recv_ && !this->pubkey_sent_) {
      std::array<uint8_t, 33> tx;
      tx[0] = 0x00;
      std::memcpy(tx.data() + 1, this->own_pub_.data() + 1, 32);
      if (this->send_raw(tx.data(), 33)) {
        this->pubkey_sent_ = true;
        this->state_ = L2capState::PUBKEY_EXCHANGED;
        ESP_LOGI(TAG, "pubkey exchange OK");
      } else {
        ESP_LOGE(TAG, "failed to send pubkey");
        this->state_ = L2capState::DISCONNECTED;
      }
    }

    return;
  }

  if (this->state_ == L2capState::PUBKEY_EXCHANGED) {
    this->state_ = L2capState::READY;
    ESP_LOGI(TAG, "L2CAP transport ready");
  }

  if (this->state_ != L2capState::READY)
    return;
}

struct os_mbuf *FipsBleL2cap::alloc_sdu_tx() {
  return os_mbuf_get_pkthdr(&s_sdu_pool, 0);
}

bool FipsBleL2cap::send(const uint8_t *data, size_t len) {
  if (this->state_ != L2capState::READY || this->l2cap_chan_ == nullptr)
    return false;

  // Length-prefix framing: [len:2 BE][payload]
  // Required for interop with FIPS daemon (rev 42d9adb+) which uses this
  // framing for cross-platform compatibility (macOS CoreBluetooth coalesces
  // byte streams). Linux BlueZ SeqPacket also uses it now.
  size_t framed_len = 2 + len;
  if (framed_len > this->peer_mtu_)
    return false;

  struct os_mbuf *sdu_tx = this->alloc_sdu_tx();
  if (sdu_tx == nullptr) {
    ESP_LOGE(TAG, "os_mbuf_get_pkthdr failed for send");
    return false;
  }

  uint8_t len_prefix[2];
  len_prefix[0] = static_cast<uint8_t>((len >> 8) & 0xFF);
  len_prefix[1] = static_cast<uint8_t>(len & 0xFF);

  int rc = os_mbuf_append(sdu_tx, len_prefix, 2);
  if (rc != 0) {
    os_mbuf_free_chain(sdu_tx);
    ESP_LOGE(TAG, "os_mbuf_append len prefix failed: %d", rc);
    return false;
  }

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

  // Length-prefix framing: [len:2 BE][payload] — same as send()
  size_t framed_len = 2 + len;
  if (framed_len > this->peer_mtu_)
    return false;

  struct os_mbuf *sdu_tx = this->alloc_sdu_tx();
  if (sdu_tx == nullptr)
    return false;

  uint8_t len_prefix[2];
  len_prefix[0] = static_cast<uint8_t>((len >> 8) & 0xFF);
  len_prefix[1] = static_cast<uint8_t>(len & 0xFF);

  int rc = os_mbuf_append(sdu_tx, len_prefix, 2);
  if (rc != 0) {
    os_mbuf_free_chain(sdu_tx);
    return false;
  }

  rc = os_mbuf_append(sdu_tx, data, len);
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

  // Payload starts after 2-byte length prefix
  size_t payload_offset = this->rx_buf_pos_ + 2;
  size_t copy_len = this->rx_frame_len_;
  if (copy_len > buf_len)
    copy_len = buf_len;

  std::memcpy(buf, this->rx_buf_.data() + payload_offset, copy_len);

  // Advance past [2-byte prefix][payload]
  this->rx_buf_pos_ += 2 + this->rx_frame_len_;
  this->rx_frame_ready_ = false;
  this->rx_frame_len_ = 0;

  // Try to extract next complete frame from remaining buffer
  size_t available = this->rx_buf_len_ - this->rx_buf_pos_;
  if (available >= 2) {
    uint16_t next_len = static_cast<uint16_t>(this->rx_buf_[this->rx_buf_pos_]) |
                         (static_cast<uint16_t>(this->rx_buf_[this->rx_buf_pos_ + 1]) << 8);
    if (available >= 2 + next_len && next_len > 0) {
      this->rx_frame_ready_ = true;
      this->rx_frame_len_ = next_len;
    }
  }

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

   struct ble_gap_conn_desc desc;
   std::memset(&desc, 0, sizeof(desc));
   int rc = ble_gap_conn_find(conn_handle, &desc);
    if (rc != 0) {
      ESP_LOGW(TAG, "ble_gap_conn_find failed: %d", rc);
      ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
      return;
    }

    ESP_LOGD(TAG, "BLE GAP connect: peer_id_addr type=%d val=%02x:%02x:%02x:%02x:%02x:%02x",
             desc.peer_id_addr.type,
             desc.peer_id_addr.val[5], desc.peer_id_addr.val[4], desc.peer_id_addr.val[3],
             desc.peer_id_addr.val[2], desc.peer_id_addr.val[1], desc.peer_id_addr.val[0]);

    if (this->has_peer_mac_ && std::memcmp(desc.peer_id_addr.val, this->allowed_peer_mac_.data(), 6) != 0) {
      ESP_LOGW(TAG, "Unexpected connection from MAC %02x:%02x:%02x:%02x:%02x:%02x (expected whitelist only), ignoring",
               desc.peer_id_addr.val[5], desc.peer_id_addr.val[4], desc.peer_id_addr.val[3],
               desc.peer_id_addr.val[2], desc.peer_id_addr.val[1], desc.peer_id_addr.val[0]);
      return;
    }

    ESP_LOGI(TAG, "BLE peer MAC accepted: %02x:%02x:%02x:%02x:%02x:%02x",
             desc.peer_id_addr.val[5], desc.peer_id_addr.val[4], desc.peer_id_addr.val[3],
             desc.peer_id_addr.val[2], desc.peer_id_addr.val[1], desc.peer_id_addr.val[0]);

   this->conn_handle_ = conn_handle;
  this->state_ = L2capState::BLE_CONNECTED;
  ESP_LOGI(TAG, "BLE connected, handle=%d", conn_handle);
}

void FipsBleL2cap::on_gap_disconnect(uint16_t conn_handle, int reason) {
  ESP_LOGI(TAG, "BLE disconnected, handle=%d, reason=%d", conn_handle, reason);
  this->conn_handle_ = 0;
  this->l2cap_chan_ = nullptr;
  this->state_ = L2capState::DISCONNECTED;
  this->disconnect_time_ = millis();
}

void FipsBleL2cap::on_l2cap_accept(uint16_t conn_handle, uint16_t peer_sdu_size, struct ble_l2cap_chan *chan) {
  ESP_LOGI(TAG, "L2CAP CoC accept, peer_mtu=%d", peer_sdu_size);
  this->peer_mtu_ = peer_sdu_size;

  struct os_mbuf *sdu_rx = os_mbuf_get_pkthdr(&s_sdu_pool, 0);
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

  if (this->l2cap_chan_ != nullptr) {
    ESP_LOGW(TAG, "rejecting additional CoC, already have active channel");
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

  this->pubkey_exchange_start_ = millis();
  this->pubkey_sent_ = false;
  this->pubkey_recv_ = false;
}

void FipsBleL2cap::on_l2cap_disconnected(uint16_t conn_handle, struct ble_l2cap_chan *chan) {
  ESP_LOGI(TAG, "L2CAP CoC disconnected, handle=%d", conn_handle);
  if (chan == this->l2cap_chan_) {
    this->l2cap_chan_ = nullptr;
    this->state_ = L2capState::DISCONNECTED;
  }
}

void FipsBleL2cap::on_l2cap_data_received(struct ble_l2cap_chan *chan, struct os_mbuf *sdu_rx) {
  if (chan != this->l2cap_chan_) {
    ESP_LOGW(TAG, "data on non-active channel, dropping %d bytes", sdu_rx ? OS_MBUF_PKTLEN(sdu_rx) : 0);
    os_mbuf_free_chain(sdu_rx);
    return;
  }

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
    this->rx_frame_len_ = 0;
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

  // Length-prefix framing: try to extract complete [len:2 BE][payload] frame.
  // Only signal rx_frame_ready when we have a full frame (prefix + payload).
  // The payload is at rx_buf_[rx_buf_pos_ + 2 .. rx_buf_pos_ + 2 + frame_len].
  if (!this->rx_frame_ready_) {
    size_t available = this->rx_buf_len_ - this->rx_buf_pos_;
    ESP_LOGD(TAG, "rx frame check: available=%d buf_len=%d buf_pos=%d", available, this->rx_buf_len_, this->rx_buf_pos_);
    if (available >= 2) {
      uint16_t frame_len = (static_cast<uint16_t>(this->rx_buf_[this->rx_buf_pos_]) << 8) |
                           static_cast<uint16_t>(this->rx_buf_[this->rx_buf_pos_ + 1]);
      ESP_LOGD(TAG, "rx frame: frame_len=%d available=%d", frame_len, available);
      if (frame_len > 0 && available >= 2 + frame_len) {
        this->rx_frame_ready_ = true;
        this->rx_frame_len_ = frame_len;
        ESP_LOGD(TAG, "rx frame ready: len=%d prefix=0x%02x", frame_len, this->rx_buf_[this->rx_buf_pos_ + 2]);
      }
    }
  }

  this->on_l2cap_accept(this->conn_handle_, this->peer_mtu_, chan);
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
      instance->on_gap_disconnect(event->disconnect.conn.conn_handle, event->disconnect.reason);
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

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
