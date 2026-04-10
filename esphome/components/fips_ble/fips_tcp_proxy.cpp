#ifdef USE_FIPS_BLE

#include "fips_tcp_proxy.h"
#include "fips_ble_l2cap.h"
#include "esphome/core/log.h"

#include <cerrno>
#include <cstring>

#include <lwip/inet.h>
#include <lwip/ip_addr.h>
#include <lwip/sockets.h>

namespace esphome::fips_ble {

static const char *const TAG = "fips_ble.tcp_proxy";

void FipsTcpProxy::setup(FipsBleL2cap *l2cap, uint16_t api_port) {
  this->l2cap_ = l2cap;
  this->api_port_ = api_port;
  this->api_fd_ = -1;
  this->pending_outbound_len_ = 0;
}

bool FipsTcpProxy::connect_to_api() {
  if (this->api_fd_ >= 0) {
    return true;
  }

  int fd = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    ESP_LOGE(TAG, "socket() failed: %d", errno);
    return false;
  }

  struct sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(this->api_port_);

  if (lwip_connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
    ESP_LOGW(TAG, "connect() to 127.0.0.1:%u failed: %d", this->api_port_, errno);
    lwip_close(fd);
    return false;
  }

  int nonblocking = 1;
  if (lwip_ioctl(fd, FIONBIO, &nonblocking) < 0) {
    ESP_LOGW(TAG, "ioctl(FIONBIO) failed: %d", errno);
    lwip_close(fd);
    return false;
  }

  this->api_fd_ = fd;
  ESP_LOGI(TAG, "connected to API on 127.0.0.1:%u", this->api_port_);
  return true;
}

void FipsTcpProxy::read_from_api() {
  if (this->api_fd_ < 0 || this->pending_outbound_len_ > 0) {
    return;
  }

  fd_set read_fds;
  FD_ZERO(&read_fds);
  FD_SET(this->api_fd_, &read_fds);
  struct timeval tv = {0, 0};

  int ret = lwip_select(this->api_fd_ + 1, &read_fds, nullptr, nullptr, &tv);
  if (ret < 0) {
    ESP_LOGW(TAG, "select() failed: %d", errno);
    this->disconnect_api();
    return;
  }

  if (ret == 0 || !FD_ISSET(this->api_fd_, &read_fds)) {
    return;
  }

  ssize_t received = lwip_recv(this->api_fd_, this->pending_outbound_, TCP_PROXY_BUF_SIZE, 0);
  if (received > 0) {
    this->pending_outbound_len_ = static_cast<size_t>(received);
    return;
  }

  if (received == 0) {
    ESP_LOGI(TAG, "API connection closed");
    this->disconnect_api();
  } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
    ESP_LOGW(TAG, "recv() failed: %d", errno);
    this->disconnect_api();
  }
}

void FipsTcpProxy::disconnect_api() {
  if (this->api_fd_ >= 0) {
    lwip_close(this->api_fd_);
    this->api_fd_ = -1;
  }

  this->pending_outbound_len_ = 0;
}

void FipsTcpProxy::loop() {
  if (this->l2cap_ == nullptr || !this->l2cap_->is_ready()) {
    if (this->api_fd_ >= 0) {
      ESP_LOGI(TAG, "BLE link not ready, disconnecting API socket");
      this->disconnect_api();
    }
    return;
  }

  if (this->api_fd_ < 0 && !this->connect_to_api()) {
    return;
  }

  this->read_from_api();
}

void FipsTcpProxy::stop() {
  this->disconnect_api();
}

void FipsTcpProxy::forward_to_tcp(const uint8_t *data, size_t len) {
  if (len == 0) {
    return;
  }

  if (this->api_fd_ < 0 && !this->connect_to_api()) {
    ESP_LOGW(TAG, "dropping %u bytes, API connect failed", static_cast<unsigned>(len));
    return;
  }

  size_t total_sent = 0;
  while (total_sent < len) {
    ssize_t sent = lwip_send(this->api_fd_, data + total_sent, len - total_sent, 0);
    if (sent <= 0) {
      ESP_LOGW(TAG, "send() failed: %d", errno);
      this->disconnect_api();
      return;
    }

    total_sent += static_cast<size_t>(sent);
  }
}

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
