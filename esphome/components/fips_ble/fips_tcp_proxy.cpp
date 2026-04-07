#ifdef USE_FIPS_BLE

#include "fips_tcp_proxy.h"
#include "fips_ble_l2cap.h"
#include "esphome/core/log.h"

#include <cstring>
#include <cerrno>

#include <lwip/sockets.h>
#include <lwip/inet.h>
#include <lwip/ip_addr.h>

namespace esphome::fips_ble {

static const char *const TAG = "fips_ble.tcp_proxy";

void FipsTcpProxy::setup(FipsBleL2cap *l2cap, uint16_t listen_port) {
  this->l2cap_ = l2cap;
  this->listen_port_ = listen_port;

  for (size_t i = 0; i < MAX_TCP_CLIENTS; i++) {
    this->client_fds_[i] = -1;
  }

  this->listen_on(listen_port);
}

bool FipsTcpProxy::listen_on(uint16_t port) {
  if (this->listen_fd_ >= 0) {
    close(this->listen_fd_);
    this->listen_fd_ = -1;
  }

  int fd = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    ESP_LOGE(TAG, "socket() failed: %d", errno);
    return false;
  }

  int opt = 1;
  lwip_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);

  if (lwip_bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    ESP_LOGE(TAG, "bind() failed: %d", errno);
    close(fd);
    return false;
  }

  if (lwip_listen(fd, 2) < 0) {
    ESP_LOGE(TAG, "listen() failed: %d", errno);
    close(fd);
    return false;
  }

  this->listen_fd_ = fd;
  ESP_LOGI(TAG, "listening on 127.0.0.1:%d", port);
  return true;
}

void FipsTcpProxy::loop() {
  if (this->l2cap_ == nullptr || !this->l2cap_->is_ready())
    return;

  this->accept_client();
  this->forward_tcp_to_fips(-1);
  this->forward_fips_to_tcp();
}

void FipsTcpProxy::accept_client() {
  if (this->listen_fd_ < 0)
    return;

  fd_set read_fds;
  FD_ZERO(&read_fds);
  FD_SET(this->listen_fd_, &read_fds);
  struct timeval tv = {0, 0};

  int ret = lwip_select(this->listen_fd_ + 1, &read_fds, nullptr, nullptr, &tv);
  if (ret <= 0)
    return;

  int client_fd = lwip_accept(this->listen_fd_, nullptr, nullptr);
  if (client_fd < 0) {
    ESP_LOGE(TAG, "accept() failed: %d", errno);
    return;
  }

  bool accepted = false;
  for (size_t i = 0; i < MAX_TCP_CLIENTS; i++) {
    if (this->client_fds_[i] < 0) {
      this->client_fds_[i] = client_fd;
      accepted = true;
      ESP_LOGI(TAG, "client connected, fd=%d", client_fd);
      break;
    }
  }

  if (!accepted) {
    ESP_LOGW(TAG, "max clients reached, rejecting fd=%d", client_fd);
    close(client_fd);
  }
}

void FipsTcpProxy::forward_tcp_to_fips(int client_fd) {
  for (size_t i = 0; i < MAX_TCP_CLIENTS; i++) {
    int fd = this->client_fds_[i];
    if (fd < 0)
      continue;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    struct timeval tv = {0, 1000};

    int ret = lwip_select(fd + 1, &read_fds, nullptr, nullptr, &tv);
    if (ret <= 0)
      continue;

    uint8_t buf[TCP_PROXY_BUF_SIZE];
    ssize_t n = lwip_recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      ESP_LOGI(TAG, "client disconnected, fd=%d", fd);
      close(fd);
      this->client_fds_[i] = -1;
      continue;
    }

    if (!this->l2cap_->send(buf, static_cast<size_t>(n))) {
      ESP_LOGW(TAG, "failed to forward %d bytes to FIPS", static_cast<int>(n));
    }
  }
}

void FipsTcpProxy::forward_fips_to_tcp() {
  uint8_t buf[TCP_PROXY_BUF_SIZE];
  int n = this->l2cap_->recv(buf, sizeof(buf));
  if (n <= 0)
    return;

  for (size_t i = 0; i < MAX_TCP_CLIENTS; i++) {
    int fd = this->client_fds_[i];
    if (fd < 0)
      continue;

    ssize_t sent = lwip_send(fd, buf, static_cast<size_t>(n), 0);
    if (sent < 0) {
      ESP_LOGW(TAG, "send to client fd=%d failed: %d", fd, errno);
      close(fd);
      this->client_fds_[i] = -1;
    }
  }
}

void FipsTcpProxy::stop() {
  for (size_t i = 0; i < MAX_TCP_CLIENTS; i++) {
    if (this->client_fds_[i] >= 0) {
      close(this->client_fds_[i]);
      this->client_fds_[i] = -1;
    }
  }

  if (this->listen_fd_ >= 0) {
    close(this->listen_fd_);
    this->listen_fd_ = -1;
  }
}

void FipsTcpProxy::forward_to_tcp(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < MAX_TCP_CLIENTS; i++) {
    int fd = this->client_fds_[i];
    if (fd < 0)
      continue;

    ssize_t sent = lwip_send(fd, data, len, 0);
    if (sent < 0) {
      ESP_LOGW(TAG, "forward to client fd=%d failed: %d", fd, errno);
      close(fd);
      this->client_fds_[i] = -1;
    }
  }
}

}  // namespace esphome::fips_ble

#endif  // USE_FIPS_BLE
