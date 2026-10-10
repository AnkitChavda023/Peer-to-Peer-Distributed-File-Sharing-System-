#pragma once

#include <string>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

using namespace std;

static const uint32_t MAX_MESSAGE_SIZE = 64u * 1024u * 1024u;

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

inline bool writeAll(int sock, const char *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(sock, data + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        off += (size_t)n;
    }
    return true;
}

inline bool readAll(int sock, char *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(sock, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        off += (size_t)n;
    }
    return true;
}

inline bool sendFramed(int sock, const std::string &payload) {
    uint32_t netLen = htonl((uint32_t)payload.size());
    if (!writeAll(sock, (const char *)&netLen, sizeof(netLen))) return false;
    if (payload.empty()) return true;
    return writeAll(sock, payload.data(), payload.size());
}

inline bool recvFramed(int sock, std::string &payload) {
    uint32_t netLen = 0;
    if (!readAll(sock, (char *)&netLen, sizeof(netLen))) return false;
    uint32_t len = ntohl(netLen);
    if (len > MAX_MESSAGE_SIZE) return false;
    payload.assign(len, '\0');
    if (len == 0) return true;
    return readAll(sock, &payload[0], len);
}

inline int connectWithTimeout(const std::string &ip, int port, int timeoutMs) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    int rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    if (rc != 0) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;

        rc = select(sock + 1, nullptr, &wfds, nullptr, &tv);
        if (rc <= 0) {
            close(sock);
            return -1;
        }

        int soErr = 0;
        socklen_t elen = sizeof(soErr);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &soErr, &elen) < 0 || soErr != 0) {
            close(sock);
            return -1;
        }
    }

    fcntl(sock, F_SETFL, flags);
    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    return sock;
}

inline bool tryParseInt(const std::string &s, int &out) {
    try {
        size_t consumed = 0;
        int v = std::stoi(s, &consumed);
        if (consumed != s.size()) return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

inline bool tryParseLongLong(const std::string &s, long long &out) {
    try {
        size_t consumed = 0;
        long long v = std::stoll(s, &consumed);
        if (consumed != s.size()) return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}
