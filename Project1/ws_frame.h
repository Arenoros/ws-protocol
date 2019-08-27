#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>

#include "platform_conf.h"
inline int read_from(SOCKET sock, std::string& http) {
    char buf[1440];
    int n = 0;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        size_t pos = http.size();
        http.append(buf, n);
        if (pos > 3) pos -= 4;
        if (http.find("\r\n\r\n", pos) != std::string::npos) return http.size();
    }
    return n;
}

inline int send_to(SOCKET sock, const char* resp, int len) {
    int limit = 1440;
    int n = 0;
    while ((n = send(sock, resp, std::min(limit, len), 0)) > 0) {
        resp += n;
        len -= n;
    }
    return n;
}

inline void print_bin(const std::vector<uint8_t>& data) {
    printf("Binary: \n\t");
    for (size_t i = 0; i < data.size(); ++i) {
        printf("0x%02x ", data[i]);
        if (i + 1 % 16 == 0) printf("\n\t");
    }
    printf("\n");
}
inline void print_text(const std::string& data) {
    printf("Text: \n");
    printf("\t%s\n", data.c_str());
}

struct WSFrame {
    enum TOpcode { Continue = 0x0, Text = 0x1, Binary = 0x2, Ping = 0x9, Pong = 0x10 };
    WSFrame(uint8_t* buf, int size);
    void decode();
    void encode();
    int load_from(SOCKET sock);

    int send_to(SOCKET sock);
    bool has_frame() const;
    void next() ;
    uint8_t fin : 1;
    uint8_t rsv : 3;
    uint8_t opcode : 4;
    uint8_t has_mask : 1;
    uint8_t short_len : 7;
    uint8_t head_len;
    uint64_t payload_len;
    uint64_t len, pos;
    const uint8_t* payload;
    union {
        uint8_t mask[4];
        uint32_t _mask;
    };

private:
    uint8_t* _buf;
    int _buf_size, _recv_size, _buf_pos;
};
