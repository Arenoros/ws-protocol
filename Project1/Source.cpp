#include <iostream>
#include <stddef.h>
#include <vector>
#include <array>
#include <thread>
#include <map>
#include <regex>

#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#include <Winsock2.h>
#include <WS2tcpip.h>
#include "sha1.h"
#include <cassert>
#pragma comment(lib, "wsock32.lib")
#pragma comment(lib, "Ws2_32.lib")
#include <openssl/sha.h>
inline bool InitializeSockets() {
#if PLATFORM == PLATFORM_WINDOWS
    WSADATA WsaData;
    return WSAStartup(MAKEWORD(2, 2), &WsaData) == NO_ERROR;
#else
    return true;
#endif
}
inline void ShutdownSockets() {
#if PLATFORM == PLATFORM_WINDOWS
    WSACleanup();
#endif
}

void parse_headers(std::string_view header, std::map<std::string, std::string>& out) {
    auto start = 0;
    auto pos = header.find("\r\n");
    if(pos == std::string::npos) return;
    const std::regex re("GET (.*) (.*)");
    std::match_results<std::string_view::const_iterator> match;
    if(std::regex_search(header.begin() + start, header.begin() + pos, match, re)) {
        out["GET"] = match[1];
        out["HTTP"] = match[2];
        start = pos + 2;
        pos = header.find("\r\n", start);
    }
    const std::regex kv("(.*): (.*)");
    while(std::regex_search(header.begin() + start, header.begin() + pos, match, kv)) {
        out[match[1]] = match[2];
        start = pos + 2;
        pos = header.find("\r\n", start);
    }
}
void custom_sha1(std::string Key) {
    auto sha1 = std::make_unique<my::SHA1>();
    sha1->addBytes(Key.c_str(), Key.size());
    std::array<uint8_t, 20> data;
    sha1->getDigest(data);
}
bool test_Accept() {
    std::string Key = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::array<uint8_t, 20> data;
    SHA1((const unsigned char*)Key.c_str(), Key.size(), data.data());
    std::string Accept = my::to_base64(data);
    return Accept == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
}

std::string create_handshake(std::map<std::string, std::string>& headers) {
    std::string Key = headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::array<uint8_t, 20> hash;
    SHA1((const uint8_t*)Key.c_str(), Key.size(), hash.data());
    std::string Accept = my::to_base64(hash);

    std::string handshake = headers["HTTP"] +
                            " 101 Web Socket Protocol Handshake\r\n"
                            "Upgrade: WebSocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: " +
                            Accept +
                            "\r\n"
                            //"Sec-WebSocket-Protocol: chat\r\n"
                            "WebSocket-Origin: http://" +
                            headers["Host"] +
                            "\r\n"
                            "WebSocket-Location: ws://" +
                            headers["Host"] + headers["GET"] + "\r\n\r\n";
    return handshake;
}
void on_read(std::vector<uint8_t>& req) {}
void on_close(SOCKET sock) { closesocket(sock); }

void on_error(SOCKET sock) {
    printf("Error: %d\n", WSAGetLastError());
    closesocket(sock);
}
template<class Cont>
int read_from(SOCKET sock, Cont& req, const Cont& end) {
    std::array<char, 1440> buf;
    int n = 0;
    while((n = recv(sock, buf.data(), buf.size(), 0)) > 0) {
        if(n == 0) return 0;
        req.insert(req.end(), buf.begin(), buf.begin() + n);
        auto it = std::search(req.end() - end.size(), req.end(), end.begin(), end.end());
        if(it != req.end()) return req.size();
    }
    if(n == -1) on_error(sock);
    return n;
}

int send_to(SOCKET sock, const char* resp, int len) {
    int limit = 1440;
    int n = 0;
    while((n = send(sock, resp, std::min(limit, len), 0)) > 0) {
        resp += n;
        len -= n;
    }
    return n;
}

struct WSFrame {
    enum TOpcode { Continue = 0x0, Text = 0x1, Binary = 0x2, Ping = 0x9, Pong = 0x10 };
    WSFrame(uint8_t* buf, int size)
        : full_len(0), len(0), pos(0), _mask(0), _buf(buf), _buf_size(size), data(nullptr) {
        _header[1] = _header[0] = 0;  // short_len = has_mask = opcode = rsv = fin = 0;
        _recv_size =0;
    }
    int load_from(SOCKET sock) {
        return _recv_size = recv(sock, (char*)_buf, _buf_size, 0);
    }
    int updte_header() {
        _header[0] = _buf[0];
        _header[1] = _buf[1];
        int pad = 2;
        full_len = short_len;
        if(full_len == 126) {
            full_len = ntohs(*(uint16_t*)(_buf + pad));
            pad += sizeof(uint16_t);
        } else if(full_len == 127) {
            full_len = ntohll(*(uint64_t*)(_buf + pad));
            pad += sizeof(uint64_t);
        }
        printf("Client: fin=%d, opcode=%d, mask=%d, len=%d\n",
               fin,
               opcode,
               has_mask,
               (int)full_len);
        if(has_mask) {
            _mask = *(uint32_t*)(_buf + pad);
            pad += sizeof(uint32_t);
        }
        data = _buf + pad;
        len = _recv_size - pad;
        if(full_len < len) {
            len = full_len;
            return full_len + pad;
        }
    }
    union {
        struct {
            uint8_t fin : 1;
            uint8_t rsv : 3;
            uint8_t opcode : 4;
            uint8_t has_mask : 1;
            uint8_t short_len : 7;
        };
        uint8_t _header[2];
    };

    uint64_t full_len;
    uint64_t len, pos;
    union {
        uint8_t mask[4];
        uint32_t _mask;
    };
    uint8_t* _buf;
    int _buf_size, _recv_size;
    const uint8_t* data;
};
void decode(uint8_t* out, const uint8_t* data, int len, uint8_t mask[4]) {
    for(int i = 0; i < len; ++i) { out[i] = data[i] ^ mask[i % 4]; }
}
template<class Cont>
void add_payload(Cont& payload, WSFrame& frame) {
    if(frame.has_mask) {
        decode((uint8_t*)&payload[frame.pos], frame.data, frame.len, frame.mask);
    } else {
        payload.insert(payload.begin() + frame.pos, frame.data, frame.data + frame.len);
    }
    frame.pos += frame.len;
}

int read_frame_header(const uint8_t* buf, int size, WSFrame& frame) {
    int pad = 2;
    frame.fin = buf[0] & 0x80 ? 1 : 0;
    frame.has_mask = buf[1] & 0x80 ? 1 : 0;

    frame.rsv = buf[0] & 0x70;
    frame.opcode = buf[0] & 0x0F;
    frame.full_len = buf[1] & 0x7F;

    if(frame.full_len == 126) {
        frame.full_len = ntohs(*(uint16_t*)(buf + pad));
        pad += sizeof(uint16_t);
    } else if(frame.len == 127) {
        frame.full_len = ntohll(*(uint64_t*)(buf + pad));
        pad += sizeof(uint64_t);
    }
    printf("Client: fin=%d, opcode=%d, mask=%d, len=%d\n",
           frame.fin,
           frame.opcode,
           frame.has_mask,
           (int)frame.full_len);
    if(frame.has_mask) {
        frame._mask = *(uint32_t*)(buf + pad);
        pad += sizeof(uint32_t);
    }
    frame.data = buf + pad;
    frame.len = size - pad;
    if(frame.full_len < frame.len) {
        frame.len = frame.full_len;
        return frame.full_len + pad;
    }
    return 0;
}
void print_bin(const std::vector<uint8_t>& data) {
    printf("Binary: \n\t");
    for(size_t i = 0; i < data.size(); ++i) {
        printf("0x%02x ", data[i]);
        if(i + 1 % 16 == 0) printf("\n\t");
    }
    printf("\n");
}
void print_text(const std::string& data) {
    printf("Text: \n");
    printf("\t%s\n", data.c_str());
}

bool frame_complited(WSFrame& frame) { return frame.full_len <= frame.len + frame.pos; }

int frame_ping(WSFrame& frame) {}
int frame_pong(WSFrame& frame) {}

int send_pong(WSFrame& frame) {}
int on_binary_data(WSFrame& frame) {
    std::vector<uint8_t> payload;
    add_payload(payload, frame);
}
int on_text_data(WSFrame& frame) {
    std::string payload;
    add_payload(payload, frame);
}

void on_connect(SOCKET sock, sockaddr_in addr) {
    printf("Connected: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    std::map<std::string, std::string> headers;
    std::string header;
    if(read_from(sock, header, std::string("\r\n\r\n")) == -1) { return; }
    printf("Headers: %s\n", header.c_str());
    parse_headers(header, headers);
    auto resp = create_handshake(headers);
    if(send_to(sock, resp.c_str(), resp.size()) == -1) { return; }
    printf("Response: %s\n", resp.c_str());

    uint8_t buf[1440];
    WSFrame frame(buf, 1440);
    while(1) {
        WSFrame::TOpcode prev = WSFrame::Continue;
        int n = 0;

        frame.data = nullptr;
        frame.pos = 0;
        for(;;) {
            if(frame.load_from(sock) == -1) {
                on_error(sock);
                return;
            }
            //if((n = recv(sock, (char*)buf, sizeof(buf), 0)) == -1) {
            //   
            //}
            const uint8_t* data = buf;
            while(n > 0) {
                n = read_frame_header(data, n, frame);
                prev = WSFrame::TOpcode(frame.opcode ? frame.opcode : prev);
                switch(prev) {
                case WSFrame::Text:
                    n = on_text_data(frame);
                    break;
                case WSFrame::Binary:
                    n = on_binary_data(frame);
                    break;
                case WSFrame::Ping:
                    n = frame_ping(frame);
                    break;
                default:
                    break;
                }
                data += n;
                if(n > 0 && frame.fin) {
                    payload_final();
                    frame.pos = 0;
                }
            }
            if(frame.pos < frame.full_len) continue;
            if(frame.fin) break;
            frame.data = nullptr;
        }
        payload_final();
        /*n = send_to(sock, (char*)buf, n);
        if(n == -1) {
            on_error(sock);
            return;
        }*/
    }
}

int main(void) {
    InitializeSockets();
    assert(test_Accept());
    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);

    if(bind(server, (sockaddr*)&addr, sizeof(sockaddr)) != 0) {
        printf("bind error: %d\n", WSAGetLastError());
        return 1;
    }
    if(listen(server, 10) != 0) {
        printf("listen error: %d\n", WSAGetLastError());
        return 1;
    }
    sockaddr_in client;
    int len = sizeof(client);
    while(SOCKET sock = accept(server, (sockaddr*)&client, &len)) {
        if(sock == INVALID_SOCKET) {
            printf("server acccept failed: %d\n", WSAGetLastError());
            closesocket(server);
            return 1;
        }
        std::thread th(&on_connect, sock, client);
        th.detach();
    }
    WSACleanup();
    return 0;
}
