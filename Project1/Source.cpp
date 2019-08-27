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
#include <list>

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

bool test_Accept() {
    std::string Key = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t data[20];
    my::SHA1::make(Key, data);
    Key = my::to_base64(data);
    return Key == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
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

int read_from(SOCKET sock, std::string& http) {
    char buf[1440];
    int n = 0;
    while((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        size_t pos = http.size();
        http.append(buf, n);
        if(pos > 3) pos -= 4;
        if(http.find("\r\n\r\n", pos) != std::string::npos) return http.size();
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
        : head_len(0), payload_len(0), len(0), pos(0), payload(nullptr), _mask(0), _buf(buf),
          _buf_size(size) {
        short_len = has_mask = opcode = rsv = fin = 0;
        _recv_size = _buf_pos = 0;
    }
    void decode() {
        if(has_mask)
            for(uint64_t j = 0, i = _buf_pos - len; i < _buf_pos; _buf[i++] ^= mask[j++ % 4]) {}
    }
    void encode() {
        if(has_mask)
            for(int i = 0; i < len; ++i) { _buf[_buf_pos - len] ^= mask[i % 4]; }
    }
    int load_from(SOCKET sock) {
        _buf_pos = 0;
        return _recv_size = recv(sock, (char*)_buf, _buf_size, 0);
    }

    int send_to(SOCKET sock) {
        uint8_t meta[2 + sizeof(payload_len) + sizeof(mask)];

        uint8_t meta_len = 2;
        meta[0] |= fin << 7;
        meta[0] |= rsv << 4;
        meta[0] |= opcode;
        meta[1] |= has_mask << 7;
        if(payload_len < 126) {
            meta[1] |= payload_len;
        } else if(payload_len < UINT16_MAX) {
            *(uint16_t*)meta[2] = ntohs(payload_len);
            meta_len += sizeof(uint16_t);
        } else {
            *(uint64_t*)meta[2] = ntohll(payload_len);
            meta_len += sizeof(uint64_t);
        }
        if(has_mask) {
            *(uint32_t*)meta[meta_len] = _mask;
            meta_len += 4;
        }
        uint8_t* frame = (uint8_t*)payload;
        if(_buf_pos - len > meta_len) {
            frame = _buf + _buf_pos - len - meta_len;
            memcpy(_buf + _buf_pos - len - meta_len, meta, meta_len);
        } else if(::send_to(sock, (const char*)meta, meta_len) == -1)
            return -1;
        return ::send_to(sock, (const char*)frame, len);
    }
    bool has_frame() const { return _recv_size > _buf_pos; }
    void next() {
        uint8_t* cur_buf = _buf + _buf_pos;
        fin = cur_buf[0] >> 7;
        has_mask = cur_buf[1] >> 7;
        rsv = cur_buf[0] >> 4 & 0x7;
        opcode = cur_buf[0] & 0xF;
        short_len = cur_buf[1] & 0x7F;

        head_len = 2;
        if(short_len < 126) { payload_len = short_len; }
        if(short_len == 126) {
            payload_len = ntohs(*(uint16_t*)(cur_buf + head_len));
            head_len += sizeof(uint16_t);
        } else if(short_len == 127) {
            payload_len = ntohll(*(uint64_t*)(cur_buf + head_len));
            head_len += sizeof(uint64_t);
        }
        printf("Client: fin=%d, opcode=%d, mask=%d, len=%d\n",
               fin,
               opcode,
               has_mask,
               (int)payload_len);
        if(has_mask) {
            _mask = *(uint32_t*)(cur_buf + head_len);
            head_len += sizeof(uint32_t);
        }
        payload = cur_buf + head_len;
        _buf_pos += head_len;
        len = std::min<uint64_t>(payload_len, _recv_size - _buf_pos);
        _buf_pos += len;
    }
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
void decode(uint8_t* out, const uint8_t* data, int len, uint8_t mask[4]) {
    for(int i = 0; i < len; ++i) { out[i] = data[i] ^ mask[i % 4]; }
}
template<class Cont>
void add_payload(Cont& payload, WSFrame& frame) {
    if(frame.has_mask) {
        decode((uint8_t*)&payload[frame.pos], frame.payload, frame.len, frame.mask);
    } else {
        payload.insert(payload.begin() + frame.pos, frame.payload, frame.payload + frame.len);
    }
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

//bool frame_complited(WSFrame& frame) { return frame.payload_len <= frame.len + frame.pos; }
//
//int frame_ping(WSFrame& frame) { return 0; }
//int frame_pong(WSFrame& frame) { return 0; }
//
//int send_pong(WSFrame& frame) { return 0; }
//int on_binary_data(WSFrame& frame) {
//    std::vector<uint8_t> payload;
//    add_payload(payload, frame);
//    return 0;
//}
//int on_text_data(WSFrame& frame) {
//    std::string payload;
//    add_payload(payload, frame);
//    return 0;
//}
typedef int error_code;
class WSClient {
    SOCKET sock;
    sockaddr_in addr;
    bool stop;
    std::thread th;
    enum Status { Closed, Connected };

    void worker() {
        std::string header;
        if(read_from(sock, header) == -1) { return; }
        printf("Headers: %s\n", header.c_str());
        ParsHeaders(header);
        std::string resp = GenerateHandshake();
        if(send_to(sock, resp.c_str(), resp.size()) == -1) { return; }
        printf("Response: %s\n", resp.c_str());

        uint8_t buf[1440];
        WSFrame::TOpcode prev = WSFrame::Continue;
        WSFrame frame(buf, sizeof(buf));
        while(!stop) {
            if(frame.load_from(sock) == -1) {
                on_error(sock);
                return;
            }
            prev = OnNewFrame(frame, prev);
        }
    }

protected:
    error_code ec;
    std::map<std::string, std::string> headers;
    std::string text;
    std::vector<uint8_t> binary;

public:
    WSClient(SOCKET sock, sockaddr_in addr)
        : sock(sock), addr(addr), stop(false), ec(0), th(&WSClient::worker, this) {
        printf("Connected: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    }

    virtual std::string GenerateHandshake() {
        std::string Key = headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        uint8_t hash[20] = {0};
        my::SHA1::make(Key, hash);
        Key = my::to_base64(hash);
        // clang-format off
        std::string handshake = 
            headers["HTTP"] + " 101 Web Socket Protocol Handshake\r\n"
            "Upgrade: WebSocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " + Key + "\r\n"
            //"Sec-WebSocket-Protocol: chat\r\n"
            "WebSocket-Origin: http://" + headers["Host"] + "\r\n"
            "WebSocket-Location: ws://" + headers["Host"] + headers["GET"] + "\r\n\r\n";
        // clang-format on
        return handshake;
    }
    virtual void Disconnect() {}
    virtual void ParsHeaders(const std::string& header) {
        size_t l_start = 0;
        auto l_end = header.find("\r\n");
        if(l_end == std::string::npos) return;
        const std::regex re("GET (.*) (.*)");
        std::match_results<std::string::const_iterator> match;
        if(std::regex_search(header.begin() + l_start, header.begin() + l_end, match, re)) {
            headers["GET"] = match[1];
            headers["HTTP"] = match[2];
            l_start = l_end + 2;
            l_end = header.find("\r\n", l_start);
        }
        const std::regex kv("(.*): (.*)");
        while(std::regex_search(header.begin() + l_start, header.begin() + l_end, match, kv)) {
            headers[match[1]] = match[2];
            l_start = l_end + 2;
            l_end = header.find("\r\n", l_start);
        }
    }
    virtual void Pong(WSFrame& frame) {
        frame.opcode = WSFrame::Pong;
        frame.send_to(sock);
    }
    virtual void OnDiconect() {}
    virtual void OnText(std::string& payload) {
        print_text(payload);
        payload.clear();
    }
    virtual void OnBinary(std::vector<uint8_t>& payload) {
        print_bin(payload);
        payload.clear();
    }
    virtual void OnPing(WSFrame& frame) { Pong(frame); }
    virtual void OnError(error_code ec) {}
    virtual WSFrame::TOpcode OnNewFrame(WSFrame& frame, WSFrame::TOpcode prev) {
        while(frame.has_frame()) {
            frame.next();
            frame.decode();
            prev = WSFrame::TOpcode(frame.opcode ? frame.opcode : prev);
            switch(prev) {
            case WSFrame::Text:
                text.append((const char*)frame.payload, frame.len);
                if(text.size() >= frame.payload_len && frame.fin) OnText(text);
                break;
            case WSFrame::Binary:
                std::copy(frame.payload, frame.payload + frame.len, std::back_inserter(binary));
                if(binary.size() >= frame.payload_len && frame.fin) OnBinary(binary);
                break;
            case WSFrame::Ping:
                OnPing(frame);
                break;
            default:
                break;
            }
        }
        return prev;
    }
    virtual ~WSClient() {
        closesocket(sock);
        stop = true;
        th.join();
    }
};
//void on_connect(SOCKET sock, sockaddr_in addr) {
//    printf("Connected: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
//
//    std::map<std::string, std::string> headers;
//    std::string header;
//    if(read_from(sock, header) == -1) { return; }
//    printf("Headers: %s\n", header.c_str());
//    parse_headers(header, headers);
//    auto resp = create_handshake(headers);
//    if(send_to(sock, resp.c_str(), resp.size()) == -1) { return; }
//    printf("Response: %s\n", resp.c_str());
//
//    uint8_t buf[1440];
//    WSFrame::TOpcode prev = WSFrame::Continue;
//    WSFrame frame(buf, 1440);
//    for(;;) {
//        if(frame.load_from(sock) == -1) {
//            on_error(sock);
//            return;
//        }
//        while(frame.has_frame()) {
//            frame.next();
//            prev = WSFrame::TOpcode(frame.opcode ? frame.opcode : prev);
//            switch(prev) {
//            case WSFrame::Text:
//                on_text_data(frame);
//                break;
//            case WSFrame::Binary:
//                on_binary_data(frame);
//                break;
//            case WSFrame::Ping:
//                frame_ping(frame);
//                break;
//            default:
//                break;
//            }
//        }
//    }
//    // payload_final();
//    /*n = send_to(sock, (char*)buf, n);
//    if(n == -1) {
//        on_error(sock);
//        return;
//    }*/
//}
class WSServer {
    sockaddr_in addr;
    std::list<std::unique_ptr<WSClient>> connections;
public:
    WSServer(uint16_t port, const char* ip=nullptr) {
        addr.sin_addr.s_addr = ip? inet_addr(ip) : INADDR_ANY;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
    }
    int Run() {
        SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
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
                return -1;
            }
            connections.push_back(std::make_unique<WSClient>(sock, client));
        }
        return 0;
    }
};
int main() {
    InitializeSockets();
    assert(test_Accept());
    WSServer server(4444);
    server.Run();
    WSACleanup();
    return 0;
}
//int main(void) {
//    InitializeSockets();
//    assert(test_Accept());
//    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
//
//    sockaddr_in addr;
//    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
//    addr.sin_family = AF_INET;
//    addr.sin_port = htons(4444);
//
//    if(bind(server, (sockaddr*)&addr, sizeof(sockaddr)) != 0) {
//        printf("bind error: %d\n", WSAGetLastError());
//        return 1;
//    }
//    if(listen(server, 10) != 0) {
//        printf("listen error: %d\n", WSAGetLastError());
//        return 1;
//    }
//    sockaddr_in client;
//    int len = sizeof(client);
//    while(SOCKET sock = accept(server, (sockaddr*)&client, &len)) {
//        if(sock == INVALID_SOCKET) {
//            printf("server acccept failed: %d\n", WSAGetLastError());
//            closesocket(server);
//            return 1;
//        }
//        std::thread th(&on_connect, sock, client);
//        th.detach();
//    }
//    WSACleanup();
//    return 0;
//}
