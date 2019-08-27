#pragma once
#include <regex>

#include "ws_client.h"
#include "sha1.h"

void WSClient::worker() {
    std::string header;
    if(read_from(sock, header) == -1) { return OnError(GetSockError()); }
    printf("Headers: %s\n", header.c_str());
    ParsHeaders(header);
    std::string resp = GenerateHandshake();
    if(send_to(sock, resp.c_str(), resp.size()) == -1) { return OnError(GetSockError()); }
    printf("Response: %s\n", resp.c_str());

    uint8_t buf[1440];
    WSFrame::TOpcode prev = WSFrame::Continue;
    WSFrame frame(buf, sizeof(buf));
    while(!stop) {
        if(frame.load_from(sock) == -1) {
            OnError(GetSockError());
            return;
        }
        prev = OnNewFrame(frame, prev);
    }
}

WSClient::WSClient(SOCKET sock, sockaddr_in addr)
    : sock(sock), addr(addr), stop(false), th(&WSClient::worker, this), ec(0) {
    printf("Connected: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
}

std::string WSClient::GenerateHandshake() {
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
            "WebSocket-Origin: http://" + headers["Host"] + "\r\n"
            "WebSocket-Location: ws://" + headers["Host"] + headers["GET"] + "\r\n\r\n";
    // clang-format on
    return handshake;
}

void WSClient::Disconnect() {}

void WSClient::ParsHeaders(const std::string& header) {
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
void WSClient::OnPing(WSFrame& frame) { Pong(frame); }
void WSClient::Pong(WSFrame& frame) {
    frame.opcode = WSFrame::Pong;
    frame.send_to(sock);
}
void WSClient::OnDiconect() {}
void WSClient::OnText(std::string& payload) {
    print_text(payload);
    payload.clear();
}
void WSClient::OnBinary(std::vector<uint8_t>& payload) {
    print_bin(payload);
    payload.clear();
}

void WSClient::OnError(error_code ec) {}
WSFrame::TOpcode WSClient::OnNewFrame(WSFrame& frame, WSFrame::TOpcode prev) {
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
WSClient::~WSClient() {
    closesocket(sock);
    stop = true;
    th.join();
}
