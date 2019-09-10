#pragma once
#include <regex>
#include "ws_connect.h"
#include "sha1.h"

namespace mplc {

    WSConnect::WSConnect(TcpSocket& sock, sockaddr_in addr)
        : prev(WSFrame::Continue), sock(sock), state(Handshake), frame(buf, RECV_LIMIT), addr(addr), ec(0) {}

    std::string WSConnect::BaseHandshake() {
        std::string Key = headers["Sec-WebSocket-Key"]+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        uint8_t hash[20] = {0};
        SHA1::make(Key, hash);
        Key = to_base64(hash);
        // clang-format off
        std::string handshake =
            headers["HTTP"]+" 101 Web Socket Protocol Handshake\r\n"
            "Upgrade: WebSocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: "+Key+"\r\n"
            "WebSocket-Origin: http://"+headers["Host"]+"\r\n"
            "WebSocket-Location: ws://"+headers["Host"]+headers["GET"]+"\r\n";
        // clang-format on
        return handshake;
    }

    void WSConnect::SendHandshake() {
        std::string handshake = BaseHandshake() + "\r\n";
        sock.PushData(handshake.begin(), handshake.end());
    }

    void WSConnect::Disconnect() {
        sock.Close();
        state = Closed;
    }

    int WSConnect::Read() {
        int n = sock.Recv(buf, sizeof(buf));
        if(n == -1) {
            OnError(sock.GetError());
            return n;
        }
        switch(state) {
        case Handshake:
            OnHttpHeader((char*)buf, n);
            break;
        case Connected: {
            // If 'load' return less then n then buffer contains part of prev frame
            if(frame.load(n) < n) NewPayloadPart();
            // if in buff has more frames read it's all
            if(frame.has_frame()) NewFrame();
        } break;
        case Closed:
            return -1;
        }
        return n;
    }

    void WSConnect::OnHttpHeader(char* data, int size) {
        handshake.append(data, size);
        size_t pos = (size_t)size + 3 > handshake.size() ? 0 : handshake.size() - size - 3;
        if((pos = handshake.find("\r\n\r\n", pos)) != std::string::npos) {
            handshake.resize(pos + 2);
            ParsHeaders(handshake);
            SendHandshake();
            handshake.clear();
            state = Connected;
        } else if(handshake.size() > 4 * TcpSocket::MTU) { // Handshake limit
            sock.Close();
        }
    }

    void WSConnect::ParsHeaders(const std::string& header) {
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
        while(l_end != std::string::npos &&
              std::regex_search(header.begin() + l_start, header.begin() + l_end, match, kv)) {
            headers[match[1]] = match[2];
            l_start = l_end + 2;
            l_end = header.find("\r\n", l_start);
        }
    }
    void WSConnect::OnPing(WSFrame& frame) { SendPong(frame); }
    void WSConnect::SendPong(WSFrame& frame) {
        frame.opcode = WSFrame::Pong;
        frame.send_to(sock);
    }
    void WSConnect::OnPong(WSFrame& ) {
        // client response on ping, update timer
    }

    void WSConnect::OnDisconnect() { printf("OnDiconect: %d\n", ec); }
    void WSConnect::OnText(const char* payload, int size, bool fin) { print_text(payload); }
    void WSConnect::OnBinary(const uint8_t* payload, int size, bool fin) {
        print_bin(payload, size);
    }

    void WSConnect::OnError(error_code ec) { printf("OnError: %d\n", ec); }
    void WSConnect::SendBinary(const uint8_t* payload, int size, bool fin) const {
        WSFrame frame;
        frame.fin = fin;
        frame.payload_len = size;
        frame.payload = payload;
        frame.opcode = WSFrame::Binary;
        frame.send_to(sock);
    }
    void WSConnect::SendText(const std::string& data, bool fin) const {
        WSFrame frame;
        frame.fin = fin;
        frame.payload_len = data.size();
        frame.payload = (const uint8_t*)data.c_str();
        frame.opcode = WSFrame::Text;
        frame.send_to(sock);
    }
    void WSConnect::SendPing() const {
        WSFrame frame;
        frame.fin = true;
        frame.opcode = WSFrame::Ping;
        frame.send_to(sock);
    }
    void WSConnect::NewPayloadPart() {
        frame.decode();
        switch(prev) {
        case WSFrame::Text:
            OnText((const char*)frame.payload, frame.len, frame.fin);
            break;
        case WSFrame::Binary:
            OnBinary(frame.payload, frame.len, frame.fin);
            break;
        case WSFrame::Close:
            OnClose(frame);
            break;
        case WSFrame::Ping:
            OnPing(frame);
            break;
        case WSFrame::Pong:
            OnPong(frame);
            break;
        default:
            break;
        }
    }
    void WSConnect::OnClose(WSFrame& frame) { SendClose(frame); }
    void WSConnect::SendClose(WSFrame& frame) {
        frame.send_to(sock);
        state = Closed;
    }

    void WSConnect::NewFrame() {
        while(frame.has_frame()) {
            frame.next();
            prev = WSFrame::TOpcode(frame.opcode ? frame.opcode : prev);
            NewPayloadPart();
        }
    }
    WSConnect::~WSConnect() {}
}  // namespace mplc
