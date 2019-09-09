#pragma once
#include <regex>

#include "ws_connect.h"
#include "sha1.h"
namespace mplc {

    // void WSConnect::worker() {
    //    std::string header;
    //    error_code ec = ReadHttpHeader(header);
    //    if(ec != 0) return OnError(ec);
    //    printf("Headers: %s\n", header.c_str());

    //    ParsHeaders(header);
    //    // std::string resp = GenerateHandshake();
    //    /*if(sock.Send(resp.c_str(), resp.size()) == -1) return OnError(sock.GetError());

    //    printf("Response: %s\n", resp.c_str());*/

    //    uint8_t buf[MTU];
    //    WSFrame::TOpcode prev = WSFrame::Continue;
    //    WSFrame frame(buf, sizeof(buf));
    //    while(!stop) {
    //        if(frame.load_from(sock) == -1) {
    //            OnError(sock.GetError());
    //            return;
    //        }
    //        prev = NewFrame(frame, prev);
    //    }
    //}

    WSConnect::WSConnect(TcpSocket& sock, sockaddr_in addr)
        : sock(sock), addr(addr), stop(false), /* th(&WSConnect::worker, this),*/ state(Handshake),
          ec(0), frame(buf, MTU) {}

    void WSConnect::GenerateHandshake() {
        std::string Key = headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        uint8_t hash[20] = {0};
        SHA1::make(Key, hash);
        Key = to_base64(hash);
        // clang-format off
        std::string handshake =
                headers["HTTP"] + " 101 Web Socket Protocol Handshake\r\n"
                "Upgrade: WebSocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: " + Key + "\r\n"
                "WebSocket-Origin: http://" + headers["Host"] + "\r\n"
                "WebSocket-Location: ws://" + headers["Host"] + headers["GET"] + "\r\n\r\n";
        // clang-format on
        sock.PushData(handshake.begin(), handshake.end());
    }

    void WSConnect::Disconnect() {
        OnDiconect();
        sock.Close();
        stop = true;
    }

    int WSConnect::Read() {
        int n = sock.Recv(buf, sizeof(buf));
        if(n == -1) {
            OnError(sock.GetError());
            return n;
        }
        int tmp = 0;
        switch(state) {
        case Handshake:
            OnHttpHeader((char*)buf, n);
            break;
        case Established: {
            // If 'load' return less then n then buffer contains part of prev frame
            if(frame.load(n) < n) NewPayloadPart();
            // if in buff has more frames read it's all
            if(frame.has_frame()) NewFrame();
        } break;
        case Closed:
        case Connected:
            break;
        }
        return n;
    }

    void WSConnect::OnHttpHeader(char* data, int size) {
        handshake.append(data, size);
        size_t pos = size + 3 > handshake.size() ? 0 : handshake.size() - size - 3;
        if((pos = handshake.find("\r\n\r\n", pos)) != std::string::npos) {
            handshake.resize(pos + 2);
            ParsHeaders(handshake);
            GenerateHandshake();
            handshake.resize(0);
            state = Established;
        }
        if(handshake.size() > 4 * MTU) { sock.Close(); }
    }
    error_code WSConnect::ReadHttpHeader(std::string& http) {
        char buf[MTU];
        int n = 0;
        while((n = sock.Recv(buf, sizeof(buf))) > 0) {
            size_t pos = http.size();
            http.append(buf, n);
            if(pos > 3) pos -= 4;
            if(http.find("\r\n\r\n", pos) != std::string::npos) return http.size();
        }
        if(n == -1) return sock.GetError();
        return 0;
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
    void WSConnect::OnPing(WSFrame& frame) { Pong(frame); }
    void WSConnect::Pong(WSFrame& frame) {
        frame.opcode = WSFrame::Pong;
        frame.send_to(sock);
    }
    void WSConnect::OnPong(WSFrame& frame) {
        // client response on ping, update timer
    }

    void WSConnect::OnDiconect() { printf("OnDiconect: %d\n", ec); }
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
        // frame.payload_len = data.size();
        // frame.payload =
        frame.opcode = WSFrame::Ping;
        frame.send_to(sock);
    }
    void WSConnect::NewPayloadPart() {
        frame.decode();
        switch(prev) {
        case WSFrame::Text:
            OnText((const char*)frame.payload, frame.len, frame.fin);
            /*text.append((const char*)frame.payload, frame.len);
            if(text.size() >= frame.payload_len && frame.fin) OnText(text);*/
            break;
        case WSFrame::Binary:
            OnBinary(frame.payload, frame.len, frame.fin);
            /*std::copy(frame.payload, frame.payload + frame.len, std::back_inserter(binary));
            if(binary.size() >= frame.payload_len && frame.fin) OnBinary(binary);*/
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

    void WSConnect::NewFrame() {
        while(frame.has_frame()) {
            frame.next();
            prev = WSFrame::TOpcode(frame.opcode ? frame.opcode : prev);
            NewPayloadPart();
        }
    }
    WSConnect::~WSConnect() {
        Disconnect();

        // th.join();
    }
}  // namespace mplc
