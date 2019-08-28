#pragma once
#include <thread>
#include <string>
#include <map>
#include <vector>

#include "platform_conf.h"
#include "ws_frame.h"
#include "tcp_socket.h"

namespace mplc {

    class WSConnect {
        TcpSocket sock;
        sockaddr_in addr;
        bool stop;
        std::thread th;
        enum Status { Closed, Connected };

        void worker();

    protected:
        error_code ec;
        std::map<std::string, std::string> headers;
        std::string text;
        std::vector<uint8_t> binary;
        error_code ReadHttpHeader(std::string& http);

    public:
        WSConnect(TcpSocket sock, sockaddr_in addr);

        virtual std::string GenerateHandshake();
        virtual void Disconnect();
        virtual void ParsHeaders(const std::string& header);
        virtual void Pong(WSFrame& frame);
        virtual void OnDiconect();
        virtual void OnText(std::string& payload);
        virtual void OnBinary(std::vector<uint8_t>& payload);
        virtual void OnPing(WSFrame& frame);
        virtual void OnError(error_code ec);
        virtual WSFrame::TOpcode OnNewFrame(WSFrame& frame, WSFrame::TOpcode prev);
        virtual ~WSConnect();
    };
}  // namespace mplc
