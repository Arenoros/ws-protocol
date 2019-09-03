#pragma once
#include <thread>
#include <string>
#include <map>
#include <vector>

#include "platform_conf.h"
#include "ws_frame.h"
#include "tcp_socket.h"

#define MAX_TRANSFER_UNIT 1440

namespace mplc {
    struct BaseConnection {
        static const size_t MTU = MAX_TRANSFER_UNIT;
        virtual void Disconnect() = 0;
        virtual int Read() = 0;
        virtual int Write() = 0;
    };

    class WSConnect : BaseConnection {
        friend class WSServer;
        WSFrame::TOpcode prev = WSFrame::Continue;
        TcpSocket& sock;
        sockaddr_in addr;
        bool stop;
        std::thread th;
        std::string handshake;
        enum Status { Closed, Connected, Handshake, Established };
        Status state;
        void worker();
       
        std::vector<uint8_t> out_buf;
        std::vector<uint8_t> in_buf;
    protected:
        
        error_code ec;
        std::map<std::string, std::string> headers;
        std::string text;
        std::vector<uint8_t> binary;
        void OnHttpHeader(char* data, int size);
        error_code ReadHttpHeader(std::string& http);
        
    public:
        WSConnect(TcpSocket& sock, sockaddr_in addr);
        int Read() override;
        int Write() override;
        void Disconnect() override;
        virtual void GenerateHandshake();
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
