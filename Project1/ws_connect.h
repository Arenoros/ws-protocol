#pragma once
#include <thread>
#include <string>
#include <map>
#include <vector>

#include "platform_conf.h"
#include "ws_frame.h"
#include "tcp_socket.h"


namespace mplc {

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
        uint8_t buf[MTU];
        WSFrame frame;
        //std::vector<uint8_t> in_buf;
    protected:
        
        error_code ec;
        std::map<std::string, std::string> headers;
        std::string text;
        std::vector<uint8_t> binary;
        void OnHttpHeader(char* data, int size);
        error_code ReadHttpHeader(std::string& http);
        
    public:
        const TcpSocket& Socket() const override { return sock; }
        WSConnect(TcpSocket& sock, sockaddr_in addr);
        int Read() override;
        //int Write() override;
        void Disconnect() override;
        virtual void GenerateHandshake();
        virtual void ParsHeaders(const std::string& header);
        virtual void Pong(WSFrame& frame);
        virtual void OnDiconect();
        virtual void OnText(const char* payload, int size, bool fin);
        virtual void OnBinary(const uint8_t* payload, int size, bool fin);
        virtual void OnPing(WSFrame& frame);
        virtual void OnPong(WSFrame& frame);
        virtual void OnError(error_code ec);
        virtual void NewPayloadPart();
        void SendText(const std::string& data, bool fin) const;
        void SendBinary(const uint8_t* payload, int size, bool fin) const;
        void SendPing() const;
        virtual void NewFrame();
        virtual ~WSConnect();
    };

    class WSStream {
        
    };
}  // namespace mplc
