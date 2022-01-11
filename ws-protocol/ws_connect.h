#pragma once
#include <string>
#include <map>
#include <vector>

#include "platform_conf.h"
#include "ws_frame.h"
#include "tcp_socket.h"

#define MPLC_WS_CONNECT_RECV_BUF_SIZE 1024*10
namespace mplc {

    class WSConnect : public BaseConnection {
        static const size_t RECV_LIMIT = MPLC_WS_CONNECT_RECV_BUF_SIZE;
        friend class WSServer;
        WSFrame::TOpcode prev;
        std::string handshake;
        enum Status { Closed, Connected, Handshake };
        Status state;
        uint8_t buf[RECV_LIMIT];
        WSFrame frame;
        virtual void NewFrame();
        virtual void NewPayloadPart();

    protected:
        TcpSocket& sock;
        struct sockaddr_in addr;
        error_code ec;
        std::map<std::string, std::string> headers;
        std::string text;
        std::vector<uint8_t> binary;
        void OnHttpHeader(char* data, int size);
        std::string BaseHandshake();
        // error_code ReadHttpHeader(std::string& http);

    public:
        //const TcpSocket& Socket() const override { return sock; }
        WSConnect(TcpSocket& sock, sockaddr_in addr);
        virtual ~WSConnect();

        virtual int Read() override;
        virtual void OnDisconnect() override;

        virtual void ParsHeaders(const std::string& header);
        virtual void OnText(const char* payload, int size, bool fin);
        virtual void OnBinary(const uint8_t* payload, int size, bool fin);
        virtual void OnPing(WSFrame& frame);
        virtual void OnPong(WSFrame& frame);
        virtual void OnClose(WSFrame& frame);
        virtual void OnError(error_code ec);

        virtual void SendHandshake();
        virtual void Disconnect();
        virtual void SendText(const std::string& data, bool fin = true) const;
        virtual void SendBinary(const uint8_t* payload, int size, bool fin = true) const;
        virtual void SendPing() const;
        virtual void SendPong(WSFrame& frame);
        virtual void SendClose(WSFrame& frame);

    };

    class WSStream {};
}  // namespace mplc
