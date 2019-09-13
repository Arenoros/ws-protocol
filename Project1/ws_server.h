#pragma once
#include "tcp_server.h"
#include "ws_connect.h"

namespace mplc {
    class WSServer : public TcpServer {
    public:
        void OnConnected(TcpSocket& connect, sockaddr_in nsi) override;
        WSServer(uint16_t port, const char* ip = nullptr);
    };

    inline std::list<std::string> messages;
    struct UserConn : WSConnect {
        UserConn(TcpSocket& sock, sockaddr_in& addr): WSConnect(sock, addr) {}
        void OnText(const char* payload, int size, bool fin) override {
            printf("new message from: %s\n", inet_ntoa(addr.sin_addr));
            print_text(payload);
            messages.push_back(payload);
            for(auto& msg: messages) { SendText(msg); }
        }
        void SendHandshake() override {
            std::string handshake = BaseHandshake()+"\r\n";
            sock.PushData(handshake.begin(), handshake.end());
        }
    };
    class Chat : public WSServer {
    public:
        void OnConnected(TcpSocket& connect, sockaddr_in nsi) override {
            printf("new user: %s\n", inet_ntoa(nsi.sin_addr));
            connect.SetConnection(new UserConn(connect,nsi));
        }
        Chat(uint16_t port, const char* ip = nullptr): WSServer(port, ip) {}
    };
}  // namespace mplc
