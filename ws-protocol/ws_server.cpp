#include "ws_server.h"

namespace mplc {

    WSServer::WSServer(uint16_t port, const char* ip): TcpServer(port, ip) {
    
    }
    
    void WSServer::OnConnected(TcpSocket& connect, sockaddr_in nsi) {
        connect.SetConnection(new WSConnect(connect, nsi));
        printf("Connected: %s:%d\n", inet_ntoa(nsi.sin_addr), ntohs(nsi.sin_port));
    }

}  // namespace mplc
