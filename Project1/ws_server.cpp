#include "ws_server.h"


WSServer::WSServer(uint16_t port, const char* ip) {
    addr.sin_addr.s_addr = ip ? inet_addr(ip) : INADDR_ANY;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
}
int WSServer::Run() {
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
