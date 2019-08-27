#pragma once
#include <list>
#include <memory>

#include "platform_conf.h"
#include "ws_client.h"

class WSServer {
    sockaddr_in addr;
    std::list<std::unique_ptr<WSClient>> connections;

public:
    WSServer(uint16_t port, const char* ip = nullptr);
    int Run() ;
};
