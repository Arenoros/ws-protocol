#pragma once
#include "platform_conf.h"
#include "connections_pool.h"

namespace mplc {
    class TcpServer {
        typedef TcpSocket SockType;
        ConnetctionsPool pool;

    public:
        enum StatusType { NO_INIT, ERR, WAIT, LISTEN };
        StatusType Status() const { return status; }
        void Disconnect() {
            stop = true;
            status = NO_INIT;
            sock.Close();
        }
        int Bind(uint16_t port, const char* intface = nullptr) {
            sock.Open();
            int val = 1;
            sock.SetOption(SO_REUSEADDR, (char*)&val, sizeof(int));
            if(sock.Bind(port, intface) != 0) {
                ec = GetLastSockError();
                return ec;
            }
            status = WAIT;
            return 0;
        }
        void Stop() { stop = true; }
        int Start() {
            if(status != WAIT) return -1;
            if(listen(sock.raw(), 10) != 0) {
                ec = GetLastSockError();
                Disconnect();
                return ec;
            }
            status = LISTEN;
            stop = false;
            while(!stop) {
                struct timeval tv;
                // Ждем подключения 1 с
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                fd_set rdst;
                ConnetctionsPool::AddToSet(sock, rdst);
                SOCKET rv = select(sock.raw() + 1, &rdst, nullptr, nullptr, &tv);
                if(rv == 0) continue;
                if(!IsValidSock(rv)) {
                    ec = GetLastSockError();
                    Disconnect();
                    return ec;
                }
                if(ConnetctionsPool::isContains(sock, rdst)) Accept();
            }
            return 0;
        }

        TcpServer() { Disconnect(); }
        TcpServer(uint16_t port, const char* intface = nullptr): status(NO_INIT) {
            Disconnect();
            Bind(port, intface);
        }
        virtual ~TcpServer() { Disconnect(); }
        virtual void OnConnected(SockType& connect, sockaddr_in nsi) = 0;

    private:
        void Accept() {
            struct sockaddr_in nsi;
            int nsi_sz = sizeof(nsi);
            SOCKET ns = accept(sock.raw(), (struct sockaddr*)(&nsi), &nsi_sz);
            if(ns != 0 && IsValidSock(ns) && GetLastSockError() != EAGAIN) {
                if(pool.size() < pool.MAX_CONNECTIONS)
                    OnConnected(pool.Add(ns), nsi);
                else
                    CloseSock(ns);
            }
        }

        SockType sock;  // Серверный сокет
        bool stop;
        error_code ec;
        StatusType status;
    };
}  // namespace mplc
