#pragma once
#include <list>
#include <memory>

#include "platform_conf.h"
#include "ws_connect.h"
#include "tcp_socket.h"

namespace mplc {
    template<class TCon>
    class Server {
        typedef TcpSocket SockType;
        typedef std::list<TCon*> ConLst;
        typedef typename std::list<TCon*>::const_iterator con_iterator;

    public:
        enum StatusType { NO_INIT, ERR, WAIT, LISTEN };
        StatusType Status() const { return status; }
        void Disconnect() {
            stop = true;
            status = NO_INIT;
            sock.Close();
            for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                delete *it;
            }
            connections.clear();
            FD_ZERO(&read_set);
            FD_ZERO(&write_set);
        }
        int Bind(uint16_t port, const char* intface = nullptr) {
            max = INVALID_SOCKET;
            sock.Open();
            int val = 1;
            sock.SetOption(SO_REUSEADDR, (char*)&val, sizeof(int));
            if(sock.Bind(port, intface) != 0) {
                ec = GetLastSockError();
                return ec;
            }
            max = sock.raw();
            AddToSet(sock, read_set);
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
                // Ждем событий 1 сек
                tv.tv_sec = 0;
                tv.tv_usec = 1000;
                fd_set rdst, wrst;
                std::memcpy(&read_set, &rdst, sizeof fd_set);
                std::memcpy(&write_set, &wrst, sizeof fd_set);
                SOCKET rv = select(GetMax() + 1, &rdst, &wrst, nullptr, &tv);
                if(rv == 0) continue;
                if(!IsValidSock(rv)) {
                    ec = GetLastSockError();
                    Disconnect();
                    return ec;
                }
                if(isContains(sock, rdst)) Accept();
                for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                    TCon& con = **it;
                    if(isContains(con, rdst) && con.Read() == -1) { DeleteConnection(it); }
                    if(isContains(con, wrst) && con.Write() == -1) { DeleteConnection(it); }
                }
            }
            return 0;
        }
        Server() { Disconnect(); }
        Server(uint16_t port, const char* intface = nullptr): status(NO_INIT) {
            Disconnect();
            Bind(port, intface);
        }

    private:
        void AddToSet(const SockType& sock, fd_set& set) { FD_SET(sock.raw(), &set); }
        void RemFromSet(const SockType& sock, fd_set& set) { FD_CLR(sock.raw(), &set); }
        bool isContains(const SockType& sock, fd_set& set) { return FD_ISSET(sock.raw(), &set); }
        void Accept() {
            struct sockaddr nsi;
            int nsi_sz = sizeof(nsi);
            SockType ns = accept(sock.raw(), (struct sockaddr*)(&nsi), &nsi_sz);
            if(ns.isValid() && GetLastSockError() != EAGAIN) {
                AddToSet(ns, read_set);
                AddToSet(ns, write_set);
                connections.push_back(new TCon(ns));
                if(max < ns.raw()) max = ns.raw();
            }
        }

        SOCKET GetMax() {
            if(max != INVALID_SOCKET) return max;
            max = sock.raw();
            for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                const SockType& sock = **it;
                if(sock.raw() > max) max = sock.raw();
            }
        }
        void DeleteConnection(con_iterator it) {
            if(it == connections.end()) return;
            if(*it == nullptr) {
                connections.erase(it);
                return;
            }
            const TcpSocket& s = **it;
            if(s.raw() == max) { max = INVALID_SOCKET; }
            RemFromSet(s, read_set);
            RemFromSet(s, write_set);
            delete *it;
            connections.erase(it);
        }

        SockType sock;  // Серверный сокет
        SOCKET max;
        // struct sockaddr_in si;
        // Структура состояния соединения
        ConLst connections;
        bool stop;
        error_code ec;
        // tthread::thread listner;
        // tthread::mutex mtx;
        StatusType status;
        fd_set read_set;
        fd_set write_set;
    };

    class WSServer {
        sockaddr_in addr;
        std::list<std::unique_ptr<WSConnect>> connections;

    public:
        WSServer(uint16_t port, const char* ip = nullptr);
        int Run();
    };
}  // namespace mplc
