#pragma once
#include <list>
#include <memory>

#include "platform_conf.h"
#include "ws_connect.h"
#include "tcp_socket.h"

namespace mplc {
    // template<class TCon>
    struct ConnetctionsPool {
        typedef TcpSocket SockType;
        typedef std::list<SockType*> ConLst;
        typedef typename std::list<SockType*>::iterator con_iterator;
        static const size_t MAX_CONNECTIONS = FD_SETSIZE;
        static void AddToSet(const SockType& sock, fd_set& set) { FD_SET(sock.raw(), &set); }
        static void RemFromSet(const SockType& sock, fd_set& set) { FD_CLR(sock.raw(), &set); }
        static bool isContains(const SockType& sock, const fd_set& set) {
            return FD_ISSET(sock.raw(), &set);
        }
        ConnetctionsPool(): stop(false), th(&ConnetctionsPool::worker, this) {
            FD_ZERO(&read_set);
            max = INVALID_SOCKET;
            ec = 0;
        }
        virtual ~ConnetctionsPool() {
            stop = true;
            FD_ZERO(&read_set);
            th.join();
            for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                (*it)->Close();
                delete *it;
            }
            connections.clear();
        }
        void DeleteConnection(con_iterator& it) {
            if(it == connections.end()) return;
            if((*it)->raw() == max) { max = INVALID_SOCKET; }
            RemFromSet(**it, read_set);
            (*it)->Close();
            delete *it;
            connections.erase(it++);
        }
        SockType& Add(SOCKET ns) {
            std::lock_guard<std::mutex> lock(con_mtx);
            AddToSet(ns, read_set);
            connections.push_back(new SockType(ns));
            if(max < ns) max = ns;
            return *connections.back();
        }
        size_t size() {
            std::lock_guard<std::mutex> lock(con_mtx);
            return connections.size();
        }
        void SendAll(const uint8_t* data, int size) {
            std::lock_guard<std::mutex> lock(con_mtx);
            public_data.insert(public_data.end(), data, data + size);
        }
        SOCKET GetMax() {
            if(max != INVALID_SOCKET) return max;
            max = 0;
            std::lock_guard<std::mutex> lock(con_mtx);
            for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                const SockType& sock = **it;
                if(sock.raw() > max) max = sock.raw();
            }
        }
        virtual void ReadSockets(const fd_set& rdst) {
            std::lock_guard<std::mutex> lock(con_mtx);
            for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                SockType& sock = **it;
                if(isContains(sock, rdst) && sock.OnRead() == -1) { DeleteConnection(it); }
            }
        }
        virtual void WriteSockets(const fd_set& wrst) {
            std::lock_guard<std::mutex> lock(con_mtx);
            for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                SockType& sock = **it;
                if(isContains(sock, wrst)) {
                    if(sock.hasData() && sock.SendData() == -1) {
                        DeleteConnection(it);
                        continue;
                    }
                    if(!public_data.empty() &&
                       sock.Send(&public_data[0], public_data.size()) == -1) {
                        DeleteConnection(it);
                    }
                }
            }
            public_data.clear();
        }

    protected:
        SOCKET max;
        fd_set read_set;
        ConLst connections;
        bool stop;
        error_code ec;
        std::thread th;
        std::mutex con_mtx;
        std::vector<uint8_t> public_data;
        void worker() {
            while(!stop) {
                struct timeval tv;
                // Ждем событий 1 сек
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                fd_set rdst, wrst;
                std::memcpy(&rdst, &read_set, sizeof fd_set);
                FD_ZERO(&wrst);
                for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                    SockType& sock = **it;
                    if(sock.hasData() || !public_data.empty()) { AddToSet(sock, wrst); }
                }
                SOCKET rv = select(GetMax() + 1, &rdst, &wrst, nullptr, &tv);
                if(rv == 0) continue;
                if(!IsValidSock(rv)) {
                    ec = GetLastSockError();
                    return;
                }
                ReadSockets(rdst);
                WriteSockets(wrst);
            }
        }
    };

    class TcpServer {
        typedef TcpSocket SockType;
       /* typedef std::list<SockType*> ConLst;
        typedef typename std::list<SockType*>::iterator con_iterator;*/
        ConnetctionsPool pool;

    public:
        enum StatusType { NO_INIT, ERR, WAIT, LISTEN };
        StatusType Status() const { return status; }
        void Disconnect() {
            stop = true;
            status = NO_INIT;
            sock.Close();
            /*for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                (*it)->Close();
                delete *it;
            }
            connections.clear();*/
            FD_ZERO(&read_set);
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
                //std::memcpy(&rdst, &read_set, sizeof fd_set);
                ConnetctionsPool::AddToSet(sock, rdst);
                /*for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                    SockType& sock = **it;
                    if(sock.hasData()) { AddToSet(sock, wrst); }
                }*/
                SOCKET rv = select(sock.raw() + 1, &rdst, nullptr, nullptr, &tv);
                if(rv == 0) continue;
                if(!IsValidSock(rv)) {
                    ec = GetLastSockError();
                    Disconnect();
                    return ec;
                }
                if(isContains(sock, rdst)) Accept();
                /*ReadSockets(rdst);
                WriteSockets(wrst);*/
            }
            return 0;
        }
        /*virtual void ReadSockets(const fd_set& rdst) {
            for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                SockType& sock = **it;
                if(isContains(sock, rdst) && sock.OnRead() == -1) { DeleteConnection(it); }
            }
        }
        virtual void WriteSockets(const fd_set& wrst) {
            for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                SockType& sock = **it;
                if(isContains(sock, wrst) && sock.SendData() == -1) { DeleteConnection(it); }
            }
        }*/
        TcpServer() { Disconnect(); }
        TcpServer(uint16_t port, const char* intface = nullptr): status(NO_INIT) {
            Disconnect();
            Bind(port, intface);
        }
        ~TcpServer() { Disconnect(); }
        /*template<class TCon>*/
        virtual void OnConnected(SockType& connect, sockaddr_in nsi) = 0; /*{
            connect.con = new BaseConnection(connect, nsi);
        }*/

    private:
        /*static void AddToSet(const SockType& sock, fd_set& set) { FD_SET(sock.raw(), &set); }
        static void RemFromSet(const SockType& sock, fd_set& set) { FD_CLR(sock.raw(), &set); }*/
        static bool isContains(const SockType& sock, const fd_set& set) {
            return FD_ISSET(sock.raw(), &set);
        }
        void Accept() {
            struct sockaddr_in nsi;
            int nsi_sz = sizeof(nsi);
            SOCKET ns = accept(sock.raw(), (struct sockaddr*)(&nsi), &nsi_sz);
            if(ns != 0 && IsValidSock(ns) && GetLastSockError() != EAGAIN) {
                //AddToSet(ns, read_set);
                if(max < ns) max = ns;
                OnConnected(pool.Add(ns), nsi);
            }
        }

        /*SOCKET GetMax() {
            if(max != INVALID_SOCKET) return max;
            max = sock.raw();
            for(con_iterator it = connections.begin(); it != connections.end(); ++it) {
                const SockType& sock = **it;
                if(sock.raw() > max) max = sock.raw();
            }
        }
        void DeleteConnection(con_iterator& it) {
            if(it == connections.end()) return;
            if((*it)->raw() == max) { max = INVALID_SOCKET; }
            RemFromSet(**it, read_set);
            (*it)->Close();
            delete *it;
            connections.erase(it++);
        }*/

        SockType sock;  // Серверный сокет
        SOCKET max;
        // struct sockaddr_in si;
        // Структура состояния соединения
        //ConLst connections;
        bool stop;
        error_code ec;
        // tthread::thread listner;
        // tthread::mutex mtx;
        StatusType status;
        //fd_set read_set;
    };

    class WSServer : public TcpServer {
        /*sockaddr_in addr;
        std::list<std::unique_ptr<WSConnect>> connections;*/

    public:
        void OnConnected(TcpSocket& connect, sockaddr_in nsi) override;
        WSServer(uint16_t port, const char* ip = nullptr);
        // int Run();
    };
}  // namespace mplc
