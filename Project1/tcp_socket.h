#pragma once
#include "platform_conf.h"
#include <cstdint>
#include <thread>
#include <mutex>

#define MAX_TRANSFER_UNIT 1440

namespace mplc {
    struct BaseConnection {
        static const size_t MTU = MAX_TRANSFER_UNIT;
        virtual void Disconnect() = 0;
        virtual int Read() = 0;
        //virtual int Write() = 0;
        virtual const TcpSocket& Socket() const = 0;
    };

    class TcpSocket {
    protected:
        SOCKET sock_fd;
        error_code ec;
        void SetError() { ec = GetSockError(sock_fd); }
        std::vector<uint8_t> buf;
        std::mutex buf_mtx;
        BaseConnection* con;
    public:
        template<class It>
        void PushData(const It& begin, const It& end) {
            std::lock_guard<std::mutex> lock(buf_mtx);
            buf.insert(buf.end(), begin, end);
        }
        int PushData(const uint8_t* data, int size) {
            if(size == 0) return 0;
            std::lock_guard<std::mutex> lock(buf_mtx);
            buf.insert(buf.end(), data, data + size);
            return size;
        }
        int SendData() {
            std::lock_guard<std::mutex> lock(buf_mtx);
            int rc = Send(&buf[0], buf.size());
            buf.clear();
            return rc;
        }
        int OnRead() {
            if(con) return con->Read();
            else return -1;
        }
        template<class TCon>
        void SetConnection(sockaddr_in nsi) {
            con = (BaseConnection*)new TCon(*this, nsi);
        }
        bool hasData() const { return !buf.empty(); }
        SOCKET raw() const { return sock_fd; }
        TcpSocket() { SetSockDiecriptor(0); }
        TcpSocket(SOCKET s) { SetSockDiecriptor(s); }

        TcpSocket& operator=(SOCKET s) {
            SetSockDiecriptor(s);
            return *this;
        }
        void SetSockDiecriptor(SOCKET s) {
            sock_fd = s;
            ec = 0;
        }
        error_code Open() {
            Close();
            SetSockDiecriptor(socket(AF_INET, SOCK_STREAM, 0));
            return GetSockError(sock_fd);
        }
        error_code SetOption(int opt, const char* val, int size) const {
            return setsockopt(sock_fd, SOL_SOCKET, opt, val, size);
        }

        error_code Bind(uint16_t port, const char* intface = nullptr) {
            struct sockaddr_in si;
            si.sin_port = htons(port);
            si.sin_addr.s_addr = intface ? inet_addr(intface) : INADDR_ANY;
            si.sin_family = AF_INET;
            if(bind(sock_fd, (struct sockaddr*)(&si), sizeof(si)) != 0) {
                return ec = GetLastSockError();
            }
            return 0;
        }
        error_code Connect(struct sockaddr* addr) {
            Open();
            if(connect(sock_fd, addr, sizeof(struct sockaddr)) == -1) { ec = GetLastSockError(); }
            return ec;
        }
        error_code GetError() const {
            if(isValid()) return GetSockError(sock_fd);
            return GetLastSockError();
        }
        error_code UnBlock() { return SetNoBlockSock(sock_fd); }
        bool isValid() const { return sock_fd != 0 && IsValidSock(sock_fd); }
        error_code Close() {
            ec = 0;
            if(isValid()) { ec = CloseSock(sock_fd); }
            sock_fd = 0;
            if(con) {
                con->Disconnect();
                delete con;
            }
            return ec;
        }
        // bool IsOpen() const { return IsValidSock(sock_fd) && ; }

        int Recv(void* buf, int size) const {
            char* ptr = (char*)buf;
            return recv(sock_fd, ptr, size, 0);
        }

        int TrySend(const void* resp, int len) {
            const char* ptr = (const char*)resp;
            return send(sock_fd, ptr, len, 0);
        }

        int Send(const void* resp, int len) {
            int limit = 1440;
            int n = 0;
            const char* ptr = (const char*)resp;
            while((n = send(sock_fd, ptr, std::min(limit, len), 0)) > 0) {
                ptr += n;
                len -= n;
            }
            return n > 0 ? len : n;
        }
    };

}  // namespace mplc
