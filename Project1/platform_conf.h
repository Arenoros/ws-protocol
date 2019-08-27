#pragma once

#define PLATFORM_WINDOWS 1
#define PLATFORM_MAC 2
#define PLATFORM_UNIX 3

#if defined(_WIN32)
#    define PLATFORM PLATFORM_WINDOWS
#elif defined(__APPLE__)
#    define PLATFORM PLATFORM_MAC
#else
#    define PLATFORM PLATFORM_UNIX
#endif

#if PLATFORM == PLATFORM_WINDOWS
#    define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#    if defined(WINCE)
#        include <Winsock2.h>
#        pragma comment(lib, "ws2.lib")
#    elif _MSC_VER < 1300
#        include <winsock.h>
#        pragma comment(lib, "wsock32.lib")
#    else
#        ifdef FD_SETSIZE
#            undef FD_SETSIZE
#            define FD_SETSIZE 1024
#        endif
#        include <Winsock2.h>
#        include <ws2tcpip.h>
#        pragma comment(lib, "ws2_32.lib")
#    endif
#    define bzero(a, b) memset((a), 0x0, (b))
#elif PLATFORM == PLATFORM_MAC || PLATFORM == PLATFORM_UNIX
#    include <sys/socket.h>
#    include <netinet/in.h>
#    include <fcntl.h>
typedef int SOCKET;
#endif
typedef int error_code;

inline bool InitializeSockets() {
#if PLATFORM == PLATFORM_WINDOWS
    WSADATA WsaData;
    return WSAStartup(MAKEWORD(2, 2), &WsaData) == NO_ERROR;
#else
    return true;
#endif
}

inline void ShutdownSockets() {
#if PLATFORM == PLATFORM_WINDOWS
    WSACleanup();
#endif
}
inline error_code GetSockError() {
#if PLATFORM == PLATFORM_WINDOWS
    return WSAGetLastError();
#else
    return errno;
#endif
}

inline bool SockIsOK(SOCKET sock) { return sock != INVALID_SOCKET; }
inline int CloseSock(SOCKET sock) {
#if PLATFORM == PLATFORM_WINDOWS
    return closesocket(sock);
#else
#    if defined(LINUX)
    shutdown(sock, 2);
#    endif
    close(sock);
#endif
}
inline void SetNoBlockSock(SOCKET sock) {
#if PLATFORM != PLATFORM_WINDOWS
    int flags = fcntl(sock, F_GETFL);
    if(flags == -1) {
        PRINT2("%ld: Error open TCP socket (%d)!", RGetTime_ms(), RGetLastError());
        CR;
    }
    flags = flags | O_NONBLOCK;
    fcntl(sock, F_SETFL, flags);
#else
    u_long on_sock = 1;
    ioctlsocket(sock, FIONBIO, &on_sock);
#endif
}

typedef int error_code;
