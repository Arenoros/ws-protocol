#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <stddef.h>
#include <vector>
#include <thread>
#include <map>
#include <regex>

#include "platform_conf.h"

#include <cassert>
#include "sha1.h"
#include "ws_server.h"

bool test_Accept() {
    std::string Key = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t data[20];
    my::SHA1::make(Key, data);
    Key = my::to_base64(data);
    return Key == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
}

void on_error(SOCKET sock) {
    printf("Error: %d\n", WSAGetLastError());
    closesocket(sock);
}

const char bin[] =
    "53616c7465645f5f4ce9a23dc07d9ea86f84720c7fb2f580b56390cfd3156eac"
    "8db1ba7337b5e064e65f5a3d00493edb247dcdfe7f02602bb0a6470782ec5a15"
    "b00be30790c4b3df84307829c35733aba8ec60871719956ab102af5e31cfff4a"
    "2c91ec5565538e6d2583d4678a631ec6d7f06ec26354bb89deee665bf82c92be"
    "935aa96fa3e6252a230830993a397619603f115773b7d4d64abb998e51ff448b"
    "f3b7b090b1e2a6192e705c11524fa9da3cc8869cc3a7d2fbc7befec7abac9d6b"
    "d71f8ff9a017cd5ae5c076c85c22ae01521b18c29836230aa5ea9d2159a8d9de"
    "0965a7ca072e23d527bc91a1279f25cb7b4454f77cb5fe5770aab8509644d872"
    "766fa499f7151fe4fd0044ae3140c8fd3db7afdb845571afcf0e4545012e6e7a"
    "6f698f2ef6339ac47c9ce0c80fef872255ff9fd86bdaeb011fbb472bb0049517"
    "2df45c7a2658f8a07be466eef93c488b9dade70e271c156cb2484690e6a5ffb7"
    "183e2c8cbad3904d1adcf41249e4d4afd7f96ac1bec0b66ba7301bebec41c5f8"
    "04e3b55a943a0c9239d36aac9b07006513da5c3c1d8c671dda78e87813794a2f"
    "f06d9f52c537a84e0ef46c5b40360c65db8aa633cc0a4617118fd769f47c638a"
    "f9854db81be7fd102cbd48d39f3cf57d80fce31a53d4bc2e1141eaf6a9f22390"
    "beb74ea52e64ad4914a882efa7365db8d59ade70e4319f07385d089aebb71096"
    "dbe481a7ccb49f6dc321a01ff834edcfcebf4fa27db445b951b06c7b2a0e6614";

int main() {
    const uint8_t* c = (uint8_t*)bin;
    uint8_t data[sizeof(bin) / 2] = {0};
    uint8_t* pos = data;
    while(*(c) && *(c + 1)) {
        char diff = *c > '9'? 'a'-10 : '0';
        uint8_t u8 = (*c - diff);
        *pos = u8 << 4;
        ++c;
        diff = *c > '9' ? 'a' - 10 : '0';
        *pos |= *c - diff;
        ++pos;
        ++c;
    }
    FILE* f = fopen("secret.dat", "w");
    fwrite(data, sizeof(uint8_t), sizeof(data), f);
    fclose(f);
    InitializeSockets();
    assert(test_Accept()); 
    WSServer server(4444);
    server.Run();
    WSACleanup();
    return 0;
}
