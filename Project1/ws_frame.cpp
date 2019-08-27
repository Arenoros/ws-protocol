#include <cstdio>
#include <algorithm>

#include "ws_frame.h"
WSFrame::WSFrame(uint8_t* buf, int size)
    : head_len(0), payload_len(0), len(0), pos(0), payload(nullptr), _mask(0), _buf(buf),
      _buf_size(size) {
    short_len = has_mask = opcode = rsv = fin = 0;
    _recv_size = _buf_pos = 0;
}
void WSFrame::decode() {
    if(has_mask)
        for(uint64_t j = 0, i = _buf_pos - len; i < _buf_pos; _buf[i++] ^= mask[j++ % 4]) {}
}
void WSFrame::encode() {
    if(has_mask)
        for(int i = 0; i < len; ++i) { _buf[_buf_pos - len] ^= mask[i % 4]; }
}
int WSFrame::load_from(SOCKET sock) {
    _buf_pos = 0;
    return _recv_size = recv(sock, (char*)_buf, _buf_size, 0);
}

int WSFrame::send_to(SOCKET sock) {
    uint8_t meta[2 + sizeof(payload_len) + sizeof(mask)];

    uint8_t meta_len = 2;
    meta[0] |= fin << 7;
    meta[0] |= rsv << 4;
    meta[0] |= opcode;
    meta[1] |= has_mask << 7;
    if(payload_len < 126) {
        meta[1] |= payload_len;
    } else if(payload_len < UINT16_MAX) {
        *(uint16_t*)meta[2] = ntohs(payload_len);
        meta_len += sizeof(uint16_t);
    } else {
        *(uint64_t*)meta[2] = ntohll(payload_len);
        meta_len += sizeof(uint64_t);
    }
    if(has_mask) {
        *(uint32_t*)meta[meta_len] = _mask;
        meta_len += 4;
    }
    uint8_t* frame = (uint8_t*)payload;
    if(_buf_pos - len > meta_len) {
        frame = _buf + _buf_pos - len - meta_len;
        memcpy(_buf + _buf_pos - len - meta_len, meta, meta_len);
    } else if(::send_to(sock, (const char*)meta, meta_len) == -1)
        return -1;
    return ::send_to(sock, (const char*)frame, len);
}
bool WSFrame::has_frame() const { return _recv_size > _buf_pos; }

void WSFrame::next() {
    uint8_t* cur_buf = _buf + _buf_pos;
    fin = cur_buf[0] >> 7;
    has_mask = cur_buf[1] >> 7;
    rsv = cur_buf[0] >> 4 & 0x7;
    opcode = cur_buf[0] & 0xF;
    short_len = cur_buf[1] & 0x7F;

    head_len = 2;
    if(short_len < 126) { payload_len = short_len; }
    if(short_len == 126) {
        payload_len = ntohs(*(uint16_t*)(cur_buf + head_len));
        head_len += sizeof(uint16_t);
    } else if(short_len == 127) {
        payload_len = ntohll(*(uint64_t*)(cur_buf + head_len));
        head_len += sizeof(uint64_t);
    }
    printf("Client: fin=%d, opcode=%d, mask=%d, len=%d\n", fin, opcode, has_mask, (int)payload_len);
    if(has_mask) {
        _mask = *(uint32_t*)(cur_buf + head_len);
        head_len += sizeof(uint32_t);
    }
    payload = cur_buf + head_len;
    _buf_pos += head_len;
    len = std::min<uint64_t>(payload_len, _recv_size - _buf_pos);
    _buf_pos += len;
}
