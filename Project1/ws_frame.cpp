#include <cstdio>
#include <algorithm>

#include "ws_frame.h"
#include "tcp_socket.h"

namespace mplc {

    WSFrame::WSFrame(uint8_t* buf, int size)
        : _mask(0), head_len(0), payload_len(0), len(0), pos(0), payload(nullptr), _buf(buf),
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
    int WSFrame::load_from(const TcpSocket& sock) {
        _buf_pos = 0;
        return _recv_size = sock.Recv(_buf, _buf_size);
    }
    int WSFrame::map_on(uint8_t* buf, int size) {
        _buf_pos = 0;
        _recv_size = size;
        _buf = buf;
        return _recv_size;
    }

    int WSFrame::send_to(TcpSocket& sock) const {
        uint8_t meta_buf[2 + sizeof(payload_len) + sizeof(mask)];
        uint8_t* meta = meta_buf;
        uint8_t meta_len = 2;
        int data_pos = _buf_pos - len;
        const uint8_t* data = _buf ? _buf + data_pos : payload;
        int size = _buf? len : payload_len;
        if(payload_len > UINT16_MAX) {
            meta_len += sizeof(uint64_t);
        } else if(payload_len > 125) {
            meta_len += sizeof(uint16_t);
        }
        if(has_mask) meta_len += 4;
        if(data_pos > meta_len) {
            data_pos -= meta_len;
            data = meta = _buf + data_pos;
        }
        meta[0] |= fin << 7;
        meta[0] |= rsv << 4;
        meta[0] |= opcode;
        meta[1] |= has_mask << 7;

        if(payload_len < 126) {
            meta[1] |= payload_len;
        } else if(payload_len < UINT16_MAX) {
            *(uint16_t*)meta[2] = ntohs(payload_len);
        } else {
            *(uint64_t*)meta[2] = ntohll(payload_len);
        }
        if(has_mask) { *(uint32_t*)meta[meta_len - 4] = _mask; }

        if(data == meta) { return sock.PushData(data, size + meta_len); }
        if(sock.PushData(meta, meta_len) == -1 || sock.PushData(data, size) == -1) return -1;
        return size;
    }
    bool WSFrame::has_frame() const { return _recv_size > _buf_pos; }

    int WSFrame::load(int size) {
        _buf_pos = 0;
        _recv_size = size;
        if(pos != payload_len) {
            payload = _buf;
            len = std::min(payload_len - pos, (uint64_t)size);
            pos += len;
            _buf_pos += len;
            return size - len;
        } 
        return size;
    }

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
        printf("Client: fin=%d, opcode=%d, mask=%d, len=%d\n",
               fin,
               opcode,
               has_mask,
               (int)payload_len);
        if(has_mask) {
            _mask = *(uint32_t*)(cur_buf + head_len);
            head_len += sizeof(uint32_t);
        }
        payload = cur_buf + head_len;
        _buf_pos += head_len;
        len = std::min<uint64_t>(payload_len, _recv_size - _buf_pos);
        _buf_pos += len;
        pos += len;
    }
}  // namespace mplc
