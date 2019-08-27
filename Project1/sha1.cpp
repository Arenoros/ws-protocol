/* sha1.cpp

Copyright (c) 2005 Michael D. Leonhard

http://tamale.net/

This file is licensed under the terms described in the
accompanying LICENSE file.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "sha1.h"
#include <cstdint>
namespace my {
    void to_base64(const uint8_t* data, size_t data_size, size_t b64_size, char* out) {
        static const char encoding_table[64] = {

            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };
        for (size_t i = 0, j = 0; i < data_size;) {
            uint32_t octet_a = data[i++];
            uint32_t octet_b = i < data_size ? data[i++] : 0;
            uint32_t octet_c = i < data_size ? data[i++] : 0;
            uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
            //uint32_t n_long = htonl(triple);
            out[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
            out[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
            out[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
            out[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
        }
        static const int mod_table[] = { 0, 2, 1 };
        for (int i = 0; i < mod_table[data_size % 3]; i++) out[b64_size - 1 - i] = '=';
    }
    void from_base64(const char* b64, size_t b64_size, size_t data_size, uint8_t* out) {
        static const char decoding_table[128] = {

            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62,
            64, 64, 64, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 0, 64, 64, 64, 0,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
            39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64 };

        for (unsigned int i = 0, j = 0; i < b64_size;) {
            uint32_t sextet_a = decoding_table[b64[i++]];
            uint32_t sextet_b = decoding_table[b64[i++]];
            uint32_t sextet_c = decoding_table[b64[i++]];
            uint32_t sextet_d = decoding_table[b64[i++]];

            uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) +
                (sextet_d << 0 * 6);
            if (j < data_size) out[j++] = (triple >> 2 * 8) & 0xFF;
            if (j < data_size) out[j++] = (triple >> 1 * 8) & 0xFF;
            if (j < data_size) out[j++] = (triple >> 0 * 8) & 0xFF;
        }
    }
    // print out memory in hexadecimal
    void SHA1::hexPrinter(unsigned char* c, int l)
    {
        assert(c);
        assert(l > 0);
        while (l > 0)
        {
            printf(" %02x", *c);
            l--;
            c++;
        }
    }

    // circular left bit rotation.  MSB wraps around to LSB
    Uint32 SHA1::lrot(Uint32 x, int bits)
    {
        return (x << bits) | (x >> (32 - bits));
    };

    // Save a 32-bit unsigned integer to memory, in big-endian order
    void SHA1::storeBigEndianUint32(unsigned char* byte, Uint32 num)
    {
        assert(byte);
        byte[0] = (unsigned char)(num >> 24);
        byte[1] = (unsigned char)(num >> 16);
        byte[2] = (unsigned char)(num >> 8);
        byte[3] = (unsigned char)num;
    }


    // Constructor *******************************************************
    SHA1::SHA1()
    {
        // make sure that the data type is the right size
        assert(sizeof(Uint32) * 5 == 20);

        // initialize
        H0 = 0x67452301;
        H1 = 0xefcdab89;
        H2 = 0x98badcfe;
        H3 = 0x10325476;
        H4 = 0xc3d2e1f0;
        unprocessedBytes = 0;
        size = 0;
    }

    // Destructor ********************************************************
    SHA1::~SHA1()
    {
        // erase data
        H0 = H1 = H2 = H3 = H4 = 0;
        for (int c = 0; c < 64; c++) bytes[c] = 0;
        unprocessedBytes = size = 0;
    }

    // process ***********************************************************
    void SHA1::process()
    {
        assert(unprocessedBytes == 64);
        //printf( "process: " ); hexPrinter( bytes, 64 ); printf( "\n" );
        int t;
        Uint32 a, b, c, d, e, K, f, W[80];
        // starting values
        a = H0;
        b = H1;
        c = H2;
        d = H3;
        e = H4;
        // copy and expand the message block
        for (t = 0; t < 16; t++) W[t] = (bytes[t * 4] << 24)
            + (bytes[t * 4 + 1] << 16)
            + (bytes[t * 4 + 2] << 8)
            + bytes[t * 4 + 3];
        for (; t < 80; t++) W[t] = lrot(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);

        /* main loop */
        Uint32 temp;
        for (t = 0; t < 80; t++)
        {
            if (t < 20) {
                K = 0x5a827999;
                f = (b & c) | ((b ^ 0xFFFFFFFF) & d);//TODO: try using ~
            }
            else if (t < 40) {
                K = 0x6ed9eba1;
                f = b ^ c ^ d;
            }
            else if (t < 60) {
                K = 0x8f1bbcdc;
                f = (b & c) | (b & d) | (c & d);
            }
            else {
                K = 0xca62c1d6;
                f = b ^ c ^ d;
            }
            temp = lrot(a, 5) + f + e + W[t] + K;
            e = d;
            d = c;
            c = lrot(b, 30);
            b = a;
            a = temp;
            //printf( "t=%d %08x %08x %08x %08x %08x\n",t,a,b,c,d,e );
        }
        /* add variables */
        H0 += a;
        H1 += b;
        H2 += c;
        H3 += d;
        H4 += e;
        //printf( "Current: %08x %08x %08x %08x %08x\n",H0,H1,H2,H3,H4 );
        /* all bytes have been processed */
        unprocessedBytes = 0;
    }

    // addBytes **********************************************************
    void SHA1::addBytes(const char* data, int num)
    {
        assert(data);
        assert(num > 0);
        // add these bytes to the running total
        size += num;
        // repeat until all data is processed
        while (num > 0)
        {
            // number of bytes required to complete block
            int needed = 64 - unprocessedBytes;
            assert(needed > 0);
            // number of bytes to copy (use smaller of two)
            int toCopy = (num < needed) ? num : needed;
            // Copy the bytes
            memcpy(bytes + unprocessedBytes, data, toCopy);
            // Bytes have been copied
            num -= toCopy;
            data += toCopy;
            unprocessedBytes += toCopy;

            // there is a full block
            if (unprocessedBytes == 64) process();
        }
    }

    // digest ************************************************************
    void SHA1::getDigest(std::array<uint8_t, 20>& data)
    {
        // save the message size
        Uint32 totalBitsL = size << 3;
        Uint32 totalBitsH = size >> 29;
        // add 0x80 to the message
        addBytes("\x80", 1);

        unsigned char footer[64] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        // block has no room for 8-byte filesize, so finish it
        if (unprocessedBytes > 56)
            addBytes((char*)footer, 64 - unprocessedBytes);
        assert(unprocessedBytes <= 56);
        // how many zeros do we need
        int neededZeros = 56 - unprocessedBytes;
        // store file size (in bits) in big-endian format
        storeBigEndianUint32(footer + neededZeros, totalBitsH);
        storeBigEndianUint32(footer + neededZeros + 4, totalBitsL);
        // finish the final block
        addBytes((char*)footer, neededZeros + 8);
        // allocate memory for the digest bytes
        // copy the digest bytes
        storeBigEndianUint32(data.data(), H0);
        storeBigEndianUint32(data.data() + 4, H1);
        storeBigEndianUint32(data.data() + 8, H2);
        storeBigEndianUint32(data.data() + 12, H3);
        storeBigEndianUint32(data.data() + 16, H4);

    }
}