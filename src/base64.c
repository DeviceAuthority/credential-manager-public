/*
 * Copyright (c) 2015 deviceauthority. - All rights reserved. - www.deviceauthority.com
 *
 * Functions to perform base64 encoding and decoding.
 */

#include "base64.h"
#include <string.h>
#include <stdio.h>

/* Because binary representation is back to front need to put the
 * octets in backwards
 */
struct Octet
{
    unsigned int fourth : 6;
    unsigned int third : 6;
    unsigned int second : 6;
    unsigned int first : 6;
};

/* Because binary representation is back to front need to put the
 * characters in backwards
 */
struct Byte
{
    unsigned int third : 8;
    unsigned int second : 8;
    unsigned int first : 8;
};

static union
{
    struct Byte bytes;
    struct Octet octs; 
} con;

unsigned char decodeTable(char input)
{
    if (input == '+')
        return 62;
    if (input == '/')
        return 63;
    if ((input >= '0') && (input <= '9'))
        return input + 4;
    if ((input >= 'A') && (input <= 'Z'))
        return input - 65;
    if ((input >= 'a') && (input <= 'z'))
        return input - 71;
    return -1;
}

char encodeTable(unsigned char input)
{
    const char encodeMap[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    return encodeMap[input];
}

unsigned int base64Decode(const char *textToDecode, unsigned char *decodedByteBuffer, unsigned int decodedByteBufferSize)
{
    unsigned short bytesToDrop;
    unsigned int decodedPos = 0;
    unsigned int c;
    unsigned char value = 64;
    const unsigned int textToDecodeLength = strlen( textToDecode );
    if (!textToDecode)
    {
        return 0;
    }
    if (!decodedByteBuffer)
    {
        return 0;
    }
    for (c = 0; c < textToDecodeLength; c = c + 4)
    {
        bytesToDrop = 0;
        value = decodeTable(textToDecode[c]);
        if (value > 64) return 0;
        con.octs.first = value;
        if (c+1 < textToDecodeLength)
        {
            value = decodeTable(textToDecode[c+1]);
            if (value > 64) return 0;
            con.octs.second = value;
        }
        if (c+2 < textToDecodeLength && textToDecode[c+2] != '=')
        {
            value = decodeTable(textToDecode[c+2]);
            if (value > 64) return 0;
            con.octs.third = value;
        }
        else
            ++bytesToDrop;
        if (c+3 < textToDecodeLength && textToDecode[c+3] != '=')
        {
            value = decodeTable(textToDecode[c+3]);
            if (value > 64) return 0;
            con.octs.fourth = value;
        }
        else
            ++bytesToDrop;
        if (decodedPos >= decodedByteBufferSize)
        {
            decodedPos = 0;
            break;
        }
        decodedByteBuffer[decodedPos] = con.bytes.first;
        ++decodedPos;
        if (decodedPos >= decodedByteBufferSize)
        {
            decodedPos = 0;
            break;
        }
        if (bytesToDrop < 2)
        {
            decodedByteBuffer[decodedPos] = con.bytes.second;
            ++decodedPos;
        }
        if (decodedPos >= decodedByteBufferSize)
        {
            decodedPos = 0;
            break;
        }
        if (bytesToDrop < 1)
        {
            decodedByteBuffer[decodedPos] = con.bytes.third;
            ++decodedPos;
        }
    }
    return decodedPos;
}

unsigned int base64Encode(const unsigned char *bytesToEncode, unsigned int bytesToEncodeLength, char *encodedTextBuffer, unsigned int encodedTextBufferSize)
{
    unsigned short octsToDrop;
    unsigned int encodedPos = 0;
    unsigned int c;
    if (!bytesToEncode)
    {
        return encodedPos;
    }
    if (!encodedTextBuffer)
    {
        return encodedPos;
    }
    if (!bytesToEncodeLength)
    {
        return encodedPos;
    }
    for (c = 0; c < bytesToEncodeLength; c = c + 3)
    {
        octsToDrop = 0;
        con.bytes.first = bytesToEncode[c];
        if (c+1 < bytesToEncodeLength)
            con.bytes.second = bytesToEncode[c+1];
        else
        {
            con.bytes.second = 0;
            ++octsToDrop;
        }
        if (c+2 < bytesToEncodeLength)
            con.bytes.third = bytesToEncode[c+2];
        else
        {
            con.bytes.third = 0;
            ++octsToDrop;
        }
        if (encodedPos >= encodedTextBufferSize)
        {
            encodedPos = 0;
            break;
        }
        encodedTextBuffer[encodedPos] = encodeTable(con.octs.first);
        ++encodedPos;
        if (encodedPos >= encodedTextBufferSize)
        {
            encodedPos = 0;
            break;
        }
        encodedTextBuffer[encodedPos] = encodeTable(con.octs.second);
        ++encodedPos;
        if (encodedPos >= encodedTextBufferSize)
        {
            encodedPos = 0;
            break;
        }
        if (octsToDrop < 2)
        {
            encodedTextBuffer[encodedPos] = encodeTable(con.octs.third);
            ++encodedPos;
        }
        else
        {
            encodedTextBuffer[encodedPos] = '=';
            ++encodedPos;
        }
        if (encodedPos >= encodedTextBufferSize)
        {
            encodedPos = 0;
            break;
        }
        if (octsToDrop < 1)
        {
            encodedTextBuffer[encodedPos] = encodeTable(con.octs.fourth);
            ++encodedPos;
        }
        else
        {
            encodedTextBuffer[encodedPos] = '=';
            ++encodedPos;
        }
    }
    encodedTextBuffer[encodedPos] = '\0';
    return encodedPos;
}

/*
int main(int argc, char* argv[])
{
//    char bytesToEncode[] = "pleasure.";
//    char textToDecode[] = "cGxlYXN1cmUu";

    if (argv[1][0] == 'E')
        encode(argv[2]);
    else
        decode(argv[2]);
    return 0;
}
*/
