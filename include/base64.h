#ifndef BASE64_H
#define BASE64_H

/*
 * Copyright (c) 2015 deviceauthority. - All rights reserved. - www.deviceauthority.com
 *
 * Functions to perform base64 encoding and decoding.
 */

#ifdef __cplusplus
extern "C"
{
#endif

unsigned int base64Encode( const unsigned char* bytesToEncode, unsigned int bytesToEncodeLength, char* encodedTextBuffer, unsigned int encodedTextBufferSize );
unsigned int base64Decode( const char* textToDecode, unsigned char* decodedByteBuffer, unsigned int decodedByteBufferSize );

#ifdef __cplusplus
};
#endif

#endif
