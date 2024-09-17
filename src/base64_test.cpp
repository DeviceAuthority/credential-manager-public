/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the Device Authority base 64 functions.
 *
 */
#include "base64.h"
#include "gtest/gtest.h"
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

TEST(CryptosoftBase64, Encode1)
{
    char result[101];
    base64Encode( (const unsigned char*) "1", 1, result, 101 );
    EXPECT_STREQ( "MQ==", result );
}

TEST(CryptosoftBase64, Encode2)
{
    char result[101];
    base64Encode( (const unsigned char*) "12", 2, result, 101 );
    EXPECT_STREQ( "MTI=", result );
}

TEST(CryptosoftBase64, Encode3)
{
    char result[101];
    base64Encode( (const unsigned char*) "123", 3, result, 101 );
    EXPECT_STREQ( "MTIz", result );
}

TEST(CryptosoftBase64, Encode4)
{
    char result[101];
    base64Encode( (const unsigned char*) "1234", 4, result, 101 );
    EXPECT_STREQ( "MTIzNA==", result );
}

TEST(CryptosoftBase64, Encode75)
{
    char result[101];
    base64Encode( (const unsigned char*) "123456789012345678901234567890123456789012345678901234567890123456789012345", 75, result, 101 );
    EXPECT_STREQ( "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1", result );
    EXPECT_EQ( 100u, strlen( result ) );
}

TEST(CryptosoftBase64, EncodeBiggerThanSpace)
{
    char result[101];
    base64Encode( (const unsigned char*) "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, result, 101 );
    EXPECT_EQ( 0u, strlen( result ) );
}

TEST(CryptosoftBase64, DecodeRubbish)
{
    unsigned char result[101];
    memset( result, 0, 101 );
    EXPECT_EQ( 0u, base64Decode("?TIz", result, 101 ) );
    EXPECT_EQ( 0u, base64Decode("M?Iz", result, 101 ) );
    EXPECT_EQ( 0u, base64Decode("MT?z", result, 101 ) );
    EXPECT_EQ( 0u, base64Decode("MTI?", result, 101 ) );
}

TEST(CryptosoftBase64, Decode1)
{
    unsigned char result[101];
    memset( result, 0, 101 );
    base64Decode("MQ==", result, 101 );
    EXPECT_STREQ( "1", (const char*) result );
}

TEST(CryptosoftBase64, Decode2)
{
    unsigned char result[101];
    memset( result, 0, 101 );
    base64Decode("MTI=", result, 101 );
    EXPECT_STREQ( "12", (const char*) result );
}

TEST(CryptosoftBase64, Decode3)
{
    unsigned char result[101];
    memset( result, 0, 101 );
    base64Decode("MTIz", result, 101 );
    EXPECT_STREQ( "123", (const char*) result );
}

TEST(CryptosoftBase64, Decode4)
{
    unsigned char result[101];
    memset( result, 0, 101 );
    base64Decode("MTIzNA==", result, 101 );
    EXPECT_STREQ( "1234", (const char*) result );
}

TEST(CryptosoftBase64, Decode75)
{
    unsigned char result[101];
    memset( result, 0, 101 );
    base64Decode("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1", result, 101 );
    EXPECT_STREQ( "123456789012345678901234567890123456789012345678901234567890123456789012345", (const char*) result );
}

TEST(CryptosoftBase64, DecodeBiggerThanSpace)
{
    unsigned char result[50];
    memset( result, 0, 50 );
    unsigned int length = base64Decode("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1", result, 50 );
    EXPECT_EQ( 0u, length );
}

#ifndef _WIN32
void* threadFuncEncode( void* args )
{
    const unsigned int iterations = 100;
    char result[101] = "";
    unsigned long total = 0;
    unsigned int i;
    for (i = 0; i < iterations; ++i)
    {
        base64Encode( (const unsigned char*) "123456789012345678901234567890123456789012345678901234567890123456789012345", 75, result, 101 );
        total += strlen( result );
    }
    return (void*) total;
}

TEST(CryptosoftBase64, ThreadsAreSafeEncode)
{
    // Test that multiple (4) threads don't cause a problem.
    const unsigned short threads = 4;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_t thread[threads];
    for (unsigned short t = 0; t < threads; ++t)
        pthread_create(&thread[t], &attr, threadFuncEncode, NULL);
    pthread_attr_destroy(&attr);
    unsigned long total = 0;
    for (unsigned short t = 0; t < threads; ++t)
    {
        void* status = 0;
        pthread_join(thread[t], &status);
        total += (unsigned long) status;
    }
//    total += (unsigned long) threadFunc(NULL);
    ASSERT_EQ( 10000ul * threads, total );
}

void* threadFuncDecode( void* args )
{
    const unsigned int iterations = 100;
    unsigned char result[101];
    unsigned long total = 0;
    unsigned int i;
    for (i = 0; i < iterations; ++i)
    {
        total += base64Decode("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1", result, 101 );
    }
    return (void*) total;
}

TEST(CryptosoftBase64, ThreadsAreSafeDecode)
{
    // Test that multiple (4) threads don't cause a problem.
    const unsigned short threads = 4;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_t thread[threads];
    for (unsigned short t = 0; t < threads; ++t)
        pthread_create(&thread[t], &attr, threadFuncDecode, NULL);
    pthread_attr_destroy(&attr);
    unsigned long total = 0;
    for (unsigned short t = 0; t < threads; ++t)
    {
        void* status = 0;
        pthread_join(thread[t], &status);
        total += (unsigned long) status;
    }
//    total += (unsigned long) threadFunc(NULL);
    ASSERT_EQ( 7500ul * threads, total );
}
#endif
