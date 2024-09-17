/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the Device Authority regular expression functions.
 *
 */
#include "regexmatch.h"
#include "gtest/gtest.h"
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

TEST(CryptosoftRegExMatch, MatchesExact)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "test1", "test1", error, 100 ) );
}

TEST(CryptosoftRegExMatch, MatchesDigit)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "test1", "test[0-9]", error, 100 ) );
}

TEST(CryptosoftRegExMatch, MatchesDigits)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "test11", "test[0-9]+", error, 100 ) );
}

TEST(CryptosoftRegExMatch, DoesntMatchDigits)
{
    char error[100] = "";
    EXPECT_EQ( 0, matches( "test", "test[0-9]+", error, 100 ) );
}

TEST(CryptosoftRegExMatch, MatchesLetter)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "test1", "[a-z]est1", error, 100 ) );
}

TEST(CryptosoftRegExMatch, MatchesWord)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "test1", "[a-z]+1", error, 100 ) );
}

TEST(CryptosoftRegExMatch, DoesntMatchWord)
{
    char error[100] = "";
    EXPECT_EQ( 0, matches( "TEST1", "[a-z]+1", error, 100 ) );
}

TEST(CryptosoftRegExMatch, MatchesWordAtStart)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "test1TEST1", "^[a-z]+1", error, 100 ) );
}

TEST(CryptosoftRegExMatch, MatchesWordAtEnd)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "TEST1test1", "[a-z]+1$", error, 100 ) );
}

TEST(CryptosoftRegExMatch, NotMatchWordAtStart)
{
    char error[100] = "";
    EXPECT_EQ( 0, matches( "TEST1test1", "^[a-z]+1$", error, 100 ) );
}

TEST(CryptosoftRegExMatch, NotMatchWordAtEnd)
{
    char error[100] = "";
    EXPECT_EQ( 0, matches( "test1TEST1", "[a-z]+1$", error, 100 ) );
}

TEST(CryptosoftRegExMatch, MatchIncSlash)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "localhost/guid/secure/upload", "localhost/.*/upload", error, 100 ) );
}

TEST(CryptosoftRegExMatch, NotMatchIncSlash)
{
    char error[100] = "";
    EXPECT_EQ( 0, matches( "localhost/guid/secure/upload", "localhost/[^/]*/upload", error, 100 ) );
}

TEST(CryptosoftRegExMatch, MatchNoSlash)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "localhost/guid/upload", "localhost/[^/]*/upload", error, 100 ) );
}

TEST(CryptosoftRegExMatch, MatchRegExEmpty)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "localhost/guid/upload", "", error, 100 ) );
}

TEST(CryptosoftRegExMatch, MatchRegExSlash)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "localhost/", "/", error, 100 ) );
}

TEST(CryptosoftRegExMatch, MatchIPAddress)
{
    char error[100] = "";
    EXPECT_EQ( 1, matches( "127.0.0.1", "\\d+\\.\\d+\\.\\d+\\.\\d+", error, 100 ) );
    EXPECT_EQ( 1, matches( "10.1.2.160", "\\d+\\.\\d+\\.\\d+\\.\\d+", error, 100 ) );
    EXPECT_EQ( 1, matches( "192.168.1.245", "\\d+\\.\\d+\\.\\d+\\.\\d+", error, 100 ) );
    EXPECT_EQ( 1, matches( "10.10.1.10/post.php", "\\d+\\.\\d+\\.\\d+\\.\\d+", error, 100 ) );
}

TEST(CryptosoftRegExMatch, ErrorOnBadRegEx)
{
    char error[100] = "";
    EXPECT_EQ( 0, matches( "10.10.1.10", "\\g+\\.\\d+\\.\\d+\\.\\d+", error, 100 ) );
    EXPECT_NE( 0, error[0] );
}

TEST(CryptosoftRegExMatch, NoCrashErrorTooSmall)
{
    char error[5] = "";
    EXPECT_EQ( 0, matches( "10.10.1.10", "\\g+\\.\\d+\\.\\d+\\.\\d+", error, 5 ) );
    EXPECT_EQ( 0, error[0] );
}

#ifndef _WIN32
void* threadFunc( void* args )
{
    const unsigned int iterations = 10000;
    char error[100] = "";
    unsigned long total = 0;
    unsigned int i;
    for (i = 0; i < iterations; ++i)
    {
        total += matches( "192.168.1.245", "\\d+\\.\\d+\\.\\d+\\.\\d+", error, 100 );
    }
    return (void*) total;
}

TEST(CryptosoftRegExMatch, ThreadsAreSafe)
{
    // Test that multiple (4) threads don't cause a problem.
    const unsigned short threads = 4;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_t thread[threads];
    for (unsigned short t = 0; t < threads; ++t)
        pthread_create(&thread[t], &attr, threadFunc, NULL);
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
#endif
