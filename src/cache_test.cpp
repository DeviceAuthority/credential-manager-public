/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the key cache class
 *
 */

#include "cache.hpp"
#include "dacryptor.hpp"
#include "base64.h"
#include "log.hpp"
#include "gtest/gtest.h"
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <pthread.h>
#include <iomanip>
#include <fstream>

// These are both used only by the test harness to induce behavour.
unsigned short c;
bool notfound;

void resetEnv( void )
{
    c = 0;
    notfound = false;
}

bool writeOutDataFileBadKey( const std::string& keyID )
{
    bool result = false;
    ++c;
    std::ofstream os( "testdata" );
    {
        std::ostringstream ossi;
        ossi << keyID << "_IV_" << std::setw( 3 ) << std::setfill( '0' ) << c;
        dacryptor cryptor;        
        cryptor.setCryptionKey("TESTKEY2TESTKEY2TESTKEY2TESTKEY2");
        cryptor.setInitVector("TESTIV02TESTIV02");
        os << "{\"message\":{\"key\":\"?THISWILLFAILTODECODE?";
        {
            std::string in = ossi.str();
            cryptor.setInputData(in);
            if (cryptor.encrypt())
            {
                const unsigned char* output = 0;
                unsigned int length = 0;
                cryptor.getCryptedData( output, length );
                std::string ready( (const char*) output, length );
                os << "\",\"iv\":\"" << ready << "\"}}";
                result = true;
            }
        }
    }
    os.close();
    return result;
}

bool writeOutDataFileBadIV( const std::string& keyID )
{
    bool result = false;
    ++c;
    std::ofstream os( "testdata" );
    {
        std::ostringstream ossk;
        ossk << keyID << "_KEY_" << std::setw( 3 ) << std::setfill( '0' ) << c;
        dacryptor cryptor;
       // cryptor.setArmor( true );
        cryptor.setCryptionKey("TESTKEY2TESTKEY2TESTKEY2TESTKEY2");
        cryptor.setInitVector("TESTIV02TESTIV02");
        os << "{\"message\":{\"iv\":\"?THISWILLFAILTODECODE?";
        {
            std::string in = ossk.str();
            cryptor.setInputData( in);
            if (cryptor.encrypt())
            {
                const unsigned char* output = 0;
                unsigned int length = 0;
                cryptor.getCryptedData( output, length );
                std::string ready( (const char*) output, length );
                os << "\",\"key\":\"" << ready << "\"}}";
                result = true;
            }
        }
    }
    os.close();
    return result;
}

bool writeOutBadAuthResponse( void )
{
    ++c;
    std::ofstream os( "testdata" );
    os << "{\"message\":{\"authenticated\":null}}";
    os.close();
    return true;
}

bool writeOutFalseAuthResponse( void )
{
    ++c;
    std::ofstream os( "testdata" );
    os << "{\"message\":{\"authenticated\":false}}";
    os.close();
    return true;
}

bool writeOutTrueAuthResponse( void )
{
    ++c;
    std::ofstream os( "testdata" );
    os << "{\"message\":{\"authenticated\":true}}";
    os.close();
    return true;
}

bool writeOutDataFile( const std::string& keyID )
{
    bool result = false;
    ++c;
    std::ofstream os( "testdata" );
    if (notfound)
    {
        os << "{\"message\":{}}";
        result = true;
    }
    else
    {
        std::ostringstream ossk;
        ossk << keyID << "_KEY_" << std::setw( 3 ) << std::setfill( '0' ) << c;
        std::ostringstream ossi;
        ossi << keyID << "_IV_" << std::setw( 3 ) << std::setfill( '0' ) << c;
        dacryptor cryptor;
        //cryptor.setArmor( true );
        cryptor.setCryptionKey("TESTKEY2TESTKEY2TESTKEY2TESTKEY2");
        cryptor.setInitVector("TESTIV02TESTIV02");
        {
            std::string in = ossk.str();
            cryptor.setInputData(in);
            if (cryptor.encrypt())
            {
                const unsigned char* output = 0;
                unsigned int length = 0;
                cryptor.getCryptedData( output, length );
                std::string ready( (const char*) output, length );
                os << "{\"message\":{\"key\":\"" << ready;
            }
        }
        {
            std::string in = ossi.str();
            cryptor.setInputData(in);
            if (cryptor.encrypt())
            {
                const unsigned char* output = 0;
                unsigned int length = 0;
                cryptor.getCryptedData( output, length );
                std::string ready( (const char*) output, length );
                os << "\",\"iv\":\"" << ready << "\"}}";
                result = true;
            }
        }
    }
    os.close();
    return result;
}

TEST(CryptosoftCache, NoServer)
{
    // Test that with no server, error is reported
    resetEnv();

    // Stop the json server
    system( "killall -s SIGINT testjsonserver 2> /dev/null > /dev/null" );
    sleep( 1 );

    Cache testCache;
    testCache.clear();

    std::string error;
    CachedData result;
    ASSERT_TRUE( writeOutDataFile( "TEST1" ) );
    EXPECT_EQ( 0, testCache.lookup( Lookup("TEST1", ""), result, error ) );
    EXPECT_EQ( 0, testCache.lookup( Lookup("", "POLICY"), result, error ) );
}
#if 0

TEST(CryptosoftCache, BadKeyDecodeFetch)
{
    // Test that with no params, items in the cache don't go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache;
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    ASSERT_TRUE( writeOutDataFileBadKey( "TEST" ) );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("TEST", ""), result, error ) );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, BadIVDecodeFetch)
{
    // Test that with no params, items in the cache don't go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache;
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    ASSERT_TRUE( writeOutDataFileBadIV( "TEST" ) );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("TEST", ""), result, error ) );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, DoesNotGoStaleFetch)
{
    // Test that with no params, items in the cache don't go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache;
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    ASSERT_TRUE( writeOutDataFile( "TEST1" ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST1", ""), result, error ) );
    ASSERT_TRUE( writeOutDataFile( "TEST1" ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST1", ""), result, error ) );
    ASSERT_STREQ( "TEST1_KEY_001", result.key_.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, DoesNotGoStaleGenerateTrue)
{
    // Test that with no params, items in the cache don't go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache;
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    ASSERT_TRUE( writeOutTrueAuthResponse() );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("", "POLICY"), result, error ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("", "POLICY"), result, error ) );
//    ASSERT_STREQ( "TESTKEY", result.key_.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, DoesNotGoStaleGenerateFalse)
{
    // Test that with no params, items in the cache don't go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache;
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    ASSERT_TRUE( writeOutFalseAuthResponse() );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("", "POLICY"), result, error ) );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("", "POLICY"), result, error ) );
//    ASSERT_STREQ( "TESTKEY", result.key_.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, DoesNotGoStaleGenerateNoResponse)
{
    // Test that with no params, items in the cache don't go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache;
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    notfound = true;
    ASSERT_TRUE( writeOutDataFile( "" ) );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("", "POLICY"), result, error ) );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("", "POLICY"), result, error ) );
//    ASSERT_STREQ( "TESTKEY", result.key_.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, DoesNotGoStaleGenerateBad)
{
    // Test that with no params, items in the cache don't go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache;
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    ASSERT_TRUE( writeOutBadAuthResponse() );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("", "POLICY"), result, error ) );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("", "POLICY"), result, error ) );
//    ASSERT_STREQ( "TESTKEY", result.key_.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, AlwaysGoStaleCount)
{
    // Test that with 0 params, items in the cache always go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache( -1, 0 );
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    ASSERT_TRUE( writeOutDataFile( "TEST2" ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST2", ""), result, error ) );
    ASSERT_TRUE( writeOutDataFile( "TEST2" ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST2", ""), result, error ) );
    ASSERT_STREQ( "TEST2_KEY_002", result.key_.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, AlwaysGoStaleTime)
{
    // Test that with 0 params, items in the cache always go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache( 0, -1 );
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    ASSERT_TRUE( writeOutDataFile( "TEST3" ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST3", ""), result, error ) );
    ASSERT_TRUE( writeOutDataFile( "TEST3" ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST3", ""), result, error ) );
    ASSERT_STREQ( "TEST3_KEY_002", result.key_.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, FalseWhenNotFound)
{
    // Test that if an item is not found in DMS false is returned.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache( -1, -1 );
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    notfound = true;
    ASSERT_TRUE( writeOutDataFile( "TEST4" ) );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("TEST4", ""), result, error ) );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, CachedWhenNotFound)
{
    // Test that if an item is not found that this is cached (doesn't try to fetch it every time).
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache( -1, 4 );
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    notfound = true;
    // Do 4 calls, first one should fetch with not found, next 3 should just used the cached "not found" value
    // rather than doing a fetch each time.
    ASSERT_TRUE( writeOutDataFile( "TEST5" ) );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("TEST5", ""), result, error ) );
    notfound = false;
    ASSERT_TRUE( writeOutDataFile( "TEST5" ) );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("TEST5", ""), result, error ) );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("TEST5", ""), result, error ) );
    EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup("TEST5", ""), result, error ) );
    // Now do one more call but expire the cache so that a fetch is performed.  If correct fetch should only
    // have been called twice (002_KEY).
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST5", ""), result, error ) );
    ASSERT_STREQ( "TEST5_KEY_002", result.key_.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, StaleFromCountWorks)
{
    // Test that the stale counter works as expected.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache( -1, 3 );
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    ASSERT_TRUE( writeOutDataFile( "TEST6" ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST6", ""), result, error ) );
    ASSERT_STREQ( "TEST6_KEY_001", result.key_.c_str() );
    ASSERT_TRUE( writeOutDataFile( "TEST6" ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST6", ""), result, error ) );
    ASSERT_STREQ( "TEST6_KEY_001", result.key_.c_str() );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST6", ""), result, error ) );
    ASSERT_STREQ( "TEST6_KEY_001", result.key_.c_str() );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST6", ""), result, error ) );
    ASSERT_STREQ( "TEST6_KEY_002", result.key_.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, StaleFromTimeWorks)
{
    // Test that the stale time works as expected.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache( 2, -1 );
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    // After 2 seconds it should be refreshed.
    ASSERT_TRUE( writeOutDataFile( "TEST7" ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST7", ""), result, error ) );
    ASSERT_STREQ( "TEST7_KEY_001", result.key_.c_str() );
    ASSERT_TRUE( writeOutDataFile( "TEST7" ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST7", ""), result, error ) );
    ASSERT_STREQ( "TEST7_KEY_001", result.key_.c_str() );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST7", ""), result, error ) );
    ASSERT_STREQ( "TEST7_KEY_001", result.key_.c_str() );
    sleep(3); // Wait 3 seconds for the cache to expire
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST7", ""), result, error ) );
    ASSERT_STREQ( "TEST7_KEY_002", result.key_.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, MaxCacheSizeExceeded)
{
    // Test that an error is returned when cache size exceeded.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache( -1, -1 );
    testCache.clear();

    // This test generates a lot of log messages that we don't want on screen.
    cryptosoft::logger.initialise( "cache_test", "MaxCacheSizeExceeded.log" );

    std::string error;
    cryptosoft::CachedData result;
    char keyID[10] = "";
    for (unsigned short count = 0; count < 100; ++count) // The maximum cache size currently is 100
    {
        sprintf( keyID, "TEST8%03d", count );
        ASSERT_TRUE( writeOutDataFile( "TEST8" ) );
        EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup(keyID, ""), result, error ) );
    }
    sprintf( keyID, "TEST8%03d", 100 );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup(keyID, ""), result, error ) );
    EXPECT_STREQ( "Cache is full, no space for new items.", error.c_str() );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "cache_test", "" );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, AllValuesReturned)
{
    // Test that a successful fetch sets all the return parameters correctly
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache( -1, -1 );
    testCache.clear();

    std::string error;
    cryptosoft::CachedData result;
    ASSERT_TRUE( writeOutDataFile( "TEST9" ) );
    EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup("TEST9", ""), result, error ) );
    ASSERT_STREQ( "TEST9_KEY_001", result.key_.c_str() );
    ASSERT_STREQ( "TEST9_IV_001", result.iv_.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

void* threadFunc( void* args )
{
    const unsigned int iterations = 10000;
    std::string error;
    cryptosoft::CachedData result;
    unsigned long total = 0;
    cryptosoft::Cache testCache( -1, iterations );
    for (unsigned int i = 0; i < iterations; ++i)
    {
        testCache.lookup( cryptosoft::Lookup("TEST10", ""), result, error );
        if (result.key_ == "TEST10_KEY_001") total += 1;
        else if (result.key_ == "TEST10_KEY_002") total += 2;
        else if (result.key_ == "TEST10_KEY_003") total += 4;
        else if (result.key_ == "TEST10_KEY_004") total += 8;
    }
    return (void*) total;
}

TEST(CryptosoftCache, ThreadsAreSafe)
{
    // Test that multiple (4) threads don't cause a problem.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    ASSERT_TRUE( writeOutDataFile( "TEST10" ) );

    cryptosoft::Cache::clear();
    unsigned long total = 0;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_t thread1;
    pthread_t thread2;
    pthread_t thread3;
    pthread_t thread4;
    pthread_create(&thread1, &attr, threadFunc, NULL);
    pthread_create(&thread2, &attr, threadFunc, NULL);
    pthread_create(&thread3, &attr, threadFunc, NULL);
    pthread_create(&thread4, &attr, threadFunc, NULL);
    pthread_attr_destroy(&attr);
    void* status;
    pthread_join(thread1, &status);
    total += (unsigned long) status;
    pthread_join(thread2, &status);
    total += (unsigned long) status;
    pthread_join(thread3, &status);
    total += (unsigned long) status;
    pthread_join(thread4, &status);
    total += (unsigned long) status;
//    total += (unsigned long) threadFunc(NULL);
//    ASSERT_EQ( (1u+2u+4u+8u) * 10000u, total );
    ASSERT_EQ( (1u+1u+1u+1u) * 10000u, total );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, RepeatedFilling)
{
    // Test that repeated filling of the cache is ok
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache( 0, 0 );
    testCache.clear();

    // This test generates a lot of log messages that we don't want on screen.
    cryptosoft::logger.initialise( "cache_test", "RepeatedFilling.log" );

    std::string error;
    cryptosoft::CachedData result;
    ASSERT_TRUE( writeOutDataFile( "TEST11" ) );
    const unsigned short reps = 10;
    unsigned short times;
    for (times = 0; times < reps; ++times)
    {
        testCache.clear();
        char keyID[10] = "";
        for (unsigned short count = 0; count < 50; ++count)
        {
            sprintf( keyID, "TEST11%03d", count );
            EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup(keyID, ""), result, error ) );
        }
        for (unsigned short count = 0; count < 50; ++count)
        {
            sprintf( keyID, "TEST11%03d", count );
            EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup(keyID, ""), result, error ) );
        }
    }
    ASSERT_EQ( reps, times );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "cache_test", "" );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftCache, RepeatedFoundAndNotFound)
{
    // Test that repeated found and then not found is ok
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::Cache testCache( 0, 0 );
    testCache.clear();

    // This test generates a lot of log messages that we don't want on screen.
    cryptosoft::logger.initialise( "cache_test", "RepeatedFoundAndNotFound.log" );

    std::string error;
    cryptosoft::CachedData result;
    const unsigned short reps = 10;
    unsigned short times;
    for (times = 0; times < reps; ++times)
    {
        char keyID[10] = "";
        notfound = false;
        ASSERT_TRUE( writeOutDataFile( "TEST12" ) );
        for (unsigned short count = 0; count < 50; ++count)
        {
            sprintf( keyID, "TEST12%03d", count );
            EXPECT_EQ( 1, testCache.lookup( cryptosoft::Lookup(keyID, ""), result, error ) );
        }
        notfound = true;
        ASSERT_TRUE( writeOutDataFile( "TEST12" ) );
        for (unsigned short count = 0; count < 50; ++count)
        {
            sprintf( keyID, "TEST12%03d", count );
            EXPECT_EQ( 0, testCache.lookup( cryptosoft::Lookup(keyID, ""), result, error ) );
        }
    }
    ASSERT_EQ( reps, times );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "cache_test", "" );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}
#endif