/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the policy store class
 *
 */

#include "policystore.hpp"
#include "log.hpp"
#include "gtest/gtest.h"
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <pthread.h>
#include <iomanip>
#include <fstream>

// This is used only by the test harness to induce behavour.
unsigned short c;

#if 0
void resetEnv( void )
{
    c = 0;
    PolicyStore::clear();
    PolicyStore::makeStale();
}

void writeOutDataFile( void )
{
    ++c;
    std::ofstream os( "testdata" );
    os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST" << c << "\",\"description\":\"TEST" << c << "\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"},{\"gatewayCryptoOperation\":\"DECRYPT\",\"urlPattern\":\"/demo/device3/json/*\",\"id\":\"TEST" << c+1 << "\",\"description\":\"TEST" << c+1 << "\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"},{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device2/json/a\",\"id\":\"TEST" << c+2 << "\",\"description\":\"TEST" << c+2 << "\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"BOTH\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"},{\"gatewayCryptoOperation\":\"DECRYPT\",\"urlPattern\":\"/demo/device2/json/*\",\"id\":\"TEST" << c+3 << "\",\"description\":\"TEST" << c+3 << "\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"S2C\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"},{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST" << c+4 << "\",\"description\":\"TEST" << c+4 << "\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"POST\",\"gatewayDataDirection\":\"BOTH\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
    c += 9;
    os.close();
}

void writeOutBadDataFile( int type )
{
    std::ofstream os( "testdata" );
    switch (type)
    {
        case 1:
            os << "{\"message\":{\"errorMessage\":\"There was an error\"}";
            break;
        case 2:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":null,\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 3:
            os << "{\"message\":{\"policies\":[{\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 4:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":null,\"id\":\"TEST\",\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 5:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"id\":\"TEST\",\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 6:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":null,\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 7:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 8:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"description\":null,\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 9:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 10:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"description\":\"TEST\",\"domain\":null,\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 11:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"description\":\"TEST\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 12:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":null,\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 13:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"payloadType\":\"PLAIN\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 14:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":null,\"cryptionPath\":\"/\"}]}}";
            break;
        case 15:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"cryptionPath\":\"/\"}]}}";
            break;
        case 16:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\",\"cryptionPath\":null}]}}";
            break;
        case 17:
            os << "{\"message\":{\"policies\":[{\"gatewayCryptoOperation\":\"ENCRYPT\",\"urlPattern\":\"/demo/device3/json/a\",\"id\":\"TEST\",\"description\":\"TEST\",\"domain\":\"cryptosoft.com\",\"gatewayMethodType\":\"NONE\",\"gatewayDataDirection\":\"C2S\",\"payloadType\":\"PLAIN\"}]}}";
            break;
    }
    os.close();
}

TEST(CryptosoftPolicyStore, NoServer)
{
    // Test that with no server, error is reported
    resetEnv();

    PolicyStore policyStore( "mqtt" );

    OpType op = NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    EXPECT_FALSE( policyStore.findAPolicyMatch( "cryptosoft.com", C2S, NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
}

TEST(CryptosoftPolicyStore, BadData)
{
    // Test that with no params, items in the store don't go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "mqtt", 0 );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    for (unsigned short i = 1; i <= 17; i++)
    {
        writeOutBadDataFile( i );
        EXPECT_FALSE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
        sleep( 1 );
    }

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, DoesNotGoStale)
{
    // Test that with no params, items in the store don't go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "mqtt" );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::ENCRYPT, op );
    EXPECT_STREQ( "TEST1", name.c_str() );
    writeOutDataFile();
    ASSERT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    ASSERT_EQ( cryptosoft::ENCRYPT, op );
    ASSERT_STREQ( "TEST1", name.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, AlwaysGoStaleTime)
{
    // Test that with 0 params, items in the cache always go stale.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "http", 0 );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::S2C, cryptosoft::NA, "/demo/device2/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::ENCRYPT, op );
    EXPECT_STREQ( "TEST3", name.c_str() );
    writeOutDataFile();
    ASSERT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::S2C, cryptosoft::NA, "/demo/device2/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    ASSERT_EQ( cryptosoft::ENCRYPT, op );
    ASSERT_STREQ( "TEST13", name.c_str() );
    writeOutDataFile();
    ASSERT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::S2C, cryptosoft::NA, "/demo/device2/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    ASSERT_EQ( cryptosoft::ENCRYPT, op );
    ASSERT_STREQ( "TEST23", name.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, NothingWhenNotFoundDomain)
{
    // Test that if an item is not found in SAC Nothing is returned.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "http", -1 );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    ASSERT_TRUE( policyStore.findAPolicyMatch( "crypto.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    ASSERT_EQ( cryptosoft::NOTHING, op );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, NothingWhenNotFoundMethod)
{
    // Test that if an item is not found in SAC Nothing is returned.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "http", -1 );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    ASSERT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::S2C, cryptosoft::GET, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    ASSERT_EQ( cryptosoft::NOTHING, op );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, NothingWhenNotFoundFlow)
{
    // Test that if an item is not found in SAC Nothing is returned.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "http", -1 );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    ASSERT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::S2C, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    ASSERT_EQ( cryptosoft::NOTHING, op );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, NothingWhenNotFoundURL)
{
    // Test that if an item is not found in SAC Nothing is returned.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "http", -1 );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    ASSERT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device4/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    ASSERT_EQ( cryptosoft::NOTHING, op );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, CachedWhenNotFound)
{
    // Test that if an item is not found that this is cached (doesn't try to fetch it every time).
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "mqtt", 5 );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    // Do 4 calls, first one should fetch with not found, next 3 should just used the cached "not found" value
    // rather than doing a fetch each time.
    writeOutDataFile();
    EXPECT_TRUE( policyStore.findAPolicyMatch( "crypto.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::NOTHING, op );
    writeOutDataFile();
    EXPECT_TRUE( policyStore.findAPolicyMatch( "crypto.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::NOTHING, op );
    EXPECT_TRUE( policyStore.findAPolicyMatch( "crypto.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::NOTHING, op );
    EXPECT_TRUE( policyStore.findAPolicyMatch( "crypto.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::NOTHING, op );
    // Now do one more call but expire the cache so that a fetch is performed.  If correct fetch should only
    // have been called twice (TEST11)
    sleep( 6 );
    EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::ENCRYPT, op );
    ASSERT_STREQ( "TEST11", name.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, StaleFromTimeWorks)
{
    // Test that the stale time works as expected.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "mqtt", 2 );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    // After 2 seconds it should be refreshed.
    writeOutDataFile();
    EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::ENCRYPT, op );
    EXPECT_STREQ( "TEST1", name.c_str() );
    writeOutDataFile();
    EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::ENCRYPT, op );
    EXPECT_STREQ( "TEST1", name.c_str() );
    EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::ENCRYPT, op );
    EXPECT_STREQ( "TEST1", name.c_str() );
    sleep(3); // Wait 3 seconds for the cache to expire
    EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::ENCRYPT, op );
    ASSERT_STREQ( "TEST11", name.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, AllValuesReturned)
{
    // Test that a successful fetch sets all the return parameters correctly
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "mqtt", -1 );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
    ASSERT_EQ( cryptosoft::ENCRYPT, op );
    ASSERT_STREQ( "TEST1", name.c_str() );
    ASSERT_STREQ( "TEST1", policyID.c_str() );
    ASSERT_STREQ( "PLAIN", payloadType.c_str() );
    ASSERT_STREQ( "/", cryptionPath.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

void* threadFunc( void* args )
{
    const unsigned int iterations = 10000;
    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    unsigned long total = 0;
    cryptosoft::PolicyStore policyStore( "mqtt", 1 );
    for (unsigned int i = 0; i < iterations; ++i)
    {
        policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error );
        if (name == "TEST1") total += 1;
        else if (name == "TEST11") total += 2;
        else if (name == "TEST21") total += 4;
        else if (name == "TEST31") total += 8;
    }
    return (void*) total;
}

TEST(CryptosoftPolicyStore, ThreadsAreSafe)
{
    // Test that multiple (4) threads don't cause a problem.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // This test generates a lot of log messages that we don't want on screen.
    cryptosoft::logger.initialise( "policystore_test", "ThreadsAreSafe.log" );

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
    ASSERT_GT( total, 10000u );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "policystore_test", "" );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, RepeatedFilling)
{
    // Test that repeated filling of the cache is ok
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Set up the store so that the cache expires on every search
    cryptosoft::PolicyStore policyStore( "mqtt", 0 );

    // This test generates a lot of log messages that we don't want on screen.
    cryptosoft::logger.initialise( "policystore_test", "RepeatedFilling.log" );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    const unsigned short reps = 10;
    unsigned short times;
    for (times = 0; times < reps; ++times)
    {
        for (unsigned short count = 0; count < 100; ++count)
        {
            ASSERT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
            ASSERT_EQ( cryptosoft::ENCRYPT, op );
        }
    }
    ASSERT_EQ( reps, times );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "policystore_test", "" );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, RepeatedFoundAndNotFound)
{
    // Test that repeated found and then not found is ok
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Set up the store so that the cache expires on every search
    cryptosoft::PolicyStore policyStore( "mqtt", 0 );

    // This test generates a lot of log messages that we don't want on screen.
    cryptosoft::logger.initialise( "policystore_test", "RepeatedFoundAndNotFound.log" );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    const unsigned short reps = 10;
    unsigned short times;
    for (times = 0; times < reps; ++times)
    {
        op = cryptosoft::NOTHING;
        for (unsigned short count = 0; count < 50; ++count)
        {
            EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
            EXPECT_EQ( cryptosoft::ENCRYPT, op );
        }
        op = cryptosoft::NOTHING;
        for (unsigned short count = 0; count < 50; ++count)
        {
            EXPECT_TRUE( policyStore.findAPolicyMatch( "crypto.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name, payloadType, cryptionPath, policyID, error ) );
            EXPECT_EQ( cryptosoft::NOTHING, op );
        }
    }
    ASSERT_EQ( reps, times );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "policystore_test", "" );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, BadProtocol)
{
    // Test that the correct policy is returned for the supplied credentials
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "AAAA", -1 );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    EXPECT_FALSE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/b", op, name, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::NOTHING, op );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, CorrectMatch)
{
    // Test that the correct policy is returned for the supplied credentials
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    cryptosoft::PolicyStore policyStore( "mqtt", -1 );

    cryptosoft::OpType op = cryptosoft::NOTHING;
    std::string name1 = "", name2 = "", payloadType = "", cryptionPath = "", policyID = "", error = "";
    writeOutDataFile();
    EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/a", op, name1, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::ENCRYPT, op );
    EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::NA, "/demo/device3/json/b", op, name2, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::DECRYPT, op );
    EXPECT_TRUE( policyStore.findAPolicyMatch( "cryptosoft.com", cryptosoft::C2S, cryptosoft::POST, "/demo/device3/json/a", op, name2, payloadType, cryptionPath, policyID, error ) );
    EXPECT_EQ( cryptosoft::ENCRYPT, op );
    EXPECT_STRNE( name1.c_str(), name2.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftPolicyStore, DumpPolicies)
{
    // Test that the the policies are listed.
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    writeOutDataFile();

    cryptosoft::PolicyStore policyStore( "mqtt", -1, true );

    std::ostringstream oss;
    policyStore.dumpToStream( oss );
    EXPECT_STREQ( "Policies:\nPolicy: TEST1 to fully ENCRYPT messages flowing from device to server on topic: /demo/device3/json/a\nPolicy: TEST2 to fully DECRYPT messages flowing from device to server on topic: /demo/device3/json/*\nPolicy: TEST3 to fully ENCRYPT messages flowing in both directions on topic: /demo/device2/json/a\nPolicy: TEST4 to fully DECRYPT messages flowing from server to device on topic: /demo/device2/json/*\nPolicy: TEST5 to fully ENCRYPT messages flowing in both directions via a POST on URL: /demo/device3/json/a\n", oss.str().c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}
#endif
