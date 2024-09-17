/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the wrapper class for the Device Authority security calls
 *
 */
#include "deviceauthority.hpp"
#include "gtest/gtest.h"
#include <string>
#include <fstream>

void writeOutDataFile( void )
{
    std::ofstream os( "testdata" );
    os << "{\"httpCode\":200,\"statusCode\":0,\"message\":{\"nextAction\":\"register\",\"message\":\"TESTING-REGISTRATION-MESSAGE\",\"challenge\":\"TESTING-CHALLENGE-MESSAGE\",\"provisionId\":\"TESTING-PROVISION-ID\"}}";
    os.close();
}

void writeOutRegisterFile( void )
{
    std::ofstream os( "regresponse" );
    os << "{\"httpCode\":200,\"statusCode\":0,\"message\":{\"message\":\"\"}}";
    os.close();
}

void writeOutErrorDataFile( void )
{
    std::ofstream os( "testdata" );
    os << "{\"httpCode\":200,\"statusCode\":1,\"message\":{\"errorMessage\":\"This is a test error message.\"}}";
    os.close();
}
/*
TEST(CryptosoftDeviceAuthority, LibraryNotLoaded)
{
    ASSERT_DEATH(DeviceAuthorityBase::getInstance(), "Unable to open libnaudaddk_shared.*");
    //DeviceAuthority( const std::string& user, const std::string& APIURL, const std::string& deviceName, Log* log, char* testing )
    //ASSERT_DEATH( DeviceAuthority da( "test@cryptosoft.com", "https://127.0.0.1:8444/", "TESTDEVICE", 0, (char*) "FAILLIBLOAD" ), "Unable to open libnaudaddk_shared.*" );
}


TEST(CryptosoftDeviceAuthority, NoServer)
{
    std::string message;
   DeviceAuthority da( "test@cryptosoft.com", "https://127.0.0.1:8444/", "TESTDEVICE", 0, (char*) "" );
    std::string keyID, key, iv;
    std::string result = da.identifyAndAuthorise( keyID, key, iv, message );
    EXPECT_STREQ( "Connect to API 'https://127.0.0.1:8444/challenge' failed (code 111).", message.c_str() );
}
*/
//Can't execute the test as DAAPIURL is read from config directly.
/*
TEST(CryptosoftDeviceAuthority, IdentifyAndAuthorise)
{
    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    writeOutDataFile();
    writeOutRegisterFile();

    std::string message;
    DeviceAuthority da( "test@cryptosoft.com", "https://127.0.0.1:8444/", "TESTDEVICE", 0, (char*) "" );
    std::string keyID, key, iv;
    std::string result = da.identifyAndAuthorise( keyID, key, iv, message );
    EXPECT_STREQ( "cd32f3d3-f0cc-467f-9114-e4942c54fddc", keyID.c_str() );
    EXPECT_STREQ( "9Hsg5f8lYtP3yMLSRc87uI2eOqtt8+IXi9PflbQrbGs=", key.c_str() );
    EXPECT_STREQ( "gTuPbfh2GnD3Z8x9wz+51w==", iv.c_str() );
    EXPECT_STREQ( "{\"userId\":\"test@cryptosoft.com\",\"deviceKey\":\"TESTING-DEVICE-KEY\"}", result.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}*/

//Can't execute the test as DAAPIURL is read from config directly.
/*
TEST(CryptosoftDeviceAuthority, IdentifyAndAuthorisePolicyIDKeyID)
{
    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    writeOutDataFile();
    writeOutRegisterFile();

    std::string message;
    DeviceAuthority da( "test@cryptosoft.com", "https://127.0.0.1:8444/", "TESTDEVICE", 0, (char*) "" );
    std::string keyID = "SOMEKEY", key, iv;
    std::string result = da.identifyAndAuthorise( keyID, key, iv, message, 0, "policyID" );
    EXPECT_STREQ( "cd32f3d3-f0cc-467f-9114-e4942c54fddc", keyID.c_str() );
    EXPECT_STREQ( "9Hsg5f8lYtP3yMLSRc87uI2eOqtt8+IXi9PflbQrbGs=", key.c_str() );
    EXPECT_STREQ( "gTuPbfh2GnD3Z8x9wz+51w==", iv.c_str() );
    EXPECT_STREQ( "{\"userId\":\"test@cryptosoft.com\",\"keyId\":\"SOMEKEY\",\"deviceKey\":\"TESTING-DEVICE-KEY\"}", result.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}*/

/*
TEST(CryptosoftDeviceAuthority, IdentifyAndAuthoriseFailure)
{
    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    writeOutErrorDataFile();
    writeOutRegisterFile();

    std::string message;
    DeviceAuthority da( "test@cryptosoft.com", "https://127.0.0.1:8444/", "", 0, (char*) "" );
    std::string keyID, key, iv;
    std::string result = da.identifyAndAuthorise( keyID, key, iv, message );
    EXPECT_STREQ( "", result.c_str() );

    // Stop the json server
    system( "killall -s SIGINT testjsonserver" );
    sleep( 1 );
}*/

/*
#ifndef _WIN32
void* threadFunc( void* args )
{
    size_t t = (size_t) args;
    const char* json = "[20,5,9,30]";
    const unsigned int iterations = 10000;
    unsigned long total = 0;
    unsigned int i;
    for (i = 0; i < iterations; ++i)
    {
        Json n;
        n.parse( json );
        char path[5];
        path[0] = '/';
        path[1] = '[';
        path[2] = '0' + t;
        path[3] = ']';
        path[4] = '\0';
        Json* res = n.atXPath(path);
        total += *(res->num);
    }
    return (void*) total;
}

TEST(CryptosoftJSONParse, ThreadsAreSafe)
{
    // Test that multiple (4) threads don't cause a problem.
    const unsigned short threads = 4;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_t thread[threads];
    for (size_t t = 0; t < threads; ++t)
        pthread_create(&thread[t], &attr, threadFunc, (void*) t);
    pthread_attr_destroy(&attr);
    unsigned long total = 0;
    for (unsigned short t = 0; t < threads; ++t)
    {
        void* status = 0;
        pthread_join(thread[t], &status);
        total += (unsigned long) status;
    }
//    total += (unsigned long) threadFunc(NULL);
    ASSERT_EQ( (10000ul * 20) + (10000ul * 5) + (10000ul * 9) + (10000ul * 30), total );
}
#endif
*/
