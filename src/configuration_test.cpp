/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the Configuration class
 *
 */
#include "configuration.hpp"
#include "gtest/gtest.h"
#include <iostream>
#include <fstream>
#include <string>
#include "constants.hpp"
//using namespace cryptosoft;

TEST(Configuration, CheckDefaultFileParse)
{
    // Try to parse the default file "config.conf"
    // Set up the test data
    std::ofstream ofs( "config.conf" );
    ofs << "# Empty configuration";
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse() );
}

TEST(Configuration, CheckFileNotFound)
{
    // Try to parse a non existent file "unknown.conf"
    Configuration component;
    ASSERT_FALSE( component.parse( "unknown.conf" ) );
}

TEST(Configuration, CheckEmptyFileParse)
{
    // Try to parse a config file with nothing in it
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse() );
}

TEST(Configuration, IgnoreComments)
{
    // Parse a config file with comments in, they should cause no problems
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "# Cache configuration" << std::endl; // Should be ignored
    ofs << "KeyCacheTimeOut = 100" << std::endl;    // Should be parsed
    ofs << "#KeyCacheTimeOut = 200" << std::endl;   // Should be ignored
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_STREQ( "100", component.lookup( CFG_KEYCACHETIMEOUT ).c_str() );
}

TEST(Configuration, SpacesAllowed)
{
    // Parse a config file with spaces in the values, they should cause no problems
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "DeviceName = Test 1.0" << std::endl;    // Should be parsed
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_STREQ( "Test 1.0", component.lookup( CFG_DEVICENAME ).c_str() );
}

TEST(Configuration, FailBadComments)
{
    // Parse a config file with bad comments in, it should fail
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "KeyCacheTimeOut = 100 # A bad comment, must be on a line on its own" << std::endl;
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_FALSE( component.parse( "test.conf" ) );
}

TEST(Configuration, NewerOverrides)
{
    // Parse a config file with two of the same entry in, the last should override the first
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "KeyCacheTimeOut = 100" << std::endl;    // Should be parsed
    ofs << "KeyCacheTimeOut = 200" << std::endl;    // Should override previous
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_STREQ( "200", component.lookup( CFG_KEYCACHETIMEOUT ).c_str() );
}

TEST(Configuration, BadSyntax1)
{
    // Parse a config file with bad syntax in it, it should fail
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "KeyCacheTimeOut=100" << std::endl;    // Not in correct format
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_FALSE( component.parse( "test.conf" ) );
}

TEST(Configuration, BadSyntax2)
{
    // Parse a config file with bad syntax in it, it should fail
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "KeyCacheTimeOut == 100" << std::endl;    // Not in correct format
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_FALSE( component.parse( "test.conf" ) );
}

TEST(Configuration, BadSyntax3)
{
    // Parse a config file with bad syntax in it, it should fail
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "KeyCacheTimeOut = 100 = 200" << std::endl;    // Not in correct format
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_FALSE( component.parse( "test.conf" ) );
}

TEST(Configuration, BadItem)
{
    // Parse a config file with a bad item in it, it should fail
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "UnknownItem = FAIL" << std::endl;    // Not known item
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_FALSE( component.parse( "test.conf" ) );
}

TEST(Configuration, BadValueForItem)
{
    // Parse a config file with text for a numeric item
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "KeyCacheTimeOut = FAIL" << std::endl;    // Should be numeric
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_FALSE( component.parse( "test.conf" ) );
}

TEST(Configuration, BadValueForEnum)
{
    // Parse a config file with invalid value for a enum item
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "Location = FAIL" << std::endl;    // Should be CLIENT_SIDE or SERVER_SIDE
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_FALSE( component.parse( "test.conf" ) );
}

TEST(Configuration, LowercaseValueForEnum)
{
    // Parse a config file with lower case value for a enum item
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "Location = client_side" << std::endl;    // Should be CLIENT_SIDE or SERVER_SIDE
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_STREQ( "CLIENT_SIDE", component.lookup( CFG_LOCATION ).c_str() );
}

TEST(Configuration, MixedcaseValueForEnum)
{
    // Parse a config file with mixed case value for a enum item
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "Location = Server_Side" << std::endl;    // Should be CLIENT_SIDE or SERVER_SIDE
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_STREQ( "SERVER_SIDE", component.lookup( CFG_LOCATION ).c_str() );
}

TEST(Configuration, UppercaseValueForEnum)
{
    // Parse a config file with upper case value for a enum item
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "Location = SERVER_SIDE" << std::endl;    // Should be CLIENT_SIDE or SERVER_SIDE
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_STREQ( "SERVER_SIDE", component.lookup( CFG_LOCATION ).c_str() );
}

TEST(Configuration, LookupUnknownItem)
{
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "KeyCacheTimeOut = -1" << std::endl;
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
}

TEST(Configuration, DBParamsEscapeSpecialChars)
{
    // Parse a config file with all the DB items in it
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "DBHost = 'host'" << std::endl;
    ofs << "DBName = \\name\\" << std::endl;
    ofs << "DBUser = \\'user'\\" << std::endl;
    ofs << "DBPassword = '\\pass\\'" << std::endl;
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    EXPECT_STREQ( "\\'host\\'", component.lookup( CFG_DBHOST ).c_str() );
    EXPECT_STREQ( "\\\\name\\\\", component.lookup( CFG_DBNAME ).c_str() );
    EXPECT_STREQ( "\\\\\\'user\\'\\\\", component.lookup( CFG_DBUSER ).c_str() );
    EXPECT_STREQ( "\\'\\\\pass\\\\\\'", component.lookup( CFG_DBPASSWORD ).c_str() );
}

TEST(Configuration, GoodItems)
{
    // Parse a config file with all the known items in it
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "KeyCacheTimeOut = -1" << std::endl;
    ofs << "PolicyCacheTimeOut = -1" << std::endl;
    ofs << "PolicyCacheSizeItems = 3" << std::endl;
    ofs << "MaximumClients = 4" << std::endl;
    ofs << "LocalPortNumber = 5" << std::endl;
    ofs << "RemoteHostAddress = 127.0.0.1" << std::endl;
    ofs << "RemotePortNumber = 6" << std::endl;
    ofs << "APIURL = TEXT7" << std::endl;
    ofs << "CertificatePath = TEXT8" << std::endl;
    ofs << "CertificatePassword = TEXT12" << std::endl;
    ofs << "DBHost = localhost" << std::endl;
    ofs << "DBName = TEXT9" << std::endl;
    ofs << "DBUser = TEXT10" << std::endl;
    ofs << "DBPassword = TEXT11" << std::endl;
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_STREQ( "-1", component.lookup( CFG_KEYCACHETIMEOUT ).c_str() );
    ASSERT_STREQ( "-1", component.lookup( CFG_POLICYCACHETIMEOUT ).c_str() );
    ASSERT_STREQ( "3", component.lookup( CFG_POLICYCACHESIZEITEMS ).c_str() );
    ASSERT_STREQ( "4", component.lookup( CFG_MAXIMUMCLIENTS ).c_str() );
    ASSERT_STREQ( "5", component.lookup( CFG_LOCALPORTNUMBER ).c_str() );
    ASSERT_STREQ( "127.0.0.1", component.lookup( CFG_REMOTEHOSTADDRESS ).c_str() );
    ASSERT_STREQ( "6", component.lookup( CFG_REMOTEPORTNUMBER ).c_str() );
    ASSERT_STREQ( "TEXT7", component.lookup( CFG_APIURL ).c_str() );
    ASSERT_STREQ( "TEXT8", component.lookup( CFG_CERTIFICATEPATH ).c_str() );
    ASSERT_STREQ( "TEXT12", component.lookup( CFG_CERTIFICATEPASSWORD ).c_str() );
    ASSERT_STREQ( "localhost", component.lookup( CFG_DBHOST ).c_str() );
    ASSERT_STREQ( "TEXT9", component.lookup( CFG_DBNAME ).c_str() );
    ASSERT_STREQ( "TEXT10", component.lookup( CFG_DBUSER ).c_str() );
    ASSERT_STREQ( "TEXT11", component.lookup( CFG_DBPASSWORD ).c_str() );
}

TEST(Configuration, LookupAsLong)
{
    // Perform a lookupAsLong on integer values
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "KeyCacheTimeOut = -1" << std::endl;
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_EQ( -1, component.lookupAsLong( CFG_KEYCACHETIMEOUT ) );
}

TEST(Configuration, LookupStringAsLong)
{
    // Perform a lookupAsLong on string values
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "RemoteHostAddress = 127.0.0.1" << std::endl;
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_DEATH( component.lookupAsLong( CFG_REMOTEHOSTADDRESS ),"");
}

TEST(Configuration, DefaultValue)
{
    // Perform a lookup on a defaultable value
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "RemoteHostAddress = 127.0.0.1" << std::endl;
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_EQ( 10, component.lookupAsLong( CFG_SLEEPPERIOD ) );
}

TEST(Configuration, NoDefaultValue)
{
    // Perform a lookup on a non defaultable value
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "SleepPeriod = 1" << std::endl;
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_DEATH( component.lookup( CFG_REMOTEHOSTADDRESS ), "" );
}

TEST(Configuration, ItemExists)
{
    // Parse a config file with all the known items in it
    // Set up the test data
    std::ofstream ofs( "test.conf" );
    ofs << "KeyCacheTimeOut = -1" << std::endl;
    ofs << "PolicyCacheTimeOut = -1" << std::endl;
    ofs << "PolicyCacheSizeItems = 3" << std::endl;
    ofs << "MaximumClients = 4" << std::endl;
    ofs << "LocalPortNumber = 5" << std::endl;
    ofs << "RemoteHostAddress = 127.0.0.1" << std::endl;
    ofs << "RemotePortNumber = 6" << std::endl;
    ofs << "APIURL = TEXT7" << std::endl;
    ofs << "CertificatePath = TEXT8" << std::endl;
    ofs << "DBHost = localhost" << std::endl;
    ofs << "DBName = TEXT9" << std::endl;
    ofs << "DBUser = TEXT10" << std::endl;
    ofs << "DBPassword = TEXT11" << std::endl;
    ofs << "LogFileName = 12" << std::endl;
    ofs << "SysLogHost = 13" << std::endl;
    ofs << "SysLogPort = 14" << std::endl;
    ofs << "AverageProcessingTimeEvery = 15" << std::endl;
    ofs << "MemoryBlockSize = 16" << std::endl;
    ofs << "KeepConnectionBuffers = 17" << std::endl;
    ofs << "SleepPeriod = 18" << std::endl;
    ofs << "TCPInputBufferSize = 19" << std::endl;
    ofs << "TCPOutputBufferSize = 20" << std::endl;
    ofs << "CertificatePassword = TEXT21" << std::endl;
    ofs << "WorkerThreads = 22" << std::endl;
    ofs << "InboundSocketQueueLength = 23" << std::endl;
    ofs << "DAUserID = TEXT24" << std::endl;
    ofs << "DAAPIURL = TEXT25" << std::endl;
    ofs << "DEVICENAME = TEXT26" << std::endl;
    ofs << "APIKey = TEXT27" << std::endl;
    ofs << "APISecret = TEXT28" << std::endl;
    ofs << "Location = CLIENT_SIDE" << std::endl;
    ofs << "Mode = X509" << std::endl;
    ofs << "UseBase64 = 0" << std::endl;
    ofs << "RotateLogAfter = 30" << std::endl;
    ofs.close();
    // Now do the test
    Configuration component;
    ASSERT_TRUE( component.parse( "test.conf" ) );
    ASSERT_TRUE( component.exists( CFG_KEYCACHETIMEOUT ) );
    ASSERT_TRUE( component.exists( CFG_POLICYCACHETIMEOUT ) );
    ASSERT_TRUE( component.exists( CFG_POLICYCACHESIZEITEMS ) );
    ASSERT_TRUE( component.exists( CFG_MAXIMUMCLIENTS ) );
    ASSERT_TRUE( component.exists( CFG_LOCALPORTNUMBER ) );
    ASSERT_TRUE( component.exists( CFG_REMOTEHOSTADDRESS ) );
    ASSERT_TRUE( component.exists( CFG_REMOTEPORTNUMBER ) );
    ASSERT_TRUE( component.exists( CFG_APIURL ) );
    ASSERT_TRUE( component.exists( CFG_CERTIFICATEPATH ) );
    ASSERT_TRUE( component.exists( CFG_DBHOST ) );
    ASSERT_TRUE( component.exists( CFG_DBNAME ) );
    ASSERT_TRUE( component.exists( CFG_DBUSER ) );
    ASSERT_TRUE( component.exists( CFG_DBPASSWORD ) );
    ASSERT_TRUE( component.exists( CFG_LOGFILENAME ) );
    ASSERT_TRUE( component.exists( CFG_SYSLOGHOST ) );
    ASSERT_TRUE( component.exists( CFG_SYSLOGPORT ) );
    ASSERT_TRUE( component.exists( CFG_AVERAGEPROCESSINGTIMEEVERY ) );
    ASSERT_TRUE( component.exists( CFG_MEMORYBLOCKSIZE ) );
    ASSERT_TRUE( component.exists( CFG_KEEPCONNECTIONBUFFERS ) );
    ASSERT_TRUE( component.exists( CFG_SLEEPPERIOD ) );
    ASSERT_TRUE( component.exists( CFG_TCPINPUTBUFFERSIZE ) );
    ASSERT_TRUE( component.exists( CFG_TCPOUTPUTBUFFERSIZE ) );
    ASSERT_TRUE( component.exists( CFG_CERTIFICATEPASSWORD ) );
    ASSERT_TRUE( component.exists( CFG_WORKERTHREADS ) );
    ASSERT_TRUE( component.exists( CFG_INBOUNDSOCKETQUEUELENGTH ) );
    ASSERT_TRUE( component.exists( CFG_DAUSERID ) );
    ASSERT_TRUE( component.exists( CFG_DAAPIURL ) );
    ASSERT_TRUE( component.exists( CFG_DEVICENAME ) );
    ASSERT_TRUE( component.exists( CFG_APIKEY ) );
    ASSERT_TRUE( component.exists( CFG_APISECRET ) );
    ASSERT_TRUE( component.exists( CFG_LOCATION ) );
    ASSERT_TRUE( component.exists( CFG_MODE ) );
    ASSERT_TRUE( component.exists( CFG_USEBASE64 ) );
    ASSERT_TRUE( component.exists( CFG_ROTATELOGAFTER ) );
    ASSERT_FALSE( component.exists( "PortNumber" ) );
}
