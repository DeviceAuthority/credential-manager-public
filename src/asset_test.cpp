/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the asset class
 *
 */

#include "asset_manager.hpp"
//#include "cryptosoftcrypt.hpp"
//#include "cryptosoftjson.hpp"
#include "base64.h"
#include "log.hpp"
#include "gtest/gtest.h"
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <pthread.h>
#include <iomanip>
#include <fstream>
#include <string>

using namespace deviceauthority;

#define RMLOG system( "rm -f BadAssetData.log" );

// The testing key and iv are found in the deviceauthority.cpp file
std::string ddkkeyId = "cd32f3d3-f0cc-467f-9114-e4942c54fddc";
std::string ddkkey = "9Hsg5f8lYtP3yMLSRc87uI2eOqtt8+IXi9PflbQrbGs=";
std::string ddkiv = "gTuPbfh2GnD3Z8x9wz+51w==";
std::string daJSON = "testing";
std::string APIURL = "https://localhost:8444/";

// These are both used only by the test harness to induce behavour.
unsigned short c;

void resetEnv( void )
{
    c = 0;
}

void writeOutDataFile( int type )
{
    std::ofstream os( "testdata" );
    switch (type)
    {
        case 1:
            os << "{\"message\":{\"errorMessage\":\"There was an error\"}";
            break;
        case 2:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[]}";
            break;
        case 3:
        case 4:
        case 20:
            {
                os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"certificate\",\"filePath\":\"";
                if (type==20) os << "/etc/junk"; else os << "./cert";
                os << "\",\"storeEncrypted\":";
                if (type==3) os << "false"; else os << "true";
                os << ",\"certificate\":\"";
                // This is the test certificate and key
                std::string cert = "THISISTHECERTIFICATE";
                std::string privkey = "THISISTHEPRIVATEKEY";
                // They need to be encrypted to the key/iv that the ddk will have.
                cryptosoft::CryptosoftCrypt cryptor;
                // The testing key (found in the deviceauthority.cpp file) is base64 encoded
                // so must be decoded before it is used.
                unsigned char decoded[1024];
                unsigned int decodedlen = base64Decode( ddkkey.c_str(), decoded, 1024 );
                assert( decodedlen == 32 );
                cryptor.setCryptionKey( (const unsigned char*) decoded, decodedlen );
                // The testing iv (found in the deviceauthority.cpp file) is base64 encoded
                // so must be decoded before it is used.
                decodedlen = base64Decode( ddkiv.c_str(), decoded, 1024 );
                assert( decodedlen == 16 );
                cryptor.setInitVector( (const unsigned char*) decoded, decodedlen );
                // Pass in the cert to be encrypted.
                cryptor.setInputData( (const unsigned char*) cert.c_str(), cert.length() );
                if (cryptor.encrypt())
                {
                    // It has encrypted ok
                    const unsigned char* output = 0;
                    unsigned int length = 0;
                    cryptor.getCryptedData( output, length );
                    std::string enccert( (const char*) output, length );
                    os << enccert << "\",\"privateKey\":\"";
                }
                // Pass in the priv key to be encrypted.
                cryptor.setInputData( (const unsigned char*) privkey.c_str(), privkey.length() );
                if (cryptor.encrypt())
                {
                    // It has encrypted ok
                    const unsigned char* output = 0;
                    unsigned int length = 0;
                    cryptor.getCryptedData( output, length );
                    std::string encprivkey( (const char*) output, length );
                    os << encprivkey << "\"}]}";
                }
            }
            break;
        case 5:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"certificate\",\"filePath\":\"./cert\",\"storeEncrypted\":false}]}";
            break;
        case 6:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"certificate\",\"filePath\":\"./cert\",\"storeEncrypted\":false,\"certificate\":\"CERT\"}]}";
            break;
        case 7:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":null,\"assetType\":\"certificate\",\"filePath\":\"./cert\",\"storeEncrypted\":false,\"certificate\":\"CERT\",\"privateKey\":\"KEY\"}]}";
            break;
        case 8:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetType\":\"certificate\",\"filePath\":\"./cert\",\"storeEncrypted\":false,\"certificate\":\"CERT\",\"privateKey\":\"KEY\"}]}";
            break;
        case 9:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"config\",\"filePath\":\"./cert\",\"storeEncrypted\":false,\"certificate\":\"CERT\",\"privateKey\":\"KEY\"}]}";
            break;
        case 10:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"\",\"filePath\":\"./cert\",\"storeEncrypted\":false,\"certificate\":\"CERT\",\"privateKey\":\"KEY\"}]}";
            break;
        case 11:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"filePath\":\"./cert\",\"storeEncrypted\":false,\"certificate\":\"CERT\",\"privateKey\":\"KEY\"}]}";
            break;
        case 12:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"certificate\",\"filePath\":null,\"storeEncrypted\":false,\"certificate\":\"CERT\",\"privateKey\":\"KEY\"}]}";
            break;
        case 13:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"certificate\",\"storeEncrypted\":false,\"certificate\":\"CERT\",\"privateKey\":\"KEY\"}]}";
            break;
        case 14:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"certificate\",\"filePath\":\"./cert\",\"storeEncrypted\":null,\"certificate\":\"CERT\",\"privateKey\":\"KEY\"}]}";
            break;
        case 15:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"certificate\",\"filePath\":\"./cert\",\"certificate\":\"CERT\",\"privateKey\":\"KEY\"}]}";
            break;
        case 16:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"certificate\",\"filePath\":\"./cert\",\"storeEncrypted\":false,\"certificate\":null,\"privateKey\":\"KEY\"}]}";
            break;
        case 17:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"certificate\",\"filePath\":\"./cert\",\"storeEncrypted\":false,\"privateKey\":\"KEY\"}]}";
            break;
        case 18:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"certificate\",\"filePath\":\"./cert\",\"storeEncrypted\":false,\"certificate\":\"CERT\",\"privateKey\":null}]}";
            break;
        case 19:
            os << "{\"message\":{\"authenticated\":true},\"assets\":[{\"assetId\":\"ASSETID\",\"assetType\":\"certificate\",\"filePath\":\"./cert\",\"storeEncrypted\":false,\"certificate\":\"CERT\"}]}";
            break;
    }
    os.close();
}

TEST(CryptosoftAsset, ServerError)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 1 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );

    EXPECT_FALSE( processAnyAssets( json, newkey, newiv, ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No assets found (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, NoAssetsReturned)
{
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    writeOutDataFile( 2 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_TRUE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, AssetsReturnedUnEnc)
{
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    writeOutDataFile( 3 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_TRUE( processAnyAssets( json, newkey, newiv,ddkkeyId ) );
    std::ifstream ifsc( "./cert.cert" ); //append ".cert" for certificate name and ".pem" to the privateKey name
    EXPECT_TRUE( ifsc.good() );
    std::string line;
    ifsc >> line;
    EXPECT_STREQ( "THISISTHECERTIFICATE", line.c_str() );
    ifsc >> line;
    EXPECT_STREQ( "THISISTHEPRIVATEKEY", line.c_str() );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, AssetsReturnedEnc)
{
    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    writeOutDataFile( 4 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_TRUE( processAnyAssets( json, newkey, newiv ,ddkkeyId) );
    std::ifstream ifsc( "./cert.cert" );
    EXPECT_TRUE( ifsc.good() );
    std::string line;
    ifsc >> line;
    EXPECT_STRNE( "THISISTHECERTIFICATE", line.c_str() );
    ifsc >> line;
    EXPECT_STRNE( "THISISTHEPRIVATEKEY", line.c_str() );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned1)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
   cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 5 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No certificate specified (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned2)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 6 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No key specified to decrypt private key") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned3)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 7 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No asset identifier specified (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned4)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 8 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No assetId found (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned5)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 9 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv  ,ddkkeyId) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("Unknown asset type \"config\" encountered, ignoring") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned6)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 10 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No asset type specified (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned7)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 11 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No assetType found (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned8)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 12 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No file path specified (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned9)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 13 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No file path specified (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned10)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 14 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No store encrypted flag specified (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned11)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 15 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No storeEncrypted found (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned12)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 16 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No certificate specified (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned13)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 17 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No certificate specified (was expected)") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned14)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 18 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No key specified to decrypt private key") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, BadAssetDataReturned15)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 19 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("No key specified to decrypt private key") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

TEST(CryptosoftAsset, AssetsReturnedCantWrite)
{
    // Remove any old log file first
    RMLOG

    resetEnv();

    // Start the json server to test against
    system( "./testjsonserver testdata &" );
    sleep( 2 );

    // Need to capture error message for this test.
    cryptosoft::logger.initialise( "asset_test", "BadAssetData.log" );

    writeOutDataFile( 20 );

    cryptosoft::CryptosoftJSON json( 6, "TestUserAgent" );
    json.setSSLCert( "testpublic.cer", 14 );
    int jsonrc = json.post( (APIURL + "auth").c_str(), daJSON.c_str() );
    ASSERT_EQ(0, jsonrc);
    unsigned char key[1024];
    unsigned int keylen = base64Decode( ddkkey.c_str(), key, 1024 );
    ASSERT_EQ(32u, keylen);
    std::string newkey( (char*) key, keylen );
    unsigned char iv[1024];
    unsigned int ivlen = base64Decode( ddkiv.c_str(), iv, 1024 );
    ASSERT_EQ(16u, ivlen);
    std::string newiv( (char*) iv, ivlen );
    EXPECT_FALSE( processAnyAssets( json, newkey, newiv ,ddkkeyId ) );

    // Set logging back to screen again
    cryptosoft::logger.initialise( "asset_test", "" );

    // Check required message appears in the log file.
    std::ifstream ifsc( "BadAssetData.log" );
    ASSERT_TRUE( ifsc.good() );
    std::string line;
#ifdef DEBUG // Two extra lines appear in debug build
    getline( ifsc, line );
    getline( ifsc, line );
#endif
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    getline( ifsc, line );
    EXPECT_NE( std::string::npos, line.find("Problem writing to file path") );
    ifsc.close();

    // Stop the json server
    system( "killall -2 testjsonserver" );
    sleep( 1 );
}

