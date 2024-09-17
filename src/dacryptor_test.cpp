/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the Device Authority Crypt class
 *
 */
#include "dacryptor.hpp"
#include "gtest/gtest.h"
#include "log.hpp"
#include <iostream>
#include <string>

#define CLEAR_TXT "THIS IS INPUT DATA"
#define CLEAR_TXT_SZ strlen( CLEAR_TXT )

#define CLEAR_TXT2 "THIS IS ALSO INPUT DATA"
#define CLEAR_TXT2_SZ strlen( CLEAR_TXT2 )

#if 1
#define CIPHER_TXT  "s63m9IopRzje81P3w9TepMgmIEP8E1oRSofEwEo2Zng="
#define CIPHER_TXT2 "s63m9IopRzjW8VDtt73UtUrOx0bQXeVC1obgtyovxfs="
#else
#define CIPHER_TXT  "s63m9IopRzje81P3w9TepMgm"
#define CIPHER_TXT2 "s63m9IopRzjW8VDtt73UtUrO"
#endif

#define CIPHER_TXT_SZ strlen( CIPHER_TXT )

TEST(dacryptor, EncryptNoInputData)
{
    // Try to call encrypt without first supplying any input data
    dacryptor component;
    ASSERT_FALSE( component.encrypt() );
}

TEST(dacryptor, EncryptNoKey)
{
    // Try to call encrypt without first supplying a key
    std::string inputData = CLEAR_TXT;
    dacryptor component;
    component.setInputData(inputData);
    ASSERT_FALSE( component.encrypt() );
    
}
//https://asecuritysite.com/encryption/openssl
TEST(dacryptor, EncryptDataIVTooShort)
{
    Log::getInstance()->printf(Log::Debug,"Enter %s:%d ",__func__,__LINE__);    
    // Try to encrypt some data and make sure it is what is expected
    std::string inputData = CLEAR_TXT;
    dacryptor component;
    component.setInputData(inputData);
    std::string iv = "01234567";
    std::string key = "01234567890123456789012345678901";
    component.setInitVector(iv);
    component.setCryptionKey(key);    
    ASSERT_FALSE( component.encrypt() );
    //const unsigned char* output;
    //unsigned int length;
    //component.getCryptedData( output, length );
    //EXPECT_EQ( 24u, length );
    //ASSERT_STREQ( "PdQ6GNnluT+Ut6x6ikqyKDvO", (const char*) output );
    //Log::getInstance()->printf(Log::Debug,"Exit %s:%d ",__func__,__LINE__);
}
TEST(dacryptor, EncryptDataKeyAndIVOK)
{
    // Use correctly sized key and iv
    std::string inputData = CLEAR_TXT;
    dacryptor component;
    component.setInputData(inputData);
    std::string iv = "0123456789ABCDEF";
    std::string key = "01234567890123456789012345678901";
    component.setInitVector(iv);
    component.setCryptionKey(key); 

    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( CIPHER_TXT_SZ, length );
    ASSERT_STREQ( CIPHER_TXT, (const char*) output );
}

TEST(dacryptor, CheckEncryptedCache)
{
    // Try to get the encrypted data out and then again to check the cache works
    std::string inputData = CLEAR_TXT;
    dacryptor component;
    component.setInputData(inputData);
    std::string iv = "0123456789ABCDEF";
    std::string key = "01234567890123456789012345678901";
    component.setInitVector(iv);
    component.setCryptionKey(key); 

    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( CIPHER_TXT_SZ, length );
    EXPECT_STREQ( CIPHER_TXT, (const char*) output );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( length, length2 );
    ASSERT_EQ( (const char*) output, (const char*) output2);
}

TEST(dacryptor, CheckEncryptedCache2)
{
    // Encrypt and then again to check that cache works
    std::string inputData = CLEAR_TXT;
    dacryptor component;
    component.setInputData(inputData);
    std::string iv = "0123456789ABCDEF";
    std::string key = "01234567890123456789012345678901";
    component.setInitVector(iv);
    component.setCryptionKey(key); 

    Log::getInstance()->printf(Log::Debug," First %s:%d  ",__func__,__LINE__);        
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( CIPHER_TXT_SZ, length );
    EXPECT_STREQ( CIPHER_TXT, (const char*) output );
    
    Log::getInstance()->printf(Log::Debug," Second %s:%d  ",__func__,__LINE__);        
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( length, length2 );
    ASSERT_EQ( (const char*) output, (const char*) output2);
}

TEST(dacryptor, CheckEncCacheMadeStale)
{
    // Try to get the encrypted data out and then change key to check the cache works
    std::string inputData = CLEAR_TXT;
    dacryptor component;
    component.setInputData(inputData);
 
    std::string iv = "0123456789ABCDEF";
    std::string key = "01234567890123456789012345678901";
    component.setInitVector(iv);
    component.setCryptionKey(key); 

    EXPECT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( CIPHER_TXT_SZ, length );
    EXPECT_STREQ( CIPHER_TXT, (const char*) output );
    
    std::string key2 = "ABCDEFABCDEFABCDEFABCDEFABCDEFAB";
    component.setCryptionKey(key2); 
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( CIPHER_TXT_SZ, length2 );
    ASSERT_STRNE( CIPHER_TXT, (const char*) output2 );
}

TEST(dacryptor, DecryptNoInputData)
{
  Log::getInstance()->printf(Log::Debug," %s:%d  Try to call decrypt without first supplying any input data ",__func__,__LINE__);        
    // Try to call decrypt without first supplying any input data
    dacryptor component;
    ASSERT_FALSE( component.decrypt() );
}

TEST(dacryptor, DecryptNoKey)
{
    // Try to call decrypt without first supplying a key
    std::string inputData = "CB95592149EB5B50E58CF8230C4F96E1BE340D";
    dacryptor component;
    component.setInputData(inputData);
    ASSERT_FALSE( component.decrypt() );
}

TEST(dacryptor, DecryptData)
{
    // Try to decrypt some data and make sure it is what is expected
    std::string inputData = CIPHER_TXT;
    dacryptor component;
    component.setInputData(inputData);
    std::string iv = "0123456789ABCDEF";
    std::string key = "01234567890123456789012345678901";
    component.setInitVector(iv);
    component.setCryptionKey(key); 

    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( CLEAR_TXT_SZ, length );
    ASSERT_STREQ( CLEAR_TXT, (const char*) output );
}

TEST(dacryptor, CheckDecryptedCache)
{
    // Try to get the decrypted data out and then again to check the cache works
    std::string inputData = CIPHER_TXT;
    dacryptor component;
    component.setInputData(inputData);
 
    std::string iv = "0123456789ABCDEF";
    std::string key = "01234567890123456789012345678901";
    component.setInitVector(iv);
    component.setCryptionKey(key); 

    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( CLEAR_TXT_SZ, length );
    EXPECT_STREQ( CLEAR_TXT, (const char*) output );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( length, length2 );
    ASSERT_EQ( (const char*) output, (const char*) output2);
}


TEST(dacryptor, CheckDecryptedCache2)
{
    // Decrypt and then again to check that cache works
    std::string inputData = CIPHER_TXT;
    dacryptor component;
    component.setInputData(inputData);

    std::string iv = "0123456789ABCDEF";
    std::string key = "01234567890123456789012345678901";
    component.setInitVector(iv);
    component.setCryptionKey(key); 

    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( CLEAR_TXT_SZ, length );
    EXPECT_STREQ( CLEAR_TXT, (const char*) output );
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( length, length2 );
    ASSERT_EQ( (const char*) output, (const char*) output2);
}

TEST(dacryptor, CheckDecCacheMadeStale)
{
    // Try to get the decrypted data out and then change data to check the cache works
    std::string inputData = CIPHER_TXT;
    dacryptor component;
    component.setInputData(inputData);

    std::string iv = "0123456789ABCDEF";
    std::string key = "01234567890123456789012345678901";
    component.setInitVector(iv);
    component.setCryptionKey(key); 

    EXPECT_TRUE( component.decrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( CLEAR_TXT_SZ, length );
    EXPECT_STREQ( CLEAR_TXT, (const char*) output );
    std::string  inputData2 = CIPHER_TXT2;
    component.setInputData(inputData2);
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( CLEAR_TXT2_SZ, length2 );
    ASSERT_STREQ( CLEAR_TXT2, (const char*) output2 );
}

TEST(dacryptor, CheckCacheMadeStale)
{
    // Try to encrypt and then decrypt with the same object to check the cache works  
    std::string inputData = CLEAR_TXT;
    dacryptor component;
    component.setInputData(inputData);
    std::string iv = "0123456789ABCDEF";
    std::string key = "01234567890123456789012345678901";
    component.setInitVector(iv);
    component.setCryptionKey(key); 
    
    EXPECT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( CIPHER_TXT_SZ, length );
    EXPECT_STREQ( CIPHER_TXT, (const char*) output );
    std::string encryptedStr;
    encryptedStr.assign((const char*)output,length	);
    component.setInputData(encryptedStr);
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( inputData.size(), length2 );
    ASSERT_STREQ( inputData.c_str(), (const char*) output2 );
}
