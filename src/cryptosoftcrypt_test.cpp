/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the Device Authority Crypt class
 *
 */
#include "dacryptor.hpp"
#include "gtest/gtest.h"
#include <iostream>
#include <string>

using namespace cryptosoft;

TEST(CryptosoftCrypt, EncryptNoInputData)
{
    // Try to call encrypt without first supplying any input data
    CryptosoftCrypt component;
    ASSERT_FALSE( component.encrypt() );
}

TEST(CryptosoftCrypt, EncryptNoKey)
{
    // Try to call encrypt without first supplying a key
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    ASSERT_FALSE( component.encrypt() );
}

TEST(CryptosoftCrypt, EncryptData)
{
    // Try to encrypt some data and make sure it is what is expected
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setCryptionKeyPassphrase( "TESTKEY" );
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 28u, length );
    ASSERT_STREQ( "y5VZIUnrW1DljPgjDE+W4b40DQ==", (const char*) output );
}

TEST(CryptosoftCrypt, EncryptDataIVTooShort)
{
    // Try to set an Initialisation Vector that is < 16 bytes.
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setInitVector( (const unsigned char*) "01234567", 8 );
    component.setCryptionKey( (const unsigned char*) "01234567890123456789012345678901", 32 );
    ASSERT_FALSE( component.encrypt() );
}

TEST(CryptosoftCrypt, EncryptDataIVTooLong)
{
    // Try to set an Initialisation Vector that is > 16 bytes.
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setInitVector( (const unsigned char*) "0123456789ABCDEFGH", 18 );
    component.setCryptionKey( (const unsigned char*) "01234567890123456789012345678901", 32 );
    ASSERT_FALSE( component.encrypt() );
}

TEST(CryptosoftCrypt, EncryptDataKeyTooShort)
{
    // Try to set a key that is < 128 bits.
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setInitVector( (const unsigned char*) "0123456789ABCDEF", 16 );
    component.setCryptionKey( (const unsigned char*) "012345678901234", 15 );
    ASSERT_FALSE( component.encrypt() );
}

TEST(CryptosoftCrypt, EncryptDataKeyTooLong)
{
    // Try to set a key that is > 256 bits.
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setInitVector( (const unsigned char*) "0123456789ABCDEF", 16 );
    component.setCryptionKey( (const unsigned char*) "0123456789012345678901234567890123456789", 40 );
    ASSERT_FALSE( component.encrypt() );
}

TEST(CryptosoftCrypt, EncryptDataKeyAndIVOK)
{
    // Use correctly sized key and iv
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setInitVector( (const unsigned char*) "0123456789ABCDEF", 16 );
    component.setCryptionKey( (const unsigned char*) "01234567890123456789012345678901", 32 );
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 28u, length );
    ASSERT_STREQ( "s63m9IopRzje81P3w9TepMgmLg==", (const char*) output );
}

TEST(CryptosoftCrypt, EncryptDataBadIV)
{
    // Use badly sized iv
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setInitVector( (const unsigned char*) "0123456789ABCDE", 15 );
    component.setCryptionKey( (const unsigned char*) "01234567890123456789012345678901", 32 );
    ASSERT_FALSE( component.encrypt() );
}

TEST(CryptosoftCrypt, CheckEncryptedCache)
{
    // Try to get the encrypted data out and then again to check the cache works
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setCryptionKeyPassphrase( "TESTKEY" );
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 28u, length );
    EXPECT_STREQ( "y5VZIUnrW1DljPgjDE+W4b40DQ==", (const char*) output );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( length, length2 );
    ASSERT_EQ( (const char*) output, (const char*) output2);
}

TEST(CryptosoftCrypt, CheckEncryptedCache2)
{
    // Encrypt and then again to check that cache works
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setCryptionKeyPassphrase( "TESTKEY" );
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 28u, length );
    EXPECT_STREQ( "y5VZIUnrW1DljPgjDE+W4b40DQ==", (const char*) output );
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( length, length2 );
    ASSERT_EQ( (const char*) output, (const char*) output2);
}

TEST(CryptosoftCrypt, CheckEncCacheMadeStale)
{
    // Try to get the encrypted data out and then change key to check the cache works
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setCryptionKeyPassphrase( "TESTKEY" );
    EXPECT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 28u, length );
    EXPECT_STREQ( "y5VZIUnrW1DljPgjDE+W4b40DQ==", (const char*) output );
    component.setCryptionKeyPassphrase( "TESTKEY2" );
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( 28u, length2 );
    ASSERT_STREQ( "kFewZoEJKtvDvEMmgeFvF+v1nw==", (const char*) output2 );
}

TEST(CryptosoftCrypt, DecryptNoInputData)
{
    // Try to call decrypt without first supplying any input data
    CryptosoftCrypt component;
    ASSERT_FALSE( component.decrypt() );
}

TEST(CryptosoftCrypt, DecryptNoKey)
{
    // Try to call decrypt without first supplying a key
    const char inputData[] = "CB95592149EB5B50E58CF8230C4F96E1BE340D";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    ASSERT_FALSE( component.decrypt() );
}

TEST(CryptosoftCrypt, DecryptData)
{
    // Try to decrypt some data and make sure it is what is expected
    const char inputData[] = "y5VZIUnrW1DljPgjDE+W4b40DQ==";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setCryptionKeyPassphrase( "TESTKEY" );
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 19u, length );
    ASSERT_STREQ( "THIS IS INPUT DATA", (const char*) output );
}

TEST(CryptosoftCrypt, CheckDecryptedCache)
{
    // Try to get the decrypted data out and then again to check the cache works
    const char inputData[] = "y5VZIUnrW1DljPgjDE+W4b40DQ==";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setCryptionKeyPassphrase( "TESTKEY" );
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 19u, length );
    EXPECT_STREQ( "THIS IS INPUT DATA", (const char*) output );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( length, length2 );
    ASSERT_EQ( (const char*) output, (const char*) output2);
}

TEST(CryptosoftCrypt, CheckDecryptedCache2)
{
    // Decrypt and then again to check that cache works
    const char inputData[] = "y5VZIUnrW1DljPgjDE+W4b40DQ==";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setCryptionKeyPassphrase( "TESTKEY" );
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 19u, length );
    EXPECT_STREQ( "THIS IS INPUT DATA", (const char*) output );
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( length, length2 );
    ASSERT_EQ( (const char*) output, (const char*) output2);
}

TEST(CryptosoftCrypt, CheckDecCacheMadeStale)
{
    // Try to get the decrypted data out and then change data to check the cache works
    const char inputData[] = "y5VZIUnrW1DljPgjDE+W4b40DQ==";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setCryptionKeyPassphrase( "TESTKEY" );
    EXPECT_TRUE( component.decrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 19u, length );
    EXPECT_STREQ( "THIS IS INPUT DATA", (const char*) output );
    const char inputData2[] = "y5VZIUnrW1Dtjvs5eCac8AKbfgfoY8j+";
    component.setInputData( (const unsigned char*) inputData2, sizeof(inputData2) );
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( 24u, length2 );
    ASSERT_STREQ( "THIS IS ALSO INPUT DATA", (const char*) output2 );
}

TEST(CryptosoftCrypt, CheckCacheMadeStale)
{
    // Try to encrypt and then decrypt with the same object to check the cache works
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component;
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    component.setCryptionKeyPassphrase( "TESTKEY" );
    EXPECT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 28u, length );
    EXPECT_STREQ( "y5VZIUnrW1DljPgjDE+W4b40DQ==", (const char*) output );
    component.setInputData( (const unsigned char*) output, length );
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( sizeof(inputData), length2 );
    ASSERT_STREQ( inputData, (const char*) output2 );
}

TEST(CryptosoftCrypt, CertEncryptNoInputData)
{
    // Try to call encrypt without first supplying any input data
    CryptosoftCrypt component( true );
    ASSERT_FALSE( component.encrypt() );
}

TEST(CryptosoftCrypt, CertEncryptNoCert)
{
    // Try to call encrypt without first supplying a key
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component( true );
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    ASSERT_FALSE( component.encrypt() );
}

TEST(CryptosoftCrypt, CertEncryptData)
{
    // Try to encrypt some data with a certificate and make sure it is what is expected
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component( true );
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    const char* certificate = "MIICszCCAhwCCQDK09hPYZtveTANBgkqhkiG9w0BAQsFADCBnTELMAkGA1UEBhMC\r\n"
                              "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                              "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                              "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                              "b20wHhcNMTYwNDE5MDc1NDQ1WhcNMTcwNDE5MDc1NDQ1WjCBnTELMAkGA1UEBhMC\r\n"
                              "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                              "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                              "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                              "b20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMnN0xwL4FnLXL0WfuHCS4uK\r\n"
                              "qbo5Uee5+lLeeoFH7uRzVFI4Vx0wRo36BOxJRhpi09g9maBpU6cSGn8bA5gFKRgI\r\n"
                              "F/XYmuVCxL1452lH87N3MZvYvAN+ozgyOsQA9vIZPqu2E5gxfoQJgE9/ISXHnI4O\r\n"
                              "BLgurEK//ByOMFouPJpJAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAmE+llTIc7nG5\r\n"
                              "3V1VzS6/SW36gBT5JX52L8G+Xyse2bxf4XmMpL7WbxhBuY6zdr5Dgapki9I0f9oi\r\n"
                              "5QMWDNX2YDRE6WQuiZJSXv/1B1VlG/7mkiIZupC98ik0v4ufdi5JQhW6M3FmVnag\r\n"
                              "RKp29NSBiNlSwNMxdLnVvcbbMCO86JM=\r\n";
    component.setEncryptionCertificate( certificate, strlen( certificate ) );
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    ASSERT_EQ( 0, strncmp( "MIIBtg", (const char*) output, 6 ) );
}

TEST(CryptosoftCrypt, CheckCertEncryptedCache)
{
    // Try to get the encrypted data out and then again to check the cache works
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component( true );
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    const char* certificate = "MIICszCCAhwCCQDK09hPYZtveTANBgkqhkiG9w0BAQsFADCBnTELMAkGA1UEBhMC\r\n"
                              "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                              "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                              "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                              "b20wHhcNMTYwNDE5MDc1NDQ1WhcNMTcwNDE5MDc1NDQ1WjCBnTELMAkGA1UEBhMC\r\n"
                              "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                              "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                              "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                              "b20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMnN0xwL4FnLXL0WfuHCS4uK\r\n"
                              "qbo5Uee5+lLeeoFH7uRzVFI4Vx0wRo36BOxJRhpi09g9maBpU6cSGn8bA5gFKRgI\r\n"
                              "F/XYmuVCxL1452lH87N3MZvYvAN+ozgyOsQA9vIZPqu2E5gxfoQJgE9/ISXHnI4O\r\n"
                              "BLgurEK//ByOMFouPJpJAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAmE+llTIc7nG5\r\n"
                              "3V1VzS6/SW36gBT5JX52L8G+Xyse2bxf4XmMpL7WbxhBuY6zdr5Dgapki9I0f9oi\r\n"
                              "5QMWDNX2YDRE6WQuiZJSXv/1B1VlG/7mkiIZupC98ik0v4ufdi5JQhW6M3FmVnag\r\n"
                              "RKp29NSBiNlSwNMxdLnVvcbbMCO86JM=\r\n";
    component.setEncryptionCertificate( certificate, strlen( certificate ) );
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 610u, length );
    ASSERT_EQ( 0, strncmp( "MIIBtg", (const char*) output, 6 ) );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( length, length2 );
    ASSERT_STREQ( (const char*) output, (const char*) output2);
}

TEST(CryptosoftCrypt, CheckCertEncCacheMadeStale)
{
    // Try to get the encrypted data out and then change key to check the cache works
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component( true );
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    const char* certificate = "MIICszCCAhwCCQDK09hPYZtveTANBgkqhkiG9w0BAQsFADCBnTELMAkGA1UEBhMC\r\n"
                              "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                              "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                              "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                              "b20wHhcNMTYwNDE5MDc1NDQ1WhcNMTcwNDE5MDc1NDQ1WjCBnTELMAkGA1UEBhMC\r\n"
                              "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                              "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                              "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                              "b20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMnN0xwL4FnLXL0WfuHCS4uK\r\n"
                              "qbo5Uee5+lLeeoFH7uRzVFI4Vx0wRo36BOxJRhpi09g9maBpU6cSGn8bA5gFKRgI\r\n"
                              "F/XYmuVCxL1452lH87N3MZvYvAN+ozgyOsQA9vIZPqu2E5gxfoQJgE9/ISXHnI4O\r\n"
                              "BLgurEK//ByOMFouPJpJAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAmE+llTIc7nG5\r\n"
                              "3V1VzS6/SW36gBT5JX52L8G+Xyse2bxf4XmMpL7WbxhBuY6zdr5Dgapki9I0f9oi\r\n"
                              "5QMWDNX2YDRE6WQuiZJSXv/1B1VlG/7mkiIZupC98ik0v4ufdi5JQhW6M3FmVnag\r\n"
                              "RKp29NSBiNlSwNMxdLnVvcbbMCO86JM=\r\n";
    component.setEncryptionCertificate( certificate, strlen( certificate ) );
    EXPECT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 610u, length );
    ASSERT_EQ( 0, strncmp( "MIIBtg", (const char*) output, 6 ) );
    certificate = "MIIDsDCCApigAwIBAgIEVcHqFjANBgkqhkiG9w0BAQsFADCBmTEqMCgGCSqGSIb3\r\n"
                  "DQEJARYbamFtZXMucGVubmV5QGNyeXB0b3NvZnQuY29tMQswCQYDVQQGEwJHQjEN\r\n"
                  "MAsGA1UECAwET3hvbjEZMBcGA1UEBwwQSGVubGV5LW9uLVRoYW1lczEXMBUGA1UE\r\n"
                  "CgwOQ3J5cHRvc29mdCBMdGQxCzAJBgNVBAsMAklUMQ4wDAYDVQQDDAVhZG1pbjAe\r\n"
                  "Fw0xNTA4MDUxMDQ5MTdaFw0xODA4MDUxMDQ5MTdaMIGZMSowKAYJKoZIhvcNAQkB\r\n"
                  "FhtqYW1lcy5wZW5uZXlAY3J5cHRvc29mdC5jb20xCzAJBgNVBAYTAkdCMQ0wCwYD\r\n"
                  "VQQIDARPeG9uMRkwFwYDVQQHDBBIZW5sZXktb24tVGhhbWVzMRcwFQYDVQQKDA5D\r\n"
                  "cnlwdG9zb2Z0IEx0ZDELMAkGA1UECwwCSVQxDjAMBgNVBAMMBWFkbWluMIIBIjAN\r\n"
                  "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAivHr+xMDh2WRvFGzgWHShXHpukZp\r\n"
                  "M1Obd+uGAmhwLTtn1k7cs4Dv1nzhujFoj3O86DkiUH2KGJaA/R7PcG8YrC2YYXdA\r\n"
                  "cNVP4oUANRiauC9d9W3JQcuzAzs6wAk4u3uJKA9+8sqh55SqhVyPIQOS/KgmdMgH\r\n"
                  "T+d4hVaXx91kFbXWqtUv0AaIB302EBAZqwmLIa6/90P9/+4gMc7J7+SOiRM2qua7\r\n"
                  "nhz6wq1zAvu/U1szPIkRjaFndSr28AXGuxEP8reAQkmCsk4jZclkHz3v/ZTsJx3s\r\n"
                  "YSZkyJ5BS4Cg0ENelNmy3h+TQzRBpNqo5lRZHhnzbydUAVdqfGveua9l5QIDAQAB\r\n"
                  "MA0GCSqGSIb3DQEBCwUAA4IBAQAQ6epqaHMO+Q+pTKTDIJnKUI3ykMaLC5E9rCHQ\r\n"
                  "NL2dZP5ETXx8+hWyFQPsKEBPcVnkj9n8ZUOqgZ9M8Sr+pR/iQkk5QetuoIfHxoJd\r\n"
                  "nihoLrGZIhtsoYhYxuAfxgkqREVIhcIHJXLIliqTR1wrpHpazP+xd0hdqj5LfkCx\r\n"
                  "bpa4CtdlDnbgWxjt1r1PzR/fYGV0VDDXAhtYTipK0Bk8w0nsEp7xLpRLlXco/Jzd\r\n"
                  "r80fUGj2zdVKEpXYEhX3wKGvMHtLklVMmSoqy8M3K23empBctI4r6lt8eP+dlWfO\r\n"
                  "msFD5tW6VBT//Lad8F5/G6mywzzSQCm84MPkKUrSuIrjHza6";
    component.setEncryptionCertificate( certificate, strlen( certificate ) );
    component.setInputData( output, length );
    ASSERT_TRUE( component.encrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( 0, strncmp( "MII", (const char*) output2, 3 ) );
    ASSERT_EQ( 2252u, length2 );
}

TEST(CryptosoftCrypt, CertDecryptNoInputData)
{
    // Try to call decrypt without first supplying any input data
    CryptosoftCrypt component( true );
    ASSERT_FALSE( component.decrypt() );
}

TEST(CryptosoftCrypt, CertDecryptNoKey)
{
    // Try to call decrypt without first supplying a key
    const char inputData[] = "MIIBtgYJKoZIhvcNAQcDoIIBpzCCAaMCAQAxggFHMIIBQwIBADCBqzCBnTELMAkG\r\n"
                             "A1UEBhMCR0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxs\r\n"
                             "MRcwFQYDVQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQx\r\n"
                             "EDAOBgNVBAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRv\r\n"
                             "c29mdC5jb20CCQDK09hPYZtveTANBgkqhkiG9w0BAQEFAASBgD2WMW2IP/WoIsxv\r\n"
                             "WGUKudrHn0ReoxiPGezir93tHMVojiFYoyUTUH8u7N/GmgUYvgueIFx8qiF1oCRx\r\n"
                             "p2FgHW76lgcEhHN9wnidKHpiEThhaemYUDE3cbMn3FwkPV9i/umdNvdDcl61jD2A\r\n"
                             "KOaInPgXwGGUNkEuzFtbdl3PKOCQMFMGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQI\r\n"
                             "EN18qif3PEOAMB7qTw40mM2OdQpBUbMWc4PtjJ0duRefuGtEbtJqqedXaNGDdK/0\r\n"
                             "dPIo1/K6EVjaPw==";
    CryptosoftCrypt component( true );
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    ASSERT_FALSE( component.decrypt() );
}

TEST(CryptosoftCrypt, CertDecryptData)
{
    // Try to decrypt some data with a certificate and make sure it is what is expected
    const char inputData[] = "MIIBtgYJKoZIhvcNAQcDoIIBpzCCAaMCAQAxggFHMIIBQwIBADCBqzCBnTELMAkG\r\n"
                             "A1UEBhMCR0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxs\r\n"
                             "MRcwFQYDVQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQx\r\n"
                             "EDAOBgNVBAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRv\r\n"
                             "c29mdC5jb20CCQDK09hPYZtveTANBgkqhkiG9w0BAQEFAASBgD2WMW2IP/WoIsxv\r\n"
                             "WGUKudrHn0ReoxiPGezir93tHMVojiFYoyUTUH8u7N/GmgUYvgueIFx8qiF1oCRx\r\n"
                             "p2FgHW76lgcEhHN9wnidKHpiEThhaemYUDE3cbMn3FwkPV9i/umdNvdDcl61jD2A\r\n"
                             "KOaInPgXwGGUNkEuzFtbdl3PKOCQMFMGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQI\r\n"
                             "EN18qif3PEOAMB7qTw40mM2OdQpBUbMWc4PtjJ0duRefuGtEbtJqqedXaNGDdK/0\r\n"
                             "dPIo1/K6EVjaPw==";
    CryptosoftCrypt component( true );
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    const char* pem = "-----BEGIN CERTIFICATE-----\r\n"
                      "MIICszCCAhwCCQDK09hPYZtveTANBgkqhkiG9w0BAQsFADCBnTELMAkGA1UEBhMC\r\n"
                      "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                      "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                      "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                      "b20wHhcNMTYwNDE5MDc1NDQ1WhcNMTcwNDE5MDc1NDQ1WjCBnTELMAkGA1UEBhMC\r\n"
                      "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                      "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                      "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                      "b20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMnN0xwL4FnLXL0WfuHCS4uK\r\n"
                      "qbo5Uee5+lLeeoFH7uRzVFI4Vx0wRo36BOxJRhpi09g9maBpU6cSGn8bA5gFKRgI\r\n"
                      "F/XYmuVCxL1452lH87N3MZvYvAN+ozgyOsQA9vIZPqu2E5gxfoQJgE9/ISXHnI4O\r\n"
                      "BLgurEK//ByOMFouPJpJAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAmE+llTIc7nG5\r\n"
                      "3V1VzS6/SW36gBT5JX52L8G+Xyse2bxf4XmMpL7WbxhBuY6zdr5Dgapki9I0f9oi\r\n"
                      "5QMWDNX2YDRE6WQuiZJSXv/1B1VlG/7mkiIZupC98ik0v4ufdi5JQhW6M3FmVnag\r\n"
                      "RKp29NSBiNlSwNMxdLnVvcbbMCO86JM=\r\n"
                      "-----END CERTIFICATE-----\r\n"
                      "-----BEGIN RSA PRIVATE KEY-----\r\n"
                      "MIICWwIBAAKBgQDJzdMcC+BZy1y9Fn7hwkuLiqm6OVHnufpS3nqBR+7kc1RSOFcd\r\n"
                      "MEaN+gTsSUYaYtPYPZmgaVOnEhp/GwOYBSkYCBf12JrlQsS9eOdpR/OzdzGb2LwD\r\n"
                      "fqM4MjrEAPbyGT6rthOYMX6ECYBPfyElx5yODgS4LqxCv/wcjjBaLjyaSQIDAQAB\r\n"
                      "AoGAGSXsI/ea6rW8BdhS0YFr9qS+B/XyrgTwG/mbnJbBP3jbzi81M+77K+A3UtbC\r\n"
                      "xLECI1Vx2pqlkRFheet85Cnod9xzLTxTWEdUSxjQtKHtblwABhsJRk4vZwwOTOlD\r\n"
                      "JmHc4b7mS5EDAtl274lrfNIH7jE1l8Z0A1fy7125x41FJN0CQQDw/ihtunWOXX81\r\n"
                      "Qe/AVfzSr0SHGe2IMz9PG7iJoDc/pqt/+OmGKl2M112wcSMyCfSWvNG1X2LRW34/\r\n"
                      "w6twZDhbAkEA1l7t8EQAqEEtHWEok05WVdHMjL04ba94o0JfVFro9YOze+jkCpHv\r\n"
                      "3i7aaZDQSiGncRTGqBMcbjINZ+9yrobZKwJAOKeXe4xdPJXQZQXWRkIwyJr5okU/\r\n"
                      "KUja9k8PCBPJSUZ2hQRQagElswmidetzGb1radCEAH6nLY6z1Gu8rxRwhwJAZEaD\r\n"
                      "hqBIrmvObq/ECyPZvssko7DfdG9gPv4NGahs0GuKyatnAIrDaWsBP+A9jm+vo3XU\r\n"
                      "d0p5QhKnsraPLpRlgQJABo2yhQs6eOclabI/5rhlInxaaGE6Zde1SGVRj/2cNsDr\r\n"
                      "obVT4Eu/i01hbpUjzQzz55hrEtEEdtz8x2+M4ou+pg==\r\n"
                      "-----END RSA PRIVATE KEY-----";
    component.setDecryptionCertificate( pem, strlen( pem ) );
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 19u, length );
    ASSERT_STREQ( "THIS IS INPUT DATA", (const char*) output );
}

TEST(CryptosoftCrypt, CheckCertDecryptedCache)
{
    // Try to get the decrypted data out and then again to check the cache works
    const char inputData[] = "MIIBtgYJKoZIhvcNAQcDoIIBpzCCAaMCAQAxggFHMIIBQwIBADCBqzCBnTELMAkG\r\n"
                             "A1UEBhMCR0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxs\r\n"
                             "MRcwFQYDVQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQx\r\n"
                             "EDAOBgNVBAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRv\r\n"
                             "c29mdC5jb20CCQDK09hPYZtveTANBgkqhkiG9w0BAQEFAASBgD2WMW2IP/WoIsxv\r\n"
                             "WGUKudrHn0ReoxiPGezir93tHMVojiFYoyUTUH8u7N/GmgUYvgueIFx8qiF1oCRx\r\n"
                             "p2FgHW76lgcEhHN9wnidKHpiEThhaemYUDE3cbMn3FwkPV9i/umdNvdDcl61jD2A\r\n"
                             "KOaInPgXwGGUNkEuzFtbdl3PKOCQMFMGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQI\r\n"
                             "EN18qif3PEOAMB7qTw40mM2OdQpBUbMWc4PtjJ0duRefuGtEbtJqqedXaNGDdK/0\r\n"
                             "dPIo1/K6EVjaPw==";
    CryptosoftCrypt component( true );
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    const char* pem = "-----BEGIN CERTIFICATE-----\r\n"
                      "MIICszCCAhwCCQDK09hPYZtveTANBgkqhkiG9w0BAQsFADCBnTELMAkGA1UEBhMC\r\n"
                      "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                      "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                      "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                      "b20wHhcNMTYwNDE5MDc1NDQ1WhcNMTcwNDE5MDc1NDQ1WjCBnTELMAkGA1UEBhMC\r\n"
                      "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                      "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                      "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                      "b20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMnN0xwL4FnLXL0WfuHCS4uK\r\n"
                      "qbo5Uee5+lLeeoFH7uRzVFI4Vx0wRo36BOxJRhpi09g9maBpU6cSGn8bA5gFKRgI\r\n"
                      "F/XYmuVCxL1452lH87N3MZvYvAN+ozgyOsQA9vIZPqu2E5gxfoQJgE9/ISXHnI4O\r\n"
                      "BLgurEK//ByOMFouPJpJAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAmE+llTIc7nG5\r\n"
                      "3V1VzS6/SW36gBT5JX52L8G+Xyse2bxf4XmMpL7WbxhBuY6zdr5Dgapki9I0f9oi\r\n"
                      "5QMWDNX2YDRE6WQuiZJSXv/1B1VlG/7mkiIZupC98ik0v4ufdi5JQhW6M3FmVnag\r\n"
                      "RKp29NSBiNlSwNMxdLnVvcbbMCO86JM=\r\n"
                      "-----END CERTIFICATE-----\r\n"
                      "-----BEGIN RSA PRIVATE KEY-----\r\n"
                      "MIICWwIBAAKBgQDJzdMcC+BZy1y9Fn7hwkuLiqm6OVHnufpS3nqBR+7kc1RSOFcd\r\n"
                      "MEaN+gTsSUYaYtPYPZmgaVOnEhp/GwOYBSkYCBf12JrlQsS9eOdpR/OzdzGb2LwD\r\n"
                      "fqM4MjrEAPbyGT6rthOYMX6ECYBPfyElx5yODgS4LqxCv/wcjjBaLjyaSQIDAQAB\r\n"
                      "AoGAGSXsI/ea6rW8BdhS0YFr9qS+B/XyrgTwG/mbnJbBP3jbzi81M+77K+A3UtbC\r\n"
                      "xLECI1Vx2pqlkRFheet85Cnod9xzLTxTWEdUSxjQtKHtblwABhsJRk4vZwwOTOlD\r\n"
                      "JmHc4b7mS5EDAtl274lrfNIH7jE1l8Z0A1fy7125x41FJN0CQQDw/ihtunWOXX81\r\n"
                      "Qe/AVfzSr0SHGe2IMz9PG7iJoDc/pqt/+OmGKl2M112wcSMyCfSWvNG1X2LRW34/\r\n"
                      "w6twZDhbAkEA1l7t8EQAqEEtHWEok05WVdHMjL04ba94o0JfVFro9YOze+jkCpHv\r\n"
                      "3i7aaZDQSiGncRTGqBMcbjINZ+9yrobZKwJAOKeXe4xdPJXQZQXWRkIwyJr5okU/\r\n"
                      "KUja9k8PCBPJSUZ2hQRQagElswmidetzGb1radCEAH6nLY6z1Gu8rxRwhwJAZEaD\r\n"
                      "hqBIrmvObq/ECyPZvssko7DfdG9gPv4NGahs0GuKyatnAIrDaWsBP+A9jm+vo3XU\r\n"
                      "d0p5QhKnsraPLpRlgQJABo2yhQs6eOclabI/5rhlInxaaGE6Zde1SGVRj/2cNsDr\r\n"
                      "obVT4Eu/i01hbpUjzQzz55hrEtEEdtz8x2+M4ou+pg==\r\n"
                      "-----END RSA PRIVATE KEY-----";
    component.setDecryptionCertificate( pem, strlen( pem ) );
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 19u, length );
    EXPECT_STREQ( "THIS IS INPUT DATA", (const char*) output );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( length, length2 );
    ASSERT_STREQ( (const char*) output, (const char*) output2);
}

TEST(CryptosoftCrypt, CheckCertDecCacheMadeStale)
{
    // Try to get the decrypted data out and then change data to check the cache works
    const char inputData[] = "MIIBtgYJKoZIhvcNAQcDoIIBpzCCAaMCAQAxggFHMIIBQwIBADCBqzCBnTELMAkG\r\n"
                             "A1UEBhMCR0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxs\r\n"
                             "MRcwFQYDVQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQx\r\n"
                             "EDAOBgNVBAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRv\r\n"
                             "c29mdC5jb20CCQDK09hPYZtveTANBgkqhkiG9w0BAQEFAASBgD2WMW2IP/WoIsxv\r\n"
                             "WGUKudrHn0ReoxiPGezir93tHMVojiFYoyUTUH8u7N/GmgUYvgueIFx8qiF1oCRx\r\n"
                             "p2FgHW76lgcEhHN9wnidKHpiEThhaemYUDE3cbMn3FwkPV9i/umdNvdDcl61jD2A\r\n"
                             "KOaInPgXwGGUNkEuzFtbdl3PKOCQMFMGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQI\r\n"
                             "EN18qif3PEOAMB7qTw40mM2OdQpBUbMWc4PtjJ0duRefuGtEbtJqqedXaNGDdK/0\r\n"
                             "dPIo1/K6EVjaPw==";
    CryptosoftCrypt component( true );
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    const char* pem = "-----BEGIN CERTIFICATE-----\r\n"
                      "MIICszCCAhwCCQDK09hPYZtveTANBgkqhkiG9w0BAQsFADCBnTELMAkGA1UEBhMC\r\n"
                      "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                      "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                      "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                      "b20wHhcNMTYwNDE5MDc1NDQ1WhcNMTcwNDE5MDc1NDQ1WjCBnTELMAkGA1UEBhMC\r\n"
                      "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                      "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                      "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                      "b20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMnN0xwL4FnLXL0WfuHCS4uK\r\n"
                      "qbo5Uee5+lLeeoFH7uRzVFI4Vx0wRo36BOxJRhpi09g9maBpU6cSGn8bA5gFKRgI\r\n"
                      "F/XYmuVCxL1452lH87N3MZvYvAN+ozgyOsQA9vIZPqu2E5gxfoQJgE9/ISXHnI4O\r\n"
                      "BLgurEK//ByOMFouPJpJAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAmE+llTIc7nG5\r\n"
                      "3V1VzS6/SW36gBT5JX52L8G+Xyse2bxf4XmMpL7WbxhBuY6zdr5Dgapki9I0f9oi\r\n"
                      "5QMWDNX2YDRE6WQuiZJSXv/1B1VlG/7mkiIZupC98ik0v4ufdi5JQhW6M3FmVnag\r\n"
                      "RKp29NSBiNlSwNMxdLnVvcbbMCO86JM=\r\n"
                      "-----END CERTIFICATE-----\r\n"
                      "-----BEGIN RSA PRIVATE KEY-----\r\n"
                      "MIICWwIBAAKBgQDJzdMcC+BZy1y9Fn7hwkuLiqm6OVHnufpS3nqBR+7kc1RSOFcd\r\n"
                      "MEaN+gTsSUYaYtPYPZmgaVOnEhp/GwOYBSkYCBf12JrlQsS9eOdpR/OzdzGb2LwD\r\n"
                      "fqM4MjrEAPbyGT6rthOYMX6ECYBPfyElx5yODgS4LqxCv/wcjjBaLjyaSQIDAQAB\r\n"
                      "AoGAGSXsI/ea6rW8BdhS0YFr9qS+B/XyrgTwG/mbnJbBP3jbzi81M+77K+A3UtbC\r\n"
                      "xLECI1Vx2pqlkRFheet85Cnod9xzLTxTWEdUSxjQtKHtblwABhsJRk4vZwwOTOlD\r\n"
                      "JmHc4b7mS5EDAtl274lrfNIH7jE1l8Z0A1fy7125x41FJN0CQQDw/ihtunWOXX81\r\n"
                      "Qe/AVfzSr0SHGe2IMz9PG7iJoDc/pqt/+OmGKl2M112wcSMyCfSWvNG1X2LRW34/\r\n"
                      "w6twZDhbAkEA1l7t8EQAqEEtHWEok05WVdHMjL04ba94o0JfVFro9YOze+jkCpHv\r\n"
                      "3i7aaZDQSiGncRTGqBMcbjINZ+9yrobZKwJAOKeXe4xdPJXQZQXWRkIwyJr5okU/\r\n"
                      "KUja9k8PCBPJSUZ2hQRQagElswmidetzGb1radCEAH6nLY6z1Gu8rxRwhwJAZEaD\r\n"
                      "hqBIrmvObq/ECyPZvssko7DfdG9gPv4NGahs0GuKyatnAIrDaWsBP+A9jm+vo3XU\r\n"
                      "d0p5QhKnsraPLpRlgQJABo2yhQs6eOclabI/5rhlInxaaGE6Zde1SGVRj/2cNsDr\r\n"
                      "obVT4Eu/i01hbpUjzQzz55hrEtEEdtz8x2+M4ou+pg==\r\n"
                      "-----END RSA PRIVATE KEY-----";
    component.setDecryptionCertificate( pem, strlen( pem ) );
    EXPECT_TRUE( component.decrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    EXPECT_EQ( 19u, length );
    EXPECT_STREQ( "THIS IS INPUT DATA", (const char*) output );
    const char inputData2[] = "MIIBvgYJKoZIhvcNAQcDoIIBrzCCAasCAQAxggFHMIIBQwIBADCBqzCBnTELMAkG\r\n"
                              "A1UEBhMCR0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxs\r\n"
                              "MRcwFQYDVQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQx\r\n"
                              "EDAOBgNVBAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRv\r\n"
                              "c29mdC5jb20CCQDK09hPYZtveTANBgkqhkiG9w0BAQEFAASBgK5KWoADUa6ZknKn\r\n"
                              "YSFlJDh3DNCU2RELpHZytjJenB+rPlxct3PP2f86eO5u+VikDGyfWAGnonfLtrLR\r\n"
                              "kWliBdS1VkkM+amKm7dbZiKmr78PEY0Ba56Vyhwojr87l44HFeObSYz8CsJshpzP\r\n"
                              "nzNO39LgxoIE+c1pPqdPajIVUXhlMFsGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQI\r\n"
                              "CbnmB7IT/g+AODPtp3PG7TUGdmsR71iDTp23uayQ2pjyLhm8X/uwPuTlNyH1QtmB\r\n"
                              "dDyv+mVvFDSs20Rst3RJUp+l";
    component.setInputData( (const unsigned char*) inputData2, sizeof(inputData2) );
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( 24u, length2 );
    ASSERT_STREQ( "THIS IS ALSO INPUT DATA", (const char*) output2 );
}

TEST(CryptosoftCrypt, CheckCertCacheMadeStale)
{
    // Try to encrypt and then decrypt with the same object to check the cache works
    const char inputData[] = "THIS IS INPUT DATA";
    CryptosoftCrypt component( true );
    component.setInputData( (const unsigned char*) inputData, sizeof(inputData) );
    const char* certificate = "MIICszCCAhwCCQDK09hPYZtveTANBgkqhkiG9w0BAQsFADCBnTELMAkGA1UEBhMC\r\n"
                              "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                              "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                              "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                              "b20wHhcNMTYwNDE5MDc1NDQ1WhcNMTcwNDE5MDc1NDQ1WjCBnTELMAkGA1UEBhMC\r\n"
                              "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                              "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                              "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                              "b20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMnN0xwL4FnLXL0WfuHCS4uK\r\n"
                              "qbo5Uee5+lLeeoFH7uRzVFI4Vx0wRo36BOxJRhpi09g9maBpU6cSGn8bA5gFKRgI\r\n"
                              "F/XYmuVCxL1452lH87N3MZvYvAN+ozgyOsQA9vIZPqu2E5gxfoQJgE9/ISXHnI4O\r\n"
                              "BLgurEK//ByOMFouPJpJAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAmE+llTIc7nG5\r\n"
                              "3V1VzS6/SW36gBT5JX52L8G+Xyse2bxf4XmMpL7WbxhBuY6zdr5Dgapki9I0f9oi\r\n"
                              "5QMWDNX2YDRE6WQuiZJSXv/1B1VlG/7mkiIZupC98ik0v4ufdi5JQhW6M3FmVnag\r\n"
                              "RKp29NSBiNlSwNMxdLnVvcbbMCO86JM=\r\n";
    component.setEncryptionCertificate( certificate, strlen( certificate ) );
    EXPECT_TRUE( component.encrypt() );
    const unsigned char* output;
    unsigned int length;
    component.getCryptedData( output, length );
    ASSERT_EQ( 0, strncmp( "MIIBtg", (const char*) output, 6 ) );
    component.setInputData( (const unsigned char*) output, length );
    const char* pem = "-----BEGIN CERTIFICATE-----\r\n"
                      "MIICszCCAhwCCQDK09hPYZtveTANBgkqhkiG9w0BAQsFADCBnTELMAkGA1UEBhMC\r\n"
                      "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                      "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                      "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                      "b20wHhcNMTYwNDE5MDc1NDQ1WhcNMTcwNDE5MDc1NDQ1WjCBnTELMAkGA1UEBhMC\r\n"
                      "R0IxEjAQBgNVBAgMCUJlcmtzaGlyZTESMBAGA1UEBwwJQnJhY2tuZWxsMRcwFQYD\r\n"
                      "VQQKDA5DcnlwdG9zb2Z0IEx0ZDEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEDAOBgNV\r\n"
                      "BAMMB1Rlc3RpbmcxJTAjBgkqhkiG9w0BCQEWFnRlc3RpbmdAY3J5cHRvc29mdC5j\r\n"
                      "b20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMnN0xwL4FnLXL0WfuHCS4uK\r\n"
                      "qbo5Uee5+lLeeoFH7uRzVFI4Vx0wRo36BOxJRhpi09g9maBpU6cSGn8bA5gFKRgI\r\n"
                      "F/XYmuVCxL1452lH87N3MZvYvAN+ozgyOsQA9vIZPqu2E5gxfoQJgE9/ISXHnI4O\r\n"
                      "BLgurEK//ByOMFouPJpJAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAmE+llTIc7nG5\r\n"
                      "3V1VzS6/SW36gBT5JX52L8G+Xyse2bxf4XmMpL7WbxhBuY6zdr5Dgapki9I0f9oi\r\n"
                      "5QMWDNX2YDRE6WQuiZJSXv/1B1VlG/7mkiIZupC98ik0v4ufdi5JQhW6M3FmVnag\r\n"
                      "RKp29NSBiNlSwNMxdLnVvcbbMCO86JM=\r\n"
                      "-----END CERTIFICATE-----\r\n"
                      "-----BEGIN RSA PRIVATE KEY-----\r\n"
                      "MIICWwIBAAKBgQDJzdMcC+BZy1y9Fn7hwkuLiqm6OVHnufpS3nqBR+7kc1RSOFcd\r\n"
                      "MEaN+gTsSUYaYtPYPZmgaVOnEhp/GwOYBSkYCBf12JrlQsS9eOdpR/OzdzGb2LwD\r\n"
                      "fqM4MjrEAPbyGT6rthOYMX6ECYBPfyElx5yODgS4LqxCv/wcjjBaLjyaSQIDAQAB\r\n"
                      "AoGAGSXsI/ea6rW8BdhS0YFr9qS+B/XyrgTwG/mbnJbBP3jbzi81M+77K+A3UtbC\r\n"
                      "xLECI1Vx2pqlkRFheet85Cnod9xzLTxTWEdUSxjQtKHtblwABhsJRk4vZwwOTOlD\r\n"
                      "JmHc4b7mS5EDAtl274lrfNIH7jE1l8Z0A1fy7125x41FJN0CQQDw/ihtunWOXX81\r\n"
                      "Qe/AVfzSr0SHGe2IMz9PG7iJoDc/pqt/+OmGKl2M112wcSMyCfSWvNG1X2LRW34/\r\n"
                      "w6twZDhbAkEA1l7t8EQAqEEtHWEok05WVdHMjL04ba94o0JfVFro9YOze+jkCpHv\r\n"
                      "3i7aaZDQSiGncRTGqBMcbjINZ+9yrobZKwJAOKeXe4xdPJXQZQXWRkIwyJr5okU/\r\n"
                      "KUja9k8PCBPJSUZ2hQRQagElswmidetzGb1radCEAH6nLY6z1Gu8rxRwhwJAZEaD\r\n"
                      "hqBIrmvObq/ECyPZvssko7DfdG9gPv4NGahs0GuKyatnAIrDaWsBP+A9jm+vo3XU\r\n"
                      "d0p5QhKnsraPLpRlgQJABo2yhQs6eOclabI/5rhlInxaaGE6Zde1SGVRj/2cNsDr\r\n"
                      "obVT4Eu/i01hbpUjzQzz55hrEtEEdtz8x2+M4ou+pg==\r\n"
                      "-----END RSA PRIVATE KEY-----";
    component.setDecryptionCertificate( pem, strlen( pem ) );
    ASSERT_TRUE( component.decrypt() );
    const unsigned char* output2;
    unsigned int length2;
    component.getCryptedData( output2, length2 );
    ASSERT_EQ( sizeof(inputData), length2 );
    ASSERT_STREQ( inputData, (const char*) output2 );
}

