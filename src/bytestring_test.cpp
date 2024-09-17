/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the byte string class
 *
 */

#include "bytestring.hpp"
#include "gtest/gtest.h"
#include <cstring>

TEST(CryptosoftByteString, EmptyString)
{
    // Test construct an empty bytestring
    bytestring bs;
    da::byte* data = 0;
    unsigned int length = 0;
    bs.getData( data, length );
    ASSERT_EQ( (da::byte*) 0, data );
    ASSERT_EQ( 0u, length );
}

TEST(CryptosoftByteString, PopulatedString)
{
    // Test construct a populated bytestring
    bytestring bs( (const da::byte*) "0123456789", 10 );
    da::byte* data = 0;
    unsigned int length = 0;
    bs.getData( data, length );
    ASSERT_EQ( 0, strncmp( "0123456789", (const char*) data, length ) );
    ASSERT_EQ( 10u, length );
}

TEST(CryptosoftByteString, AppendToEmptyString)
{
    // Test append to an empty string
    bytestring bs;
    da::byte* data = bs.needAtLeastOverLength( 10 );
    ASSERT_NE( (da::byte*) 0, data );
    memcpy( data, "0123456789", 10 );
    bs.length( 10 );
    unsigned int length = 0;
    bs.getData( data, length );
    ASSERT_EQ( 0, strncmp( "0123456789", (const char*) data, length ) );
    ASSERT_EQ( 10u, length );
}

TEST(CryptosoftByteString, AppendToEmptyString2)
{
    // Test append to an empty string
    bytestring bs;
    bs.append( (const da::byte*) "0123456789", 10 );
    da::byte* data = 0;
    unsigned int length = 0;
    bs.getData( data, length );
    ASSERT_EQ( 0, strncmp( "0123456789", (const char*) data, length ) );
    ASSERT_EQ( 10u, length );
}

TEST(CryptosoftByteString, AppendToExistingString)
{
    // Test append to a string that already contains some bytes
    bytestring bs( (const da::byte*) "0123456789", 10 );
    da::byte* data = bs.needAtLeastOverLength( 10 );
    memcpy( data, "0123456789", 10 );
    bs.length( 20 );
    unsigned int length = 0;
    bs.getData( data, length );
    ASSERT_EQ( 0, strncmp( "01234567890123456789", (const char*) data, length ) );
    ASSERT_EQ( 20u, length );
}

TEST(CryptosoftByteString, AppendToExistingString2)
{
    // Test append to a string that already contains some bytes
    bytestring bs( (const da::byte*) "0123456789", 10 );
    bs.append( (const da::byte*) "0123456789", 10 );
    da::byte* data = 0;
    unsigned int length = 0;
    bs.getData( data, length );
    ASSERT_EQ( 0, strncmp( "01234567890123456789", (const char*) data, length ) );
    ASSERT_EQ( 20u, length );
}

TEST(CryptosoftByteString, ClearWorks)
{
    // Test that clear empties the string
    bytestring bs( (const da::byte*) "0123456789", 10 );
    bs.clear();
    da::byte* data = 0;
    unsigned int length = 0;
    bs.getData( data, length );
    ASSERT_NE( (da::byte*) 0, data );
    ASSERT_EQ( 0u, length );
    ASSERT_NE( 0u, bs.size() );
}

TEST(CryptosoftByteString, ClearAndDestroyWorks)
{
    // Test that clearAndDestroy empties the string
    bytestring bs( (const da::byte*) "0123456789", 10 );
    bs.clearAndDestroy();
    da::byte* data = 0;
    unsigned int length = 0;
    bs.getData( data, length );
    ASSERT_EQ( (da::byte*) 0, data );
    ASSERT_EQ( 0u, length );
    ASSERT_EQ( 0u, bs.size() );
}
/*
TEST(CryptosoftByteString, AdvanceWorks)
{
    // Test that advance moves the starting point of the string
    bytestring bs( (const da::byte*) "0123456789", 10 );
    const da::byte* data = 0;
    unsigned int length = 0;
    bs.getData( data, length );
    EXPECT_EQ( 0, strncmp( "0123456789", (const char*) data, length ) );
    EXPECT_EQ( 10, length );
    bs.advance( 5 );
    const da::byte* newdata = 0;
    bs.getData( newdata, length );
    ASSERT_EQ( 0, strncmp( "56789", (const char*) newdata, length ) );
    ASSERT_EQ( 5, length );
    ASSERT_EQ( data + 5, newdata );
}

TEST(CryptosoftByteString, CompactWorks)
{
    // Test that compact moves the starting point to the beginning
    // of the allocated memory.
    bytestring bs( (const da::byte*) "0123456789", 10 );
    const da::byte* data = 0;
    unsigned int length = 0;
    bs.getData( data, length );
    bs.advance( 5 );
    bs.compact();
    const da::byte* newdata = 0;
    bs.getData( newdata, length );
    ASSERT_EQ( 0, strncmp( "56789", (const char*) newdata, length ) );
    ASSERT_EQ( data, newdata );
}
*/
TEST(CryptosoftByteString, LengthIsCorrect)
{
    // Test length returns the correct values
    bytestring bs( (const da::byte*) "0123456789", 10 );
    unsigned int length = bs.length();
    ASSERT_EQ( 10u, length );
    bs.clear();
    length = bs.length();
    ASSERT_EQ( 0u, length );
    da::byte* data = bs.needAtLeastOverLength( 10 );
    memcpy( data, "0123456789", 10 );
    bs.length( 10 );
    length = bs.length();
    ASSERT_EQ( 10u, length );
    bs.clearAndDestroy();
    length = bs.length();
    ASSERT_EQ( 0u, length );
    data = bs.needAtLeastOverLength( 10 );
    memcpy( data, "0123456789", 10 );
    bs.length( 10 );
    length = bs.length();
    ASSERT_EQ( 10u, length );
//    bs.advance( 5 );
//    length = bs.length();
//    ASSERT_EQ( 5, length );
}

TEST(CryptosoftByteString, MemoryAllocatedReallocated)
{
    unsigned int minimumToIncreaseBy = 2048; // default value as per config
    // Test memory is allocated in blocks of "amountToIncreaseBy" and repopulated
    bytestring bs( (const da::byte*) "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789", 100 );
    EXPECT_EQ( minimumToIncreaseBy, bs.size() );
    da::byte* data1 = 0;
    unsigned int length = 0;
    bs.getData( data1, length );
    da::byte* data2 = bs.reallocAtLeast( 100 );
    EXPECT_EQ( minimumToIncreaseBy, bs.size() );
    EXPECT_EQ( data1, data2 );
    data2 = bs.reallocAtLeast( 2100 );
    EXPECT_NE( data1, data2 );
    ASSERT_EQ( 0, strncmp( "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789", (const char*) data2, length ) );
    EXPECT_EQ( 100u, length );
    EXPECT_EQ( 2 * minimumToIncreaseBy, bs.size() );
}

TEST(CryptosoftByteString, MemoryAllocatedReallocatedCont)
{
    // Test memory is allocated when bigger than "amountToIncreaseBy"
    bytestring bs( (const da::byte*) "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                                 "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789", 2100 );
    da::byte* data = 0;
    unsigned int length = 0;
    bs.getData( data, length );
    ASSERT_EQ( 0, strncmp( "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                           , (const char*) data, length ) );
    EXPECT_EQ( 2100u, length );
    EXPECT_EQ( 2100u, bs.size() );
}
