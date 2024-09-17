/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a string of bytes.
 */
#ifndef BYTESTRING_HPP
#define BYTESTRING_HPP

#include "byte.h"

//namespace cryptosoft
//{

class bytestring
{
public:
    bytestring();
    bytestring(const da::byte* data, unsigned int length);
    bytestring(const bytestring &);//copy const
    bytestring(unsigned int length);

    ~bytestring(void);

    void clear(void);
    void clearAndDestroy(void);
    void getData(da::byte*& data, unsigned int& length) const;
    unsigned int length(void) const;
    void length(unsigned int newLength);
    da::byte* reallocAtLeast(unsigned int newSize);
    da::byte* needAtLeastOverLength(unsigned int extra);
    void append(const da::byte *data, unsigned int size);

#ifdef TESTHARNESS
    unsigned int size(void) const
    {
        return size_;
    }
#endif
    // This is not needed for normal operation of bytestring, it is
    // only used to make debug messages more readable.
    void setDescription( const char* description )
    {
        description_ = description;
    }

private:
    da::byte *store_;               // Pointer to the actual bytes
    unsigned int size_;         // The actual size of the allocated space
    unsigned int length_;       // The length of data held (this will be <= size)
    const char *description_;   // This has no use other than for the debug log messages.
};

//};

#endif // #ifndef BYTESTRING_HPP
