/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a string of bytes.
 */

#include "bytestring.hpp"
#include "configuration.hpp"
#include "log.hpp"
#include <cstring>
#include <cstdlib>

//namespace cryptosoft
//{

    bytestring::bytestring( const da::byte* data, unsigned int length )
            : store_( 0 ), size_( 0 ), length_( 0 ), description_( "data" )
   {
      reallocAtLeast( length );
      memcpy( store_, data, length );
      length_ = length;
   }

   bytestring::bytestring(const bytestring &existingObj)
   {
     size_ = existingObj.size_;
     length_ = existingObj.length_;
     store_ = new da::byte[size_];
     memcpy( store_, existingObj.store_, length_ );
   }

   bytestring::bytestring()
   : store_( 0 ), size_( 0 ), length_( 0 ), description_( "data" )
   {
     //logger.printf( Log::Emergency,"1 Constructor ..." );
   }

   bytestring::bytestring( unsigned int length)
        : store_( 0 ), size_( 0 ), length_( 0 ), description_( "data" )
   {
      store_ = new da::byte[length + 4];
      memset(store_,0x00,(length+4));

      if (store_ == 0)
      {
         Log::getInstance()->printf( Log::Emergency, "Unable to allocate memory for buffer, exiting..." );
         exit( 1 );
      }
      length_ = length;
      size_ = length;
   }


    bytestring::~bytestring( void )
    {
        clearAndDestroy();
    }

    void bytestring::clear( void )
    {
        length_ = 0;
    }

    void bytestring::clearAndDestroy( void )
    {
        delete [] store_;
        store_ = 0;
        size_ = 0;
        length_ = 0;
    }

    void bytestring::getData( da::byte*& data, unsigned int& length ) const
    {
        // Return a pointer to the start position and the length of data.
        data = store_;
        length = length_;
    }

    unsigned int bytestring::length( void ) const
    {
        // Return the length of data.
        return length_;
    }

    void bytestring::length( unsigned int newLength )
    {
        length_ = newLength;
    }

    da::byte* bytestring::reallocAtLeast( unsigned int newSize )
    {
        if (newSize > size_)
        {
            static unsigned int minimumToIncreaseBy = config.lookupAsLong( "MemoryBlockSize" );
            // Want to increase size by at least the minimum amount
            if (newSize - size_ < minimumToIncreaseBy) newSize = size_ + minimumToIncreaseBy;
            // Increase the buffer size
            Log::getInstance()->printf( Log::Debug, "Increasing %s buffer from %d to %d.", description_, size_, newSize );
            da::byte* newStore = new da::byte[newSize + 4];
            if (newStore == 0)
            {
                Log::getInstance()->printf( Log::Emergency, "Unable to allocate memory for buffer, exiting..." );
                exit( 1 );
            }
            // Copy any existing data from the old buffer to the new.
            if(store_ != 0 && length_ > 0)
            {
				memcpy( newStore, store_, length_ );
            }
            // Now swap over the old and new buffers
            delete [] store_;
            store_ = newStore;
            size_ = newSize;
        }
        return store_;
    }

    da::byte* bytestring::needAtLeastOverLength( unsigned int extra )
    {
        return reallocAtLeast( length_ + extra ) + length_;
    }

    void bytestring::append( const da::byte* data, unsigned int size )
    {
        needAtLeastOverLength( size );
        memcpy( &(store_[length_]), data, size );
        length_ += size;
    }

//}
