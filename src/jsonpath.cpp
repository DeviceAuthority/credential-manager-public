/*
 * Copyright (c) 2019 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class provides JSON parsing functionality
 */

#include "jsonpath.hpp"
#include <cassert>
#include <cstdlib>

namespace rapidjson
{

void allAtXPath( Value* value, const std::string& path, std::vector< Value* >& result )
{
    if ( path.empty() || path == "/" )
    {
    	result.push_back( value );
    }
    else if ( value->IsObject() )
    {
        std::string tempPath = path;
        if ( tempPath.empty() ){ tempPath = "/*"; };

        size_t pos = tempPath.find_first_of( '/', 1 );
        std::string level = tempPath.substr( 1, pos-1 );

        for ( Value::MemberIterator itr = value->MemberBegin(); itr != value->MemberEnd(); ++itr )
        {
        	if ( level == itr->name.GetString() || level == "*" )
            {
        		std::string p( tempPath, pos == std::string::npos ? tempPath.size() : pos );
        		allAtXPath( &itr->value, p, result );
            }
        }
    }
    else if ( value->IsArray() )
    {
        std::string tempPath = path;

        if ( tempPath.empty() ){ tempPath = "/[*]"; } // Match all

        if (tempPath.length() < 4 || tempPath[1] != '[' ){ return; }

        size_t pos = tempPath.find_first_of( ']' );
        if ( pos == std::string::npos ){ return; }

        std::string level = tempPath.substr( 2, pos-2 );
        if ( level == "*" )
        {
        	for ( Value::ValueIterator itr = value->Begin(); itr != value->End(); ++itr )
        	{
        		allAtXPath( itr, tempPath.substr(pos+1), result );
        	}
        }
        else
        {
            int num = atoi( level.c_str() );
            assert( num >= 0 );
            if ( (unsigned int)num >= value->Size() ){ return; }

            allAtXPath( &(*value)[num], tempPath.substr(pos+1), result );
        }
    }
}

} //end rapidjson
