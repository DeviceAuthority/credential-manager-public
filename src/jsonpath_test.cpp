/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the Device Authority JSON parser class
 *
 */
#include "jsonpath.hpp"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "gtest/gtest.h"
#include <string>

using namespace rapidjson;

TEST(JSONPathMatching, AllChildren)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";

    Document parser;
    EXPECT_FALSE( parser.Parse( json ).HasParseError() );
    std::vector< Value* > result;
    allAtXPath( &parser, "/[*]/children", result );

    StringBuffer buffer;

    for ( std::vector< Value* >::const_iterator i = result.begin(); i != result.end(); ++i )
    {
    	 Writer< rapidjson::StringBuffer > writer(buffer);
        (*i)->Accept( writer );
    }

    EXPECT_STREQ( "[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}][{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]",
                   buffer.GetString() );
}

TEST(JSONPathMatching, AllChildrensAges)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";

    Document parser;
    EXPECT_FALSE( parser.Parse( json ).HasParseError() );
    std::vector< Value* > result;
    allAtXPath( &parser, "/[*]/children/[*]/age", result );

    StringBuffer buffer;

    for ( std::vector< Value* >::const_iterator i = result.begin(); i != result.end(); ++i )
    {
    	Writer< rapidjson::StringBuffer > writer(buffer);
        (*i)->Accept( writer );
    }

    EXPECT_STREQ( "591116", buffer.GetString() );
}

TEST(JSONPathMatching, AllSecondChildFields)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";

    Document parser;
    EXPECT_FALSE( parser.Parse( json ).HasParseError() );
    std::vector< Value* > result;
    allAtXPath( &parser, "/[*]/children/[1]/*", result );

    StringBuffer buffer;

    for ( std::vector< Value* >::const_iterator i = result.begin(); i != result.end(); ++i )
    {
    	Writer< rapidjson::StringBuffer > writer(buffer);
        (*i)->Accept( writer );
        buffer.Put(' ');
    }

    EXPECT_STREQ( "\"john\" 9 \"lorna\" 16 ", buffer.GetString() );
}

