/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class is a unit test for the Device Authority JSON parser class
 *
 */
#include "jsonparse.hpp"
#include "gtest/gtest.h"
#include <string>

using namespace cryptosoft;

TEST(CryptosoftJSONParse, SuperSimpleObject)
{
    const char* json = "{}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, SuperSimpleObjectWithSpaces)
{
    const char* json = "{    }";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadSimpleObject1)
{
    const char* json = "{:}";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadSimpleObject2)
{
    const char* json = "{,}";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadObjectNoFirst)
{
    const char* json = "{:\"second\"}";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadObjectNoSecond)
{
    const char* json = "{\"first\":}";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadObjectNothingAfterComma)
{
    const char* json = "{\"first\":\"second\",}";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadObjectNothingBeforeComma)
{
    const char* json = "{,\"first\":\"second\"}";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadObjectNoCloseBrace)
{
    const char* json = "{\"first\":\"second\"";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadObjectNoOpenBrace)
{
    const char* json = "\"first\":\"second\"}";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadObjectNoQuotesFirst)
{
    const char* json = "{first:\"second\"}";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadObjectNoQuotesSecond)
{
    const char* json = "{\"first\":second}";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, GoodObjectStringString)
{
    const char* json = "{\"first\":\"second\"}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, GoodObjectStringNull)
{
    const char* json = "{\"first\":null}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, GoodObjectStringTrue)
{
    const char* json = "{\"first\":true}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, GoodObjectStringFalse)
{
    const char* json = "{\"first\":false}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, GoodObjectStringNumber)
{
    const char* json = "{\"first\":100}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, SuperSimpleArray)
{
    const char* json = "[]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, SuperSimpleArrayWithSpaces)
{
    const char* json = "[    ]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadSimpleArray)
{
    const char* json = "[,]";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadArrayNothingAfterComma)
{
    const char* json = "[\"first\",]";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadArrayNothingBeforeComma)
{
    const char* json = "[,\"second\"]";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadArrayNoCloseBrace)
{
    const char* json = "[\"first\"";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadArrayNoOpenBrace)
{
    const char* json = "\"first\"]";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadArrayNoQuotesFirst)
{
    const char* json = "[first]";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, BadArrayNoQuotesSecond)
{
    const char* json = "[\"first\",second]";
    Json n;
    EXPECT_FALSE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, GoodArrayStringString)
{
    const char* json = "[\"first\",\"second\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, GoodArrayStringNull)
{
    const char* json = "[\"first\",null]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, GoodArrayStringTrue)
{
    const char* json = "[\"first\",true]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, GoodArrayStringFalse)
{
    const char* json = "[\"first\",false]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParse, GoodArrayStringNumber)
{
    const char* json = "[\"first\",100]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNumbers, GoodDigit)
{
    const char* json = "[1]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNumbers, GoodDigits)
{
    const char* json = "[1234567890]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNumbers, GoodDecimalPoint)
{
    const char* json = "[0.1]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNumbers, GoodDecimalPoints)
{
    const char* json = "[0.123456789]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNumbers, GoodNegative)
{
    const char* json = "[-1]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNumbers, GoodNegativePoint)
{
    const char* json = "[-1.0]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNumbers, GoodE)
{
    const char* json = "[1E2]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNumbers, GoodMinusE)
{
    const char* json = "[1E-2]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNumbers, GoodPlusE)
{
    const char* json = "[1E+2]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNumbers, GoodPointE)
{
    const char* json = "[1.0E2]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNumbers, Goode)
{
    const char* json = "[1e0]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseStrings, Good)
{
    const char* json = "[\"string\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseStrings, GoodEmbeddedQuote)
{
    const char* json = "[\"str\\\"ing\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseStrings, GoodEmbeddedBackslash)
{
    const char* json = "[\"str\\\\ing\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseStrings, GoodEmbeddedForwardslash)
{
    const char* json = "[\"str\\/ing\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseStrings, GoodEmbeddedBackspace)
{
    const char* json = "[\"str\\bing\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseStrings, GoodEmbeddedFormfeed)
{
    const char* json = "[\"str\\fing\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseStrings, GoodEmbeddedNewline)
{
    const char* json = "[\"str\\ning\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseStrings, GoodEmbeddedCarriageReturn)
{
    const char* json = "[\"str\\ring\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseStrings, GoodEmbeddedTab)
{
    const char* json = "[\"str\\ting\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseStrings, GoodEmbeddedHexDigits)
{
    const char* json = "[\"str\\ubfa1ing\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseBoolean, GoodTrue)
{
    const char* json = "[true]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseBoolean, GoodFalse)
{
    const char* json = "[false]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseNull, GoodNull)
{
    const char* json = "[null]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseComplex, GoodArrayArray)
{
    const char* json = "[[1],[2]]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseComplex, GoodArrayArrays)
{
    const char* json = "[[1,2],[3,4]]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseComplex, GoodArrayObject)
{
    const char* json = "[{\"first\":1},{\"second\":2}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseComplex, GoodArrayObjects)
{
    const char* json = "[{\"first\":1,\"second\":2},{\"third\":3,\"fourth\":4}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseComplex, GoodObjectArray)
{
    const char* json = "{\"first\":[1,2]}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseComplex, GoodObjectArrays)
{
    const char* json = "{\"first\":[1,2],\"second\":[3,4]}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseComplex, GoodObjectObject)
{
    const char* json = "{\"first\":{\"second\":2}}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseComplex, GoodObjectObjects)
{
    const char* json = "{\"first\":{\"second\":2},\"third\":{\"fourth\":4}}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
}

TEST(CryptosoftJSONParseOutput, SimpleObjectNumber)
{
    const char* json = "{\"first\":1}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, SimpleObjectString)
{
    const char* json = "{\"first\":\"1\"}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, SimpleObjectTrue)
{
    const char* json = "{\"first\":true}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, SimpleObjectFalse)
{
    const char* json = "{\"first\":false}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, SimpleObjectNull)
{
    const char* json = "{\"first\":null}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, SimpleObjectAll)
{
    const char* json = "{\"1\":1,\"2\":\"second\",\"3\":true,\"4\":false,\"5\":null}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, SimpleArrayNumber)
{
    const char* json = "[1]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, SimpleArrayString)
{
    const char* json = "[\"1\"]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, SimpleArrayTrue)
{
    const char* json = "[true]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, SimpleArrayFalse)
{
    const char* json = "[false]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, SimpleArrayNull)
{
    const char* json = "[null]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, SimpleArrayAll)
{
    const char* json = "[1,\"2\",true,false,null]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseOutput, ComplexArray)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( json, oss.str().c_str() );
}

TEST(CryptosoftJSONParseMatching, SimpleArrayNull)
{
    const char* json = "[null]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    Json* result = n.atXPath( "/[0]" );
    ASSERT_NE( (Json*) 0, result );
    EXPECT_TRUE( result->isNull() );
}

TEST(CryptosoftJSONParseMatching, Everything)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    Json* result = n.atXPath( "/" );
    ASSERT_NE( (Json*) 0, result );
    std::ostringstream oss;
    result->spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseMatching, FirstArrayItem)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    Json* result = n.atXPath( "/[0]" );
    ASSERT_NE( (Json*) 0, result );
    std::ostringstream oss;
    result->spool( oss );
    EXPECT_STREQ( "{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]}", oss.str().c_str() );
}

TEST(CryptosoftJSONParseMatching, SecondArrayItem)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    Json* result = n.atXPath( "/[1]" );
    ASSERT_NE( (Json*) 0, result );
    std::ostringstream oss;
    result->spool( oss );
    EXPECT_STREQ( "{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}", oss.str().c_str() );
}

TEST(CryptosoftJSONParseMatching, ThirdArrayItem)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    Json* result = n.atXPath( "/[2]" );
    EXPECT_EQ( (Json*) 0, result );
}

TEST(CryptosoftJSONParseMatching, FirstArrayChildren)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    Json* result = n.atXPath( "/[0]/children" );
    ASSERT_NE( (Json*) 0, result );
    std::ostringstream oss;
    result->spool( oss );
    EXPECT_STREQ( "[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseMatching, SecondArrayChildren)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    Json* result = n.atXPath( "/[1]/children" );
    ASSERT_NE( (Json*) 0, result );
    std::ostringstream oss;
    result->spool( oss );
    EXPECT_STREQ( "[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseMatching, AllChildren)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::vector< Json* > result;
    n.allAtXPath( "/[*]/children", result );
    std::ostringstream oss;
    for (std::vector< Json* >::const_iterator i = result.begin(); i != result.end(); ++i)
        (*i)->spool( oss );
    EXPECT_STREQ( "[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}][{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseMatching, AllChildrensAges)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    std::vector< Json* > result;
    n.allAtXPath( "/[*]/children/[*]/age", result );
    std::ostringstream oss;
    for (std::vector< Json* >::const_iterator i = result.begin(); i != result.end(); ++i)
        (*i)->spool( oss );
    EXPECT_STREQ( "591116", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NullForObject)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNullAtXPath( "/[1]" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},null]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NullForArray)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNullAtXPath( "/[1]/children" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":null}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NullForString)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":\"Yes\",\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":\"Yes\",\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNullAtXPath( "/[0]/married" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":null,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":\"Yes\",\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NullForBool)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNullAtXPath( "/[0]/married" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":null,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NullForNumber)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":1,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":1,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNullAtXPath( "/[0]/married" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":null,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":1,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, ObjectForObject)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    const char* newperson = "{\"name\":\"mike\",\"age\":45,\"children\":[{\"name\":\"julia\",\"age\":12}]}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceAllAtXPath( "/[1]", newperson );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"mike\",\"age\":45,\"children\":[{\"name\":\"julia\",\"age\":12}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, ArrayForArray)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    const char* newchildren = "[{\"name\":\"julia\",\"age\":12}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceAllAtXPath( "/[1]/children", newchildren );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"julia\",\"age\":12}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, StringForString)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    const char* newstring = "0123456789ABCDEF0123456789ABCDEF";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceStringAtXPath( "/[0]/name", newstring );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"0123456789ABCDEF0123456789ABCDEF\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NumberForNumber)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    double newnumber = 56;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNumberAtXPath( "/[0]/age", newnumber );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":56,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, BoolForBool)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    bool newbool = false;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceBoolAtXPath( "/[0]/married", newbool );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":false,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NullForObjects)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNullAtXPath( "/[*]" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[null,null]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NullForArrays)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNullAtXPath( "/[*]/children" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"children\":null},{\"name\":\"greg\",\"age\":30,\"children\":null}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NullForStrings)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":\"Yes\",\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":\"Yes\",\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNullAtXPath( "/[*]/married" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":null,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":null,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NullForBools)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNullAtXPath( "/[*]/married" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":null,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":null,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NullForNumbers)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":1,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":1,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNullAtXPath( "/[*]/married" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":null,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":null,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, ObjectForObjects)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    const char* newperson = "{\"name\":\"mike\",\"age\":45,\"children\":[{\"name\":\"julia\",\"age\":12}]}";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceAllAtXPath( "/[*]", newperson );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"mike\",\"age\":45,\"children\":[{\"name\":\"julia\",\"age\":12}]},{\"name\":\"mike\",\"age\":45,\"children\":[{\"name\":\"julia\",\"age\":12}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, ArrayForArrays)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    const char* newchildren = "[{\"name\":\"julia\",\"age\":12}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceAllAtXPath( "/[*]/children", newchildren );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"julia\",\"age\":12}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"julia\",\"age\":12}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, StringForStrings)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    const char* newstring = "0123456789ABCDEF0123456789ABCDEF";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceStringAtXPath( "/[*]/name", newstring );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"0123456789ABCDEF0123456789ABCDEF\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"0123456789ABCDEF0123456789ABCDEF\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NumberForNumbers)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    double newnumber = 56;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNumberAtXPath( "/[*]/age", newnumber );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":56,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":56,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, BoolForBools)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    bool newbool = false;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceBoolAtXPath( "/[*]/married", newbool );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":false,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":false,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, StringForBool)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    const char* newstring = "Yes";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceStringAtXPath( "/[0]/married", newstring );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":\"Yes\",\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NumberForBool)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    double newnumber = 1;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNumberAtXPath( "/[0]/married", newnumber );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":1,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, BoolForString)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":\"Yes\",\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":\"Yes\",\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    bool newbool = true;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceBoolAtXPath( "/[0]/married", newbool );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":\"Yes\",\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NumberForString)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":\"Yes\",\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":\"Yes\",\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    double newnumber = 1;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNumberAtXPath( "/[0]/married", newnumber );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":1,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":\"Yes\",\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, BoolForNumber)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":1,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":1,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    bool newbool = true;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceBoolAtXPath( "/[0]/married", newbool );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":1,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, StringForNumber)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":1,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":1,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    const char* newstring = "Yes";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceStringAtXPath( "/[0]/married", newstring );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":\"Yes\",\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":1,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, StringForBools)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    const char* newstring = "Yes";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceStringAtXPath( "/[*]/married", newstring );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":\"Yes\",\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":\"Yes\",\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NumberForBools)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    double newnumber = 1;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNumberAtXPath( "/[*]/married", newnumber );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":1,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":1,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, BoolForStrings)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":\"Yes\",\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":\"Yes\",\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    bool newbool = true;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceBoolAtXPath( "/[*]/married", newbool );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, NumberForStrings)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":\"Yes\",\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":\"Yes\",\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    double newnumber = 1;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceNumberAtXPath( "/[*]/married", newnumber );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":1,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":1,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, BoolForNumbers)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":1,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":1,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    bool newbool = true;
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceBoolAtXPath( "/[*]/married", newbool );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, StringForNumbers)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":1,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":1,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    const char* newstring = "Yes";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceStringAtXPath( "/[*]/married", newstring );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":\"Yes\",\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":\"Yes\",\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, StrStringForString)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceAllAtXPath( "/[0]/name", "\"0123456789ABCDEF0123456789ABCDEF\"");
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"0123456789ABCDEF0123456789ABCDEF\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, StrNumberForNumber)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceAllAtXPath( "/[0]/age", "56" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":56,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, StrBoolForBool)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"married\":true,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":false,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceAllAtXPath( "/[0]/married", "false" );
    n.replaceAllAtXPath( "/[1]/married", "true" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[{\"name\":\"fred\",\"age\":20,\"married\":false,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"married\":true,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]", oss.str().c_str() );
}

TEST(CryptosoftJSONParseSubstitute, StrNullForObjects)
{
    const char* json = "[{\"name\":\"fred\",\"age\":20,\"children\":[{\"name\":\"amy\",\"age\":5},{\"name\":\"john\",\"age\":9}]},{\"name\":\"greg\",\"age\":30,\"children\":[{\"name\":\"petra\",\"age\":11},{\"name\":\"lorna\",\"age\":16}]}]";
    Json n;
    EXPECT_TRUE( n.parse( json ) );
    n.replaceAllAtXPath( "/[*]", "null" );
    std::ostringstream oss;
    n.spool( oss );
    EXPECT_STREQ( "[null,null]", oss.str().c_str() );
}

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
