/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class provides JSON parsing functionality
 */

#include "jsonparse.hpp"
#include <sstream>
#include <cassert>
#include <cstdlib>
#define ALLOW_SPACES true

namespace cryptosoft
{

Json::~Json()
{
    clearAndDestroy();
}

bool Json::parseObject( std::istream& is )
{
    enum parseState
    {
        ERROR,
        OPEN_CURLY,
        READ_PAIR_OR_END,
        READ_PAIR,
        COLON,
        VALUE,
        COMMA_OR_END,
        COMPLETE
    };

    parseState state = OPEN_CURLY;
    std::string lhs = "";
    Json* rhs = 0;
    do
    {
        char c = is.get();
        switch (c)
        {
#ifdef ALLOW_SPACES
            case ' ':
            case '\n':
                // Ignore spaces
                break;
#endif
            case '{':
                {
                    if (state == OPEN_CURLY)
                    {
                        obj = new objType;
                        lhs = "";
                        state = READ_PAIR_OR_END;
                    }
                    else if (state == VALUE)
                    {
                        is.unget();
                        rhs = new Json;
                        if (rhs->parseObject( is ))
                        {
//                            obj->operator[](lhs) = rhs;
                            obj->push_back(std::pair< std::string, Json* >(lhs, rhs));
                            state = COMMA_OR_END;
                        }
                        else
                        {
                            state = ERROR;
                            delete rhs;
                            rhs = 0;
                        }
                    }
                    else
                        state = ERROR;
                }
                break;
               
            case '}':
                {
                    if (state == READ_PAIR_OR_END || state == COMMA_OR_END)
                        state = COMPLETE;
                    else
                        state = ERROR;
                }
                break;

            case ':':
                {
                    if (state == COLON)
                    {
                        rhs = 0;
                        state = VALUE;
                    }
                    else
                       state = ERROR;
                }
                break;

            case ',':
                {
                    if (state == COMMA_OR_END)
                    {
                        lhs = "";
                        state = READ_PAIR;
                    }
                    else
                       state = ERROR;
                }
                break;

            default:
                {
                    is.unget();
                    if (state == READ_PAIR || state == READ_PAIR_OR_END)
                    {
                        if (parseString( is, &lhs ))
                            state = COLON;
                        else
                            state = ERROR;
                    }
                    else if (state == VALUE)
                    {
                        rhs = new Json;
                        if (c == '"')
                        {
                            if (rhs->parseString( is ))
                                state = COMMA_OR_END;
                            else
                                state = ERROR;
                        }
                        else if ((c >= '0' && c <= '9') || c == '-')
                        {
                            if (rhs->parseNumber( is ))
                                state = COMMA_OR_END;
                            else
                                state = ERROR;
                        }
                        else if (c == '[')
                        {
                            if (rhs->parseArray( is ))
                                state = COMMA_OR_END;
                            else
                                state = ERROR;
                        }
                        else if (c == 't' || c == 'f')
                        {
                            if (rhs->parseBool( is ))
                                state = COMMA_OR_END;
                            else
                                state = ERROR;
                        }
                        else if (c == 'n')
                        {
                            if (rhs->parseNull( is ))
                                state = COMMA_OR_END;
                            else
                                state = ERROR;
                        }
                        else
                            state = ERROR;
                        if (state == ERROR)
                        {
                            delete rhs;
                            rhs = 0;
                        }
                        else
//                            obj->operator[](lhs) = rhs;
                            obj->push_back(std::pair< std::string, Json* >(lhs, rhs));
                    }
                    else
                       state = ERROR;
                }
                break;
        }
    } while (! is.eof() && state != COMPLETE && state != ERROR);
    return state == COMPLETE;
}

bool Json::parseArray( std::istream& is )
{
    enum parseState
    {
        ERROR,
        OPEN_SQUARE,
        VALUE_OR_END,
        VALUE,
        COMMA_OR_END,
        COMPLETE
    };

    parseState state = OPEN_SQUARE;
    Json* rhs = 0;
    do
    {
        char c = is.get();
        switch (c)
        {
#ifdef ALLOW_SPACES
            case ' ':
	    case '\n':
                // Ignore spaces
                break;
#endif
            case '[':
                {
                    if (state == OPEN_SQUARE)
                    {
                        arr = new arrType;
                        rhs = 0;
                        state = VALUE_OR_END;
                    }
                    else if (state == VALUE || state == VALUE_OR_END)
                    {
                        rhs = new Json;
                        is.unget();
                        if (rhs->parse( is ))
                        {
                            arr->push_back( rhs );
                            state = COMMA_OR_END;
                        }
                        else
                        {
                            delete rhs;
                            rhs = 0;
                            state = ERROR;
                        }
                    }
                    else
                        state = ERROR;
                }
                break;
               
            case ']':
                {
                    if (state == VALUE_OR_END || state == COMMA_OR_END)
                        state = COMPLETE;
                    else
                        state = ERROR;
                }
                break;

            case ',':
                {
                    if (state == COMMA_OR_END)
                    {
                        rhs = 0;
                        state = VALUE;
                    }
                    else
                       state = ERROR;
                }
                break;

            default:
                {
                    is.unget();
                    if (state == VALUE || state == VALUE_OR_END)
                    {
                        rhs = new Json;
                        if (c == '"')
                        {
                            rhs->parseString( is );
                            state = COMMA_OR_END;
                        }
                        else if ((c >= '0' && c <= '9') || c == '-')
                        {
                            rhs->parseNumber( is );
                            state = COMMA_OR_END;
                        }
                        else if (c == '{')
                        {
                            rhs->parseObject( is );
                            state = COMMA_OR_END;
                        }
                        else if (c == 't' || c == 'f')
                        {
                            rhs->parseBool( is );
                            state = COMMA_OR_END;
                        }
                        else if (c == 'n')
                        {
                            rhs->parseNull( is );
                            state = COMMA_OR_END;
                        }
                        else
                            state = ERROR;
                        if (state == ERROR)
                        {
                            delete rhs;
                            rhs = 0;
                        }
                        else
                            arr->push_back( rhs );
                    }
                    else
                       state = ERROR;
                }
                break;
        }
    } while (! is.eof() && state != COMPLETE && state != ERROR);
    return state == COMPLETE;
}

bool Json::parseNull( std::istream& is )
{
    enum parseState
    {
        ERROR,
        EN,
        EU,
        EL,
        EL2,
        COMPLETE
    };

    parseState state = EN;
    assert( ! is.eof() );
    do
    {
        char c = is.get();
        switch (c)
        {
            case 'n':
                if (state == EN)
                    state = EU;
                else
                    state = ERROR;
                break;
            case 'u':
                if (state == EU)
                    state = EL;
                else
                    state = ERROR;
                break;
            case 'l':
                if (state == EL)
                    state = EL2;
                else if (state == EL2)
                {
                    state = COMPLETE;
                    // Nothing to do as node is null already.
                }
                else
                    state = ERROR;
                break;
            default:
                state = ERROR;
                break;
        }
        if (state == ERROR) is.unget();
    } while (! is.eof() && state != COMPLETE && state != ERROR);
    return state == COMPLETE;
}

bool Json::parseBool( std::istream& is )
{
    enum parseState
    {
        ERROR,
        TE_OR_EF,
        AR,
        EU,
        EE,
        AE,
        EL,
        ES,
        COMPLETE
    };

    bool value = true;
    parseState state = TE_OR_EF;
    assert( ! is.eof() );
    do
    {
        char c = is.get();
        switch (c)
        {
            case 't':
                if (state == TE_OR_EF)
                {
                    state = AR;
                    value = true;
                }
                else
                    state = ERROR;
                break;
            case 'r':
                if (state == AR)
                    state = EU;
                else
                    state = ERROR;
                break;
            case 'u':
                if (state == EU)
                    state = EE;
                else
                    state = ERROR;
                break;
            case 'e':
                if (state == EE)
                {
                    state = COMPLETE;
                    boolean = new bool( value );
                }
                else
                    state = ERROR;
                break;
            case 'f':
                if (state == TE_OR_EF)
                {
                    state = AE;
                    value = false;
                }
                else
                    state = ERROR;
                break;
            case 'a':
                if (state == AE)
                    state = EL;
                else
                    state = ERROR;
                break;
            case 'l':
                if (state == EL)
                    state = ES;
                else
                    state = ERROR;
                break;
            case 's':
                if (state == ES)
                    state = EE;
                else
                    state = ERROR;
                break;
            default:
                state = ERROR;
                break;
        }
        if (state == ERROR) is.unget();
    } while (! is.eof() && state != COMPLETE && state != ERROR);
    return state == COMPLETE;
}

bool Json::parseNumber( std::istream& is )
{
    enum parseState
    {
        ERROR,
        MINUS_OR_DIGIT,
        DIGIT_BEFORE_POINT,
        DIGITS_BEFORE_POINT,
        POINT_OR_OTHER,
        DIGIT_AFTER_POINT,
        DIGITS_AFTER_POINT,
        PLUS_OR_MINUS,
        DIGIT_AFTER_EE,
        DIGITS_AFTER_EE,
        COMPLETE
    };

    std::string value;
    parseState state = MINUS_OR_DIGIT;
    assert( ! is.eof() );
    do
    {
        char c = is.get();
        switch (c)
        {
            case '-':
                if (state == MINUS_OR_DIGIT)
                    state = DIGIT_BEFORE_POINT;
                else if (state == PLUS_OR_MINUS)
                    state = DIGIT_AFTER_EE;
                else
                    state = ERROR;
                if (state != ERROR) value.push_back( c );
                break;
            case '+':
                if (state == PLUS_OR_MINUS)
                    state = DIGIT_AFTER_EE;
                else
                    state = ERROR;
                if (state != ERROR) value.push_back( c );
                break;
            case '0':
                if (state == MINUS_OR_DIGIT)
                    state = POINT_OR_OTHER;
                else if (state == DIGIT_BEFORE_POINT)
                    state = POINT_OR_OTHER;
                else if (state == DIGITS_BEFORE_POINT)
                    state = DIGITS_BEFORE_POINT;
                else if (state == DIGIT_AFTER_POINT)
                    state = DIGITS_AFTER_POINT;
                else if (state == DIGITS_AFTER_POINT)
                    state = DIGITS_AFTER_POINT;
                else if (state == DIGITS_AFTER_EE)
                    state = DIGITS_AFTER_EE;
                else if (state == PLUS_OR_MINUS)
                    state = DIGITS_AFTER_EE;
                else if (state == DIGIT_AFTER_EE)
                    state = DIGITS_AFTER_EE;
                else
                    state = ERROR;
                if (state != ERROR) value.push_back( c );
                break;
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                if (state == MINUS_OR_DIGIT)
                    state = DIGITS_BEFORE_POINT;
                else if (state == DIGIT_BEFORE_POINT)
                    state = DIGITS_BEFORE_POINT;
                else if (state == DIGITS_BEFORE_POINT)
                    state = DIGITS_BEFORE_POINT;
                else if (state == DIGIT_AFTER_POINT)
                    state = DIGITS_AFTER_POINT;
                else if (state == DIGITS_AFTER_POINT)
                    state = DIGITS_AFTER_POINT;
                else if (state == PLUS_OR_MINUS)
                    state = DIGITS_AFTER_EE;
                else if (state == DIGIT_AFTER_EE)
                    state = DIGITS_AFTER_EE;
                else if (state == DIGITS_AFTER_EE)
                    state = DIGITS_AFTER_EE;
                else
                    state = ERROR;
                if (state != ERROR) value.push_back( c );
                break;
            case '.':
                if (state == POINT_OR_OTHER)
                    state = DIGIT_AFTER_POINT;
                else if (state == DIGITS_BEFORE_POINT)
                    state = DIGIT_AFTER_POINT;
                else if (state == DIGIT_BEFORE_POINT)
                    state = DIGIT_AFTER_POINT;
                else
                    state = ERROR;
                if (state != ERROR) value.push_back( c );
                break;
            case 'e':
            case 'E':
                if (state == DIGIT_AFTER_POINT)
                    state = PLUS_OR_MINUS;
                else if (state == DIGITS_AFTER_POINT)
                    state = PLUS_OR_MINUS;
                else if (state == DIGIT_BEFORE_POINT)
                    state = PLUS_OR_MINUS;
                else if (state == DIGITS_BEFORE_POINT)
                    state = PLUS_OR_MINUS;
                else if (state == POINT_OR_OTHER)
                    state = PLUS_OR_MINUS;
                else
                    state = ERROR;
                if (state != ERROR) value.push_back( c );
                break;
            default:
//                if (c == '}' || c == ']' || c == ',' || c == ':')
                    is.unget();
                    if (state == DIGITS_AFTER_EE || state == DIGITS_AFTER_POINT || state == POINT_OR_OTHER || state == DIGITS_BEFORE_POINT)
                    {
                        num = new double;
                        *num = atof( value.c_str() );
                        state = COMPLETE;
                    }
                    else
                        state = ERROR;
//                else
//                    state = ERROR;
                break;
        }
        if (state == ERROR) is.unget();
    } while (! is.eof() && state != COMPLETE && state != ERROR);
    return state == COMPLETE;
}

bool Json::parseString( std::istream& is, std::string* useThis )
{
    enum parseState
    {
        ERROR,
        QUOTE,
        CHARS,
        ESCAPE,
        HEX1,
        HEX2,
        HEX3,
        HEX4,
        ENDSTRING,
        COMPLETE
    };

    std::string hexNum;
    std::string value;
    parseState state = QUOTE;
    assert( ! is.eof() );
    do
    {
        char c = is.get();
        switch (c)
        {
            case '\"':
                if (state == QUOTE)
                    state = CHARS;
                else if (state == ESCAPE)
                {
                    value.push_back( c );
                    state = CHARS;
                }
                else if (state == CHARS)
                {
                    state = ENDSTRING;
                }
                else
                    state = ERROR;
                break;
            case '\\':
                if (state == CHARS)
                    state = ESCAPE;
                else if (state == ESCAPE)
                {
                    value.push_back( c );
                    state = CHARS;
                }
                else
                    state = ERROR;
                break;
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            case 'a':
            case 'c':
            case 'd':
            case 'e':
            case 'A':
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
                if (state == HEX1)
                {
                    hexNum.push_back( c );
                    state = HEX2;
                }
                else if (state == HEX2)
                {
                    hexNum.push_back( c );
                    state = HEX3;
                }
                else if (state == HEX3)
                {
                    hexNum.push_back( c );
                    state = HEX4;
                }
                else if (state == HEX4)
                {
                    hexNum.push_back( c );
                    state = CHARS;
                }
                else if (state == CHARS)
                {
                    value.push_back( c );
                    state = CHARS;
                }
                else
                    state = ERROR;
                break;
            case 'b':
            case 'f':
                if (state == HEX1)
                {
                    hexNum.push_back( c );
                    state = HEX2;
                }
                else if (state == HEX2)
                {
                    hexNum.push_back( c );
                    state = HEX3;
                }
                else if (state == HEX3)
                {
                    hexNum.push_back( c );
                    state = HEX4;
                }
                else if (state == HEX4)
                {
                    hexNum.push_back( c );
                    state = CHARS;
                }
                else if (state == ESCAPE)
                {
                    if (c == 'f')
                        value.push_back('\f');
                    else if (c == 'b')
                        value.push_back('\b');
                    state = CHARS;
                }
                else if (state == CHARS)
                {
                    value.push_back( c );
                    state = CHARS;
                }
                else
                    state = ERROR;
                break;
            case '/':
            case 'n':
            case 'r':
            case 't':
                if (state == ESCAPE)
                {
                    if (c == 't')
                        value.push_back('\t');
                    else if (c == 'r')
                        value.push_back('\r');
                    else if (c == 'n')
                        value.push_back('\n');
                    else if (c == '/')
                        value.push_back('/');
                    state = CHARS;
                }
                else if (state == CHARS)
                {
                    value.push_back( c );
                    state = CHARS;
                }
                else
                    state = ERROR;
                break;
            case 'u':
                if (state == ESCAPE)
                {
                    hexNum.clear();
                    state = HEX1;
                }
                else if (state == CHARS)
                {
                    value.push_back( c );
                    state = CHARS;
                }
                else
                    state = ERROR;
                break;
            default:
                if (state == ENDSTRING)
                {
//                    if (c == '}' || c == ']' || c == ',' || c == ':')
                    {
                        is.unget();
                        if (useThis)
                            *useThis = value;
                        else
                            val = new std::string( value );
                        state = COMPLETE;
                    }
//                    else
//                        state = ERROR;
                }
                else if (state == CHARS)
                    value.push_back( c );
                else
                    state = ERROR;
                break;
        }
        if (state == ERROR) is.unget();
    } while (! is.eof() && state != COMPLETE && state != ERROR);
    return state == COMPLETE;
}

bool Json::parse( std::istream& is, bool allowValues )
{
    bool result = false;
    if (! is.eof())
    {
        char c = is.get();
        is.unget();
        if (c == '{')
            result = parseObject( is );
        else if (c == '[')
            result = parseArray( is );
        else if (allowValues && c == '"')
            result = parseString( is );
        else if (allowValues && ((c >= '0' && c <= '9') || c == '-'))
            result = parseNumber( is );
        else if (allowValues && (c == 't' || c == 'f'))
            result = parseBool( is );
        else if (allowValues && c == 'n')
            result = parseNull( is );
    } 
    return result;
}

bool Json::parse( const std::string& ss, bool allowValues )
{
    std::istringstream iss( ss );
    return parse( iss, allowValues );
}

Json* Json::atXPath( const std::string& path )
{
    if (path.empty() || path == "/") return this;
    if (obj)
    {
        if (path.empty()) return 0;
        size_t pos = path.find_first_of( '/', 1 );
        std::string level = path.substr( 1, pos-1 );
        for (objType::iterator i = obj->begin(); i != obj->end(); ++i)
        {
            if (level == i->first)
            {
                if (pos == std::string::npos)
                    return i->second->atXPath( "" );
                else
                    return i->second->atXPath( path.substr(pos) );
            }
        }
        return 0;
    }
    else
    {
        if (path.length() < 4) return 0;
        if (path[1] != '[') return 0;
        size_t pos = path.find_first_of( ']' );
        if (pos == std::string::npos) return 0;
        std::string level = path.substr( 2, pos-2 );
        int num = atoi( level.c_str() );
        assert( num >= 0 );
        if ((unsigned int) num >= arr->size()) return 0;
        return arr->operator[](num)->atXPath( path.substr(pos+1) );
    }
}

void Json::allAtXPath( const std::string& path, std::vector< Json* >& result )
{
    if (path.empty() || path == "/") result.push_back( this );
    else if (obj)
    {
        std::string tempPath = path;
        if (tempPath.empty()) tempPath = "/*";
        size_t pos = tempPath.find_first_of( '/', 1 );
        std::string level = tempPath.substr( 1, pos-1 );
        for (objType::iterator i = obj->begin(); i != obj->end(); ++i)
        {
            if (level == i->first || level == "*")
            {
                if (pos == std::string::npos)
                    i->second->allAtXPath( "", result );
                else
                    i->second->allAtXPath( tempPath.substr(pos), result );
            }
        }
    }
    else if (arr)
    {
        std::string tempPath = path;
        if (tempPath.empty()) tempPath = "/[*]"; // Match all
        if (tempPath.length() < 4) return;
        if (tempPath[1] != '[') return;
        size_t pos = tempPath.find_first_of( ']' );
        if (pos == std::string::npos) return;
        std::string level = tempPath.substr( 2, pos-2 );
        if (level == "*")
        {
            for (arrType::iterator i = arr->begin(); i != arr->end(); ++i)
            {
                (*i)->allAtXPath( tempPath.substr(pos+1), result );
            }
        }
        else
        {
            int num = atoi( level.c_str() );
            assert( num >= 0 );
            if ((unsigned int) num >= arr->size()) return;
            arr->operator[](num)->allAtXPath( tempPath.substr(pos+1), result );
        }
    }
}

bool Json::replaceWith( const std::string& replacement )
{
    Json newbit;
    if (newbit.parse( replacement, true ))
    {
        clearAndDestroy(); // Remove what is there already;
        *this = newbit;
        newbit.clear(); // So that memory is not deleted.
        return true;
    }
    return false;
}

void Json::clear( void )
{
    obj = 0;
    arr = 0;
    val = 0;
    boolean = 0;
    num = 0;
}

void Json::clearAndDestroy( void )
{
    if (obj)
    {
        for (objType::const_iterator i = obj->begin(); i != obj->end(); ++i)
            delete i->second;
    }
    delete obj;
    obj = 0;
    if (arr)
    {
        for (arrType::const_iterator i = arr->begin(); i != arr->end(); ++i)
            delete *i;
    }
    delete arr;
    arr = 0;
    delete val;
    val = 0;
    delete num;
    num = 0;
    delete boolean;
    boolean = 0;
}

bool Json::replaceAllAtXPath( const std::string& path, const std::string& replacement )
{
    std::vector< Json* > result;
    allAtXPath( path, result );
    for (std::vector< Json* >::const_iterator i = result.begin(); i != result.end(); ++i)
    {
        if (!(*i)->replaceWith( replacement ))
            return false;
    }
    return true;
}

void Json::replaceStringAtXPath( const std::string& path, const std::string& replacement )
{
    std::vector< Json* > result;
    allAtXPath( path, result );
    for (std::vector< Json* >::const_iterator i = result.begin(); i != result.end(); ++i)
    {
        (*i)->setString( replacement );
    }
}

void Json::replaceBoolAtXPath( const std::string& path, bool replacement )
{
    std::vector< Json* > result;
    allAtXPath( path, result );
    for (std::vector< Json* >::const_iterator i = result.begin(); i != result.end(); ++i)
    {
        (*i)->setBool( replacement );
    }
}

void Json::replaceNumberAtXPath( const std::string& path, double replacement )
{
    std::vector< Json* > result;
    allAtXPath( path, result );
    for (std::vector< Json* >::const_iterator i = result.begin(); i != result.end(); ++i)
    {
        (*i)->setNumber( replacement );
    }
}

void Json::replaceNullAtXPath( const std::string& path )
{
    std::vector< Json* > result;
    allAtXPath( path, result );
    for (std::vector< Json* >::const_iterator i = result.begin(); i != result.end(); ++i)
    {
        (*i)->setNull();
    }
}

void Json::spool( std::ostream& os ) const
{
    if (obj)
    {
        bool skipComma = true;
        os << "{";
        for (objType::const_iterator i = obj->begin(); i != obj->end(); ++i)
        {
            if (skipComma)
                skipComma = false;
            else
                os << ",";
            os << "\"" << i->first << "\"";
            os << ":";
            i->second->spool( os );
        }
        os << "}";
    }
    else if (arr)
    {
        bool skipComma = true;
        os << "[";
        for (arrType::const_iterator i = arr->begin(); i != arr->end(); ++i)
        {
            if (skipComma)
                skipComma = false;
            else
                os << ",";
            (*i)->spool( os );
        }
        os << "]";
    }
    else if (val)
    {
        os << "\"" << *val << "\"";
    }
    else if (boolean)
    {
        os << (*boolean?"true":"false");
    }
    else if (num)
    {
        os << *num;
    }
    else
    {
        os << "null";
    }
}

bool Json::isNull( void ) const
{
    return (! obj && ! arr && ! val && ! boolean && ! num);
}

void Json::setString( const std::string& value )
{
    if (val) *val = value;
    else
    {
        clearAndDestroy();
        val = new std::string( value );
    }
}

void Json::setBool( bool value )
{
    if (boolean) *boolean = value;
    else
    {
        clearAndDestroy();
        boolean = new bool( value );
    }
}

void Json::setNumber( double value )
{
    if (num) *num = value;
    else
    {
        clearAndDestroy();
        num = new double( value );
    }
}

void Json::setNull( void )
{
    clearAndDestroy();
}
}
