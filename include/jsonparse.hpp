#ifndef JSON_H
#define JSON_H

/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class provides JSON parsing functionality
 */

#include <iostream>
#include <vector>
#include <string>

namespace cryptosoft
{

class Json
{
    public:

        typedef std::vector< std::pair< std::string, Json* > > objType;
        typedef std::vector< Json* > arrType;

        Json() : obj(0), arr(0), val(0), boolean(0), num(0)
        {
        }

        ~Json();

        bool parse( std::istream& is, bool allowValues = false );
        bool parse( const std::string& ss, bool allowValues = false );

        Json* atXPath( const std::string& path );
        void allAtXPath( const std::string& path, std::vector< Json* >& result );
        bool replaceWith( const std::string& replacement );
        bool replaceAllAtXPath( const std::string& path, const std::string& replacement );
        void replaceStringAtXPath( const std::string& path, const std::string& replacement );
        void replaceBoolAtXPath( const std::string& path, bool replacement );
        void replaceNumberAtXPath( const std::string& path, double replacement );
        void replaceNullAtXPath( const std::string& path );
        void spool( std::ostream& os ) const;
        bool isNull( void ) const;
        void setString( const std::string& value );
        void setBool( bool value );
        void setNumber( double value );
        void setNull( void );

//    private:

        bool parseObject( std::istream& is );
        bool parseArray( std::istream& is );
        bool parseNull( std::istream& is );
        bool parseBool( std::istream& is );
        bool parseNumber( std::istream& is );
        bool parseString( std::istream& is, std::string* useThis = 0 );
        void clearAndDestroy( void );
        void clear( void );

        objType* obj;
        arrType* arr;
        std::string* val;
        bool* boolean;
        double* num;
};

}
#endif
