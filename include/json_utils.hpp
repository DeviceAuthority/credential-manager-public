
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Contains utility functions for processing JSON
 */
#ifndef JSON_UTILS_HPP
#define JSON_UTILS_HPP

#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <iomanip>
#include <sstream>

class JsonUtils
{
public:
    static const std::string getJSONField(const rapidjson::Value &json, const std::string &name, const char *defaultVal = 0)
    {
        std::string field;

        if (json.HasMember(name.c_str()))
        {
            field = json[name.c_str()].GetString();
        }
        if (field.empty())
        {
            if (defaultVal)
            {
                field.assign(defaultVal);
            }
            else
            {
                throw std::runtime_error("Missing field: " + name + " (was expected).");
            }
        }

        return field;
    }

    static const std::string escapeJSON(const std::string &s)
    {
        std::ostringstream o;
        for (size_t i = 0; i < s.size(); i++)
        {
            const char c = s.at(i);
            switch (c)
            {
            case '"':
                o << "\\\"";
                break;
            case '\\':
                o << "\\\\";
                break;
            case '\b':
                o << "\\b";
                break;
            case '\f':
                o << "\\f";
                break;
            case '\n':
                o << "\\n";
                break;
            case '\r':
                o << "\\r";
                break;
            case '\t':
                o << "\\t";
                break;

            default:
                if ('\x00' <= c && c <= '\x1f')
                {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                }
                else
                {
                    o << c;
                }
                break;
            }
        }
        return o.str();
    }
};

#endif // #ifndef JSON_UTILS_HPP
