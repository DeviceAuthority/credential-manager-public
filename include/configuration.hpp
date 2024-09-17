/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a configuration reader.
 */
#ifndef CONFIGURATION_HPP
#define CONFIGURATION_HPP

#include <string>
#include <map>
#if defined(USETHREADING)
#include <pthread.h>
#endif // #if defined(USETHREADING)

#define NUMERIC_TYPE   0
#define TEXT_TYPE      1
#define ESCTEXTDB_TYPE 2
#define LOCATION_TYPE  3
#define MODE_TYPE      4
#define TEXTLOWER_TYPE 5
#define BOOL_TYPE      6

class Configuration
{
public:
    Configuration();
    virtual ~Configuration();

    bool parse(const std::string fullPathOfFile = "config.conf");
    bool exists(const std::string& item) const;
    std::string lookup(const std::string& item) const;
    long lookupAsLong(const std::string& item) const;

    bool override(const std::string& item, const std::string& value);
    std::string path() const;

protected:
    void addValidationMap(std::map< std::string, int >& validationMap, const std::map< std::string, std::string >& defaults);

private:
    enum Type
    {
        NUMERIC,
        TEXT,
        ESCTEXTDB,
        LOCATIONTYPE,
        MODETYPE,
        TEXTLOWER,
        BOOLTYPE,
    };

    typedef std::map< std::string, Type > ValidationContainer;
    typedef std::map< std::string, std::string > DefaultsContainer;
    typedef std::map< std::string, std::string > ConfigurationContainer;

    std::string escapeSpecialChars(const std::string& from) const;
    bool isNumeric(const std::string& value) const;
    bool isLocationType(const std::string& value) const;
    bool isModeType(const std::string& value) const;
    bool isBoolType(const std::string& value) const;
    bool validate(const std::string& item, const std::string& value) const;
    std::string upperCase(const std::string& item) const;

    void add(const std::string& item, const std::string& value);
    void trimValue(std::string& value);

private:
    static const std::string noDefault_;
    ConfigurationContainer data_;
    ValidationContainer validationMap_;
    DefaultsContainer defaults_;
    std::string fullPathOfFile_;
#if defined(USETHREADING)
    static pthread_mutex_t m_config_lock;
#endif // #if defined(USETHREADING)
};

extern Configuration config;

#endif // #ifndef CONFIGURATION_HPP
