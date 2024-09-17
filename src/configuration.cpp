/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a configuration reader.
 */
#include "constants.hpp"
#include "configuration.hpp"
#include <cassert>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <stdlib.h>
#include "log.hpp"
#include "utils.hpp"

const std::string Configuration::noDefault_ = "NODEF";

#if defined(USETHREADING)
pthread_mutex_t Configuration::m_config_lock = PTHREAD_MUTEX_INITIALIZER;
#endif // #if defined(USETHREADING)

Configuration::Configuration()
{
    validationMap_.insert(std::pair<std::string, Type>(CFG_KEYCACHETIMEOUT, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_KEYCACHETIMEOUT, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_POLICYCACHETIMEOUT, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_POLICYCACHETIMEOUT, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_POLICYCACHESIZEITEMS, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_POLICYCACHESIZEITEMS, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_MAXIMUMCLIENTS, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_MAXIMUMCLIENTS, "100"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_LOCALPORTNUMBER, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_LOCALPORTNUMBER, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_REMOTEHOSTADDRESS, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_REMOTEHOSTADDRESS, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_REMOTEPORTNUMBER, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_REMOTEPORTNUMBER, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_LOGFILENAME, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_LOGFILENAME, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_SYSLOGHOST, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_SYSLOGHOST, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_SYSLOGPORT, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_SYSLOGPORT, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_AVERAGEPROCESSINGTIMEEVERY, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_AVERAGEPROCESSINGTIMEEVERY, "0"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_MEMORYBLOCKSIZE, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_MEMORYBLOCKSIZE, "2048"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_KEEPCONNECTIONBUFFERS, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_KEEPCONNECTIONBUFFERS, "0"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_INBOUNDSOCKETQUEUELENGTH, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_INBOUNDSOCKETQUEUELENGTH, "10"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_ACCEPTUPTOCONNECTIONSPERLOOP, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_ACCEPTUPTOCONNECTIONSPERLOOP, "5"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_SLEEPPERIOD, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_SLEEPPERIOD, "10"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_PROXYCONNLOOPWAIT, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_PROXYCONNLOOPWAIT, "20"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_ENABLEALWAYSONPROXY, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_ENABLEALWAYSONPROXY, "0"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_TCPINPUTBUFFERSIZE, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_TCPINPUTBUFFERSIZE, "1"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_TCPOUTPUTBUFFERSIZE, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_TCPOUTPUTBUFFERSIZE, "1"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_WORKERTHREADS, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_WORKERTHREADS, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_APIURL, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_APIURL, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_CERTIFICATEPATH, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_CERTIFICATEPATH, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_CERTIFICATEPASSWORD, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_CERTIFICATEPASSWORD, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_APIKEY, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_APIKEY, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_APISECRET, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_APISECRET, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_DBHOST, ESCTEXTDB));
    defaults_.insert(std::pair<std::string, std::string>(CFG_DBHOST, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_DBNAME, ESCTEXTDB));
    defaults_.insert(std::pair<std::string, std::string>(CFG_DBNAME, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_DBUSER, ESCTEXTDB));
    defaults_.insert(std::pair<std::string, std::string>(CFG_DBUSER, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_DBPASSWORD, ESCTEXTDB));
    defaults_.insert(std::pair<std::string, std::string>(CFG_DBPASSWORD, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_DAUSERID, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_DAUSERID, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_DAAPIURL, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_DAAPIURL, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_DEVICENAME, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_DEVICENAME, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_LOCATION, LOCATIONTYPE));
    defaults_.insert(std::pair<std::string, std::string>(CFG_LOCATION, noDefault_));
    validationMap_.insert(std::pair<std::string, Type>(CFG_MODE, MODETYPE));
    defaults_.insert(std::pair<std::string, std::string>(CFG_MODE, "AES"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_USEBASE64, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_USEBASE64, "1"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_ROTATELOGAFTER, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_ROTATELOGAFTER, "1024000"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_ENDDACONFIG, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_ENDDACONFIG, "true"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_REMOTECONNECTIONSSL, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_REMOTECONNECTIONSSL, "0"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_UDI, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_UDI, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_UDITYPE, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_UDITYPE, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_KEYSCALER_PROTOCOL, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_KEYSCALER_PROTOCOL, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_KEYSCALER_HOST, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_KEYSCALER_HOST, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_KEYSCALER_PORT, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_KEYSCALER_PORT, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_SCHEDULEINTERVAL, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_SCHEDULEINTERVAL, "10"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_UPDATEINTERVAL, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_UPDATEINTERVAL, "10"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_RETRYINTERVAL, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_RETRYINTERVAL, "10"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_CAPATH, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_CAPATH, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_CAFILE, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_CAFILE, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_USEIDCTOKEN, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_USEIDCTOKEN, "0"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_IDCTOKENTTL, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_IDCTOKENTTL, "0"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_KEYSTORE_PROVIDER, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_KEYSTORE_PROVIDER, "SunPKCS11-NSS"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_PROTOCOL, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_PROTOCOL, "HTTP"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_MQTT_TOPIC_IN, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_MQTT_TOPIC_IN, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_MQTT_TOPIC_OUT, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_MQTT_TOPIC_OUT, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_DEVICE_ROLE, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_DEVICE_ROLE, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_BROKER_HOST, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_BROKER_HOST, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_BROKER_PORT, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_BROKER_PORT, "1883"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_DAPLATFORM, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_DAPLATFORM, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_USERAGENT, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_USERAGENT, ""));

    validationMap_.insert(std::pair<std::string, Type>(CFG_METADATAFILE, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_METADATAFILE, "metadata.cfg"));

    validationMap_.insert(std::pair<std::string, Type>(CFG_PROXY, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_PROXY, ""));

    validationMap_.insert(std::pair<std::string, Type>(CFG_PROXY_CREDENTIALS, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_PROXY_CREDENTIALS, ""));

    validationMap_.insert(std::pair<std::string, Type>(CFG_POLL_TIME_FOR_REQUESTED_DATA, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_POLL_TIME_FOR_REQUESTED_DATA, "60"));

    validationMap_.insert(std::pair<std::string, Type>(CFG_NODE, TEXTLOWER));
    defaults_.insert(std::pair<std::string, std::string>(CFG_NODE, ""));

    validationMap_.insert(std::pair<std::string, Type>(CFG_HEARTBEAT_INTERVAL_S, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_HEARTBEAT_INTERVAL_S, "-1"));

    validationMap_.insert(std::pair<std::string, Type>(CFG_EVENT_NOTIFICATION_LIBRARIES, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_EVENT_NOTIFICATION_LIBRARIES, ""));

    validationMap_.insert(std::pair<std::string, Type>(CFG_RETRY_AUTHORIZATION_INTERVAL_S, NUMERIC));
    defaults_.insert(std::pair<std::string, std::string>(CFG_RETRY_AUTHORIZATION_INTERVAL_S, "15"));

    validationMap_.insert(std::pair<std::string, Type>(CFG_USE_UDI_AS_DEVICE_IDENTITY, BOOLTYPE));
    defaults_.insert(std::pair<std::string, std::string>(CFG_USE_UDI_AS_DEVICE_IDENTITY, "FALSE"));

    validationMap_.insert(std::pair<std::string, Type>(CFG_EXT_DDKG_UDI_PROPERTY, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_EXT_DDKG_UDI_PROPERTY, ""));

    validationMap_.insert(std::pair<std::string, Type>(CFG_DDKG_ROOT_FS, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_DDKG_ROOT_FS, ""));

    validationMap_.insert(std::pair<std::string, Type>(CFG_OSSL_PROVIDER, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_OSSL_PROVIDER, ""));

#if defined(WIN32)
    validationMap_.insert(std::pair<std::string, Type>(CFG_DDKGLIB, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_DDKGLIB, "npUDADDK.dll"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_LIBDIR, TEXT));
    defaults_.insert(std::pair<std::string, std::string>(CFG_LIBDIR, ""));
    validationMap_.insert(std::pair<std::string, Type>(CFG_FORCE_MS_ENHANCED_PROVIDER, BOOLTYPE));
    defaults_.insert(std::pair<std::string, std::string>(CFG_FORCE_MS_ENHANCED_PROVIDER, "FALSE"));
    validationMap_.insert(std::pair<std::string, Type>(CFG_STORE_FULL_CERTIFICATE_CHAIN, BOOLTYPE));
    defaults_.insert(std::pair<std::string, std::string>(CFG_STORE_FULL_CERTIFICATE_CHAIN, "FALSE"));
#endif // #if defined(WIN32)
}

Configuration::~Configuration()
{
}

bool Configuration::isNumeric(const std::string &value) const
{
    return (value.find_first_not_of("-0123456789") == std::string::npos);
}

bool Configuration::isLocationType(const std::string &value) const
{
    std::string ucValue = upperCase(value);

    return ((ucValue == "CLIENT_SIDE") || (ucValue == "SERVER_SIDE"));
}

bool Configuration::isModeType(const std::string &value) const
{
    std::string ucValue = upperCase(value);

    return ((ucValue == "AES") || (ucValue == "X509"));
}

bool Configuration::isBoolType(const std::string& value) const
{
    std::string ucValue = upperCase(value);

    return ((ucValue == "TRUE") || (ucValue == "FALSE"));
}

bool Configuration::validate(const std::string &item, const std::string &value) const
{
    std::string ucItem = upperCase(item);
    bool valid = false;
    ValidationContainer::const_iterator f = validationMap_.find(ucItem);

    if (f != validationMap_.end())
    {
        switch (f->second)
        {
        case NUMERIC:
            valid = isNumeric(value);
            break;

        case TEXT:
        case TEXTLOWER:
            valid = true;
            break;

        case ESCTEXTDB:
            valid = true;
            break;

        case LOCATIONTYPE:
            valid = isLocationType(value);
            break;

        case MODETYPE:
            valid = isModeType(value);
            break;

        case BOOLTYPE:
            valid = isBoolType(value);
            break;

        default:
            assert("Unknown type used.");
        }
    }

    return valid;
}

// Some characters need to be escaped for use with the DB.
std::string Configuration::escapeSpecialChars(const std::string &from) const
{
    std::string to;

    for (std::string::const_iterator f = from.begin(); f != from.end(); ++f)
    {
        if ((*f == '\'') || (*f == '\\'))
        {
            to.push_back('\\');
        }
        to.push_back(*f);
    }

    return to;
}

void Configuration::add(const std::string &item, const std::string &value)
{
    std::string ucItem = upperCase(item);

    ValidationContainer::const_iterator f = validationMap_.find(ucItem);

    if (f != validationMap_.end())
    {
        switch (f->second)
        {
        case NUMERIC:
        case TEXT:
            data_[ucItem] = value;
            break;

        case ESCTEXTDB:
            data_[ucItem] = escapeSpecialChars(value);
            break;

        case LOCATIONTYPE:
        case MODETYPE:
            data_[ucItem] = upperCase(value);
            break;
        case TEXTLOWER:
            data_[ucItem] = utils::toLower(value);
            break;
        case BOOLTYPE:
            data_[ucItem] = upperCase(value);
            break;
        default:
            assert("Unknown type used.");
        }
    }
}

std::string Configuration::upperCase(const std::string &item) const
{
    std::string ucItem = item;

    std::transform(ucItem.begin(), ucItem.end(), ucItem.begin(), toupper);

    return ucItem;
}

bool Configuration::exists(const std::string &item) const
{
#if defined(USETHREADING)
    pthread_mutex_lock(&m_config_lock);
#endif // #if defined(USETHREADING)

    ConfigurationContainer::const_iterator f = data_.find(upperCase(item));

#if defined(USETHREADING)
    pthread_mutex_unlock(&m_config_lock);
#endif // #if defined(USETHREADING)

    return (f != data_.end());
}

std::string Configuration::lookup(const std::string &item) const
{
#if defined(USETHREADING)
    pthread_mutex_lock(&m_config_lock);
#endif // #if defined(USETHREADING)

    std::string result = "";
    ConfigurationContainer::const_iterator f = data_.find(upperCase(item));

    if (f == data_.end())
    {
        DefaultsContainer::const_iterator d = defaults_.find(upperCase(item));

        if (d != defaults_.end())
        {
            if (d->second != noDefault_)
            {
                result = d->second;
            }
            else
            {
                Log::getInstance()->printf(Log::Error, " %s Unknown configuration item '%s', exiting....", __func__, item.c_str());
            }
        }
        else
        {
            Log::getInstance()->printf(Log::Error, " %s Unknown configuration item '%s', exiting....", __func__, item.c_str());
        }
    }
    else
    {
        result = f->second;
    }

#if defined(USETHREADING)
    pthread_mutex_unlock(&m_config_lock);
#endif // #if defined(USETHREADING)

    return result;
}

long Configuration::lookupAsLong(const std::string &item) const
{
    std::string value = lookup(item);

    if (!isNumeric(value))
    {
        Log::getInstance()->printf(Log::Error, " %s '%s' is non numeric, exiting....", __func__, item.c_str());
        exit(1);
    }

    return strtol(value.c_str(), NULL, 0);
}

// bool Configuration::parse(const char *fullPathOfFile)
bool Configuration::parse(const std::string fullPathOfFile)
{
    bool parsed = true;
    std::ifstream ifs(fullPathOfFile.c_str());

    if (ifs.good())
    {
        while (!ifs.eof())
        {
            std::string buffer;

            getline(ifs, buffer);
            if (buffer.empty() || (buffer[0] == '#'))
            {
                continue;
            }

            size_t pos = buffer.find(" = ");

            if (pos == std::string::npos)
            {
                Log::getInstance()->printf(Log::Error, " %s Invalid line in configuration: %s", __func__, buffer.c_str());
                parsed = false;
                break;
            }

            std::string item = buffer.substr(0, pos);
            std::string value = buffer.substr(pos + 3);

            trimValue(value);
            if (!validate(item, value))
            {
                Log::getInstance()->printf(Log::Error, " %s Invalid configuration item/value: %s", __func__, item.c_str());
                parsed = false;
                break;
            }
            add(item, value);
        }
    }
    else
    {
        Log::getInstance()->printf(Log::Error, " %s Unable to open configuration file: %s", __func__, fullPathOfFile.c_str());
        parsed = false;
    }
    ifs.close();

    if (parsed)
    {
        fullPathOfFile_ = fullPathOfFile;
    }

    return parsed;
}

std::string Configuration::path() const
{
    return fullPathOfFile_;
}

void Configuration::trimValue(std::string &value)
{
    std::string whitespaces(" \t\f\v\n\r");
    size_t last = value.find_last_not_of(whitespaces);

    if (last != std::string::npos)
    {
        value.erase(last + 1);
    }

    size_t first = value.find_first_not_of(whitespaces);

    if (first != std::string::npos)
    {
        value.erase(0, first);
    }
    if (first == std::string::npos) // empty string..all spaces??
    {
        value = "";
    }
}

bool Configuration::override(const std::string &item, const std::string &value)
{
    if (validate(item, value))
    {
        add(item, value);

        return true;
    }

    return false;
}

void Configuration::addValidationMap(std::map<std::string, int> &validationMap, const std::map<std::string, std::string> &defaults)
{
    for (std::map<std::string, int>::const_iterator it = validationMap.begin(); it != validationMap.end(); ++it)
    {
        if (it->second == NUMERIC_TYPE)
        {
            validationMap_.insert(std::pair<std::string, Type>(it->first, NUMERIC));
        }
        else if (it->second == TEXT_TYPE)
        {
            validationMap_.insert(std::pair<std::string, Type>(it->first, TEXT));
        }
        else if (it->second == ESCTEXTDB_TYPE)
        {
            validationMap_.insert(std::pair<std::string, Type>(it->first, ESCTEXTDB));
        }
        else if (it->second == LOCATION_TYPE)
        {
            validationMap_.insert(std::pair<std::string, Type>(it->first, LOCATIONTYPE));
        }
        else if (it->second == MODE_TYPE)
        {
            validationMap_.insert(std::pair<std::string, Type>(it->first, MODETYPE));
        }
        else if (it->second == TEXTLOWER_TYPE)
        {
            validationMap_.insert(std::pair<std::string, Type>(it->first, TEXTLOWER));
        }
        else if (it->second == BOOL_TYPE)
        {
            validationMap_.insert(std::pair<std::string, Type>(it->first, BOOLTYPE));
        }
    }
    for (std::map<std::string, std::string>::const_iterator it = defaults.begin(); it != defaults.end(); ++it)
    {
        defaults_.insert(std::pair<std::string, std::string>(it->first, it->second));
    }
}

// Global instance of the config
Configuration config;
