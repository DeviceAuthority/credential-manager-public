/**
 * \file 
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to DeviceAuthority Inc. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from DeviceAuthority Inc.
 */

#include <cstring>
#include <sstream>
#include "rapidjson/document.h"
#include "rapidjson/rapidjson.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "event_manager.hpp"
#include "log.hpp"

EventManagerBase* EventManager::mp_instance = nullptr;

bool EventManager::initialise(const std::string &event_library_names)
{
    std::string event_library_name;
    std::istringstream iss(event_library_names);

    while (std::getline(iss, event_library_name, ','))
    {
#if defined(USETHREADING)
        pthread_mutex_lock(&m_event_libs_mutex);
#endif // #if defined(USETHREADING)
        const auto event_lib_iter = m_event_libs.find(event_library_name);
#if defined(USETHREADING)
        pthread_mutex_unlock(&m_event_libs_mutex);
#endif // #if defined(USETHREADING)

        if (event_lib_iter != m_event_libs.end())
        {
            Log::getInstance()->printf(
                Log::Severity::Warning, 
                "Failed to load event library %s. Already loaded!", 
                event_library_name.c_str());
            continue;
        }
        std::unique_ptr<EventLib> event_lib(new EventLib(event_library_name));
        event_lib->initialise();

#if defined(USETHREADING)
        pthread_mutex_lock(&m_event_libs_mutex);
#endif // #if defined(USETHREADING)
        m_event_libs.emplace(std::pair<std::string, std::unique_ptr<EventLib>>(event_library_name, std::move(event_lib)));
#if defined(USETHREADING)
        pthread_mutex_unlock(&m_event_libs_mutex);
#endif // #if defined(USETHREADING)
    }

    return !m_event_libs.empty();
}

void EventManager::teardown()
{
#if defined(USETHREADING)
    pthread_mutex_lock(&m_event_libs_mutex);
#endif // #if defined(USETHREADING)
	
    for (auto event_lib_iter = m_event_libs.begin(); event_lib_iter != m_event_libs.end(); event_lib_iter++)
    {
        event_lib_iter->second->teardown();
        event_lib_iter->second.reset(nullptr);
    }
    m_event_libs.clear();

#if defined(USETHREADING)
    pthread_mutex_unlock(&m_event_libs_mutex);
#endif // #if defined(USETHREADING)
}

bool EventManager::notifyStartup(const std::string &udi)
{
    return notify("Startup", "Info", createJsonString("udi", udi));
}

bool EventManager::notifyShutdown(const std::string &udi)
{
    return notify("Shutdown", "Info", createJsonString("udi", udi));
}

bool EventManager::notifyHeartbeat()
{
    return notify("Heartbeat", "Info");
}

bool EventManager::notifyRegistrationRequired()
{
    return notify("Registration", "Required");
}

bool EventManager::notifyRegistrationInProgress()
{
    return notify("Registration", "InProgress");
}

bool EventManager::notifyRegistrationFailure(const std::string &error)
{
    return notify("Registration", "Failure", createJsonString("error", error));
}

bool EventManager::notifyRegistrationSuccess()
{
    return notify("Registration", "Success");
}

bool EventManager::notifyAuthorizationInProgress()
{
    return notify("Authorization", "InProgress");
}

bool EventManager::notifyAuthorizationFailure(const std::string &error)
{
    return notify("Authorization", "Failure", createJsonString("error", error));
}

bool EventManager::notifyAuthorizationSuccess()
{
    return notify("Authorization", "Success");
}

bool EventManager::notifyCertificateReceived()
{
    return notify("Certificate", "Received");
}

bool EventManager::notifyCertificateStored(const std::string &subject_name, const std::string &location, const std::string &provider_name, bool encrypted)
{
    return notify("Certificate", "Stored", createJsonString("subject_name", subject_name, "location", location, "provider", provider_name, "encrypted", encrypted ? "true" : "false"));
}

bool EventManager::notifyCertificateFailure(const std::string &error)
{
    return notify("Certificate", "Failure", createJsonString("error", error));
}

bool EventManager::notifyCertificateDataReceived()
{
    return notify("CertificateData", "Received");
}

bool EventManager::notifyPrivateKeyCreated()
{
    return notify("PrivateKey", "Created");
}

bool EventManager::notifyPrivateKeyReceived()
{
    return notify("PrivateKey", "Received");
}

bool EventManager::notifyPrivateKeyStored(const std::string &key_id, const std::string &location, const std::string &provider_name, bool encrypted)
{
    return notify("PrivateKey", "Stored", createJsonString("key_id", key_id, "location", location, "provider", provider_name, "encrypted", encrypted ? "true" : "false"));
}

bool EventManager::notifyPrivateKeyFailure(const std::string &error)
{
    return notify("PrivateKey", "Failure", createJsonString("error", error));
}

bool EventManager::notifyCSRCreated()
{
    return notify("CertificateSigningRequest", "Created");
}

bool EventManager::notifyCSRDelivered()
{
    return notify("CertificateSigningRequest", "Delivered");
}

bool EventManager::notifyCSRFailure(const std::string &error)
{
    return notify("CertificateSigningRequest", "Failure", createJsonString("error", error));
}

bool EventManager::notifyAPMReceived(const std::string &username)
{
    return notify("APM", "Received", createJsonString("username", username));
}

bool EventManager::notifyAPMSuccess(const std::string &username)
{
    return notify("APM", "Success", createJsonString("username", username));
}

bool EventManager::notifyAPMFailure(const std::string &error)
{
    return notify("APM", "Failure", createJsonString("error", error));
}

bool EventManager::notifySATReceived()
{
    return notify("SecureAssetTransfer", "Received");
}

bool EventManager::notifySATSuccess()
{
    return notify("SecureAssetTransfer", "Success");
}

bool EventManager::notifySATFailure(const std::string &error)
{
    return notify("SecureAssetTransfer", "Failure", createJsonString("error", error));
}

bool EventManager::notifyGroupMetadataReceived()
{
    return notify("GroupMetadata", "Received");
}

bool EventManager::notifyGroupMetadataSuccess()
{
    return notify("GroupMetadata", "Success");
}

bool EventManager::notifyGroupMetadataFailure(const std::string &error)
{
    return notify("GroupMetadata", "Failure", createJsonString("error", error));
}

EventManager::EventManager()
    : m_event_libs()
{
    #if defined(USETHREADING)
    m_event_libs_mutex = PTHREAD_MUTEX_INITIALIZER;
    #endif // #if defined(USETHREADING)
}

EventManager::~EventManager()
{
#if defined(USETHREADING)
    pthread_mutex_lock(&m_event_libs_mutex);
#endif // #if defined(USETHREADING)

    m_event_libs.clear();

#if defined(USETHREADING)
    pthread_mutex_unlock(&m_event_libs_mutex);
#endif // #if defined(USETHREADING)
}

bool EventManager::notify(const std::string &event_type, const std::string &notification_type, const std::string &context)
{
    bool success = true;
    
#if defined(USETHREADING)
    pthread_mutex_lock(&m_event_libs_mutex);
#endif // #if defined(USETHREADING)
	
    for (auto event_lib_iter = m_event_libs.begin(); event_lib_iter != m_event_libs.end(); event_lib_iter++)
    {
        success &= event_lib_iter->second->notify(event_type, notification_type, context);
    }

#if defined(USETHREADING)
    pthread_mutex_unlock(&m_event_libs_mutex);
#endif // #if defined(USETHREADING)

    return success;
}

const std::string EventManager::createJsonString(
    const std::string &key1, 
    const std::string &value1, 
    const std::string &key2, 
    const std::string &value2,
    const std::string &key3,
    const std::string &value3,
    const std::string &key4,
    const std::string &value4)
{
    rapidjson::Document root_document;
    root_document.SetObject();
    rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

    if (!key1.empty() && !value1.empty())
    {
        root_document.AddMember(
            rapidjson::StringRef(key1.c_str()), 
            rapidjson::Value(value1.c_str(), allocator).Move(), allocator);
    }
    if (!key2.empty() && !value2.empty())
    {
        root_document.AddMember(
            rapidjson::StringRef(key2.c_str()), 
            rapidjson::Value(value2.c_str(), allocator).Move(), allocator);
    }
    if (!key3.empty() && !value3.empty())
    {
        root_document.AddMember(
            rapidjson::StringRef(key3.c_str()),
            rapidjson::Value(value3.c_str(), allocator).Move(), allocator);
    }
    if (!key4.empty() && !value4.empty())
    {
        root_document.AddMember(
            rapidjson::StringRef(key4.c_str()),
            rapidjson::Value(value4.c_str(), allocator).Move(), allocator);
    }

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    root_document.Accept(writer);

    return std::string(strbuf.GetString());
}
