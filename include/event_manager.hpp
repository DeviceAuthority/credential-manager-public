/**
 * \file 
 *
 * \brief Singleton event manager class that calls the API of an external event library
 * library to notify it of events raised by credential manager.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to DeviceAuthority Inc. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from DeviceAuthority Inc.
 */

#ifndef EVENT_MANAGER_H
#define EVENT_MANAGER_H

#if defined(WIN32)
#include <Windows.h>
#endif // #if defined(WIN32)
#if defined(USETHREADING)
#include <pthread.h>
#endif // #if defined(USETHREADING)

#ifdef _WIN32
#include <codecvt>
#else // # ifdef _WIN32
#include <dlfcn.h>
#endif // # ifdef _WIN32

#include <map>
#include <memory>
#include <string>
#include <vector>
#include "event_manager_base.hpp"
#include "eventlib_api.h"
#include "log.hpp"

#if !defined(WIN32)
typedef void* HMODULE;
#endif // #ifndef _WIN32

#ifndef WIN32
// Non-Windows platform
typedef union
{
    EVENTLIB_STARTUP_PROC eventlib_startup;
    EVENTLIB_SHUTDOWN_PROC eventlib_shutdown;
    EVENTLIB_GETVERSION_PROC eventlib_getversion;
    EVENTLIB_NOTIFY_PROC eventlib_notify;
    void *obj;
} EventlibFuncPtrAlias;
#endif // #ifndef WIN32

class EventLib
{
    public:
    explicit EventLib(const std::string &event_library_name)
		: mp_handle(nullptr)
		, mp_eventlib_initialise(nullptr)
		, mp_eventlib_teardown(nullptr)
		, mp_eventlib_getversion(nullptr)
		, mp_eventlib_notify(nullptr)
    {
        loadLibrary(event_library_name);
    }

    ~EventLib()
    {
#ifndef _WIN32
        if (mp_handle)
        {
            dlclose(mp_handle);
            mp_handle = nullptr;
        }
#endif // #ifndef _WIN32
    }

    /// @brief Initialises the event library
    /// @return True if successfully initialised or no event library 
    /// available, false if failure to load event library
    bool initialise()
    {
        if (mp_eventlib_initialise)
        {
            mp_eventlib_initialise();
            return true;
        }
        return false;
    }

    /// @brief Shutdown the event library
    void teardown()
    {
        if (mp_eventlib_teardown)
        {
            mp_eventlib_teardown();
        }
    }

    /// @brief Get the version string from the event library
    /// @param[out] version_str Reference to object that will contain the returned function string
    /// @return True on success, else false
    bool getVersion(std::string &version)
    {
        if (mp_eventlib_getversion)
        {
            const char *result = mp_eventlib_getversion();
            if (result != nullptr)
            {
                version = std::string(result, std::strlen(result));
                return true;
            }
        }

        return false;
    }

    /// @brief Raises an event notification with the external event library
    /// @param event_type The event type string
    /// @param notification_type The notification type string
    /// @param context The associated context data to be delivered with the event
    /// @return True if successfully sent notification or no event library 
    /// loaded, false if failure to notify
    bool notify(const std::string &event_type, const std::string &notification_type, const std::string &context)
    {
        if (mp_eventlib_notify)
        {
            return mp_eventlib_notify(
                event_type.c_str(), 
                event_type.length(), 
                notification_type.c_str(), 
                notification_type.length(), 
                context.c_str(), 
                context.length()) == 1;
        }

        return false;
    }

    private:
    /// @brief The event library handle
    HMODULE mp_handle;

    /// @brief Event manager library API calls
    EVENTLIB_STARTUP_PROC mp_eventlib_initialise;
    EVENTLIB_SHUTDOWN_PROC mp_eventlib_teardown;
    EVENTLIB_GETVERSION_PROC mp_eventlib_getversion;
    EVENTLIB_NOTIFY_PROC mp_eventlib_notify;
	
	/// Disable copy constructors as each instance manages the handle to the dynamic lib
	/// Note that when we support C++11 fully (in Windows) we should replace these with `= delete`
    EventLib(const EventLib &);
    EventLib& operator=(EventLib &);

    /// @brief Loads the event library (if available)
    void loadLibrary(const std::string &event_library_name)
    {
        // Dynamically load DDKG shared library
#ifdef _WIN32
        // Convert string to wide-string
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
        std::wstring sDdkgLib = conv.from_bytes(event_library_name);
        mp_handle = LoadLibrary(sDdkgLib.c_str());
#else // ifdef _WIN32
        mp_handle = dlopen(event_library_name.c_str(), RTLD_LAZY);
#endif // ifdef _WIN32

        Log *p_logger = Log::getInstance();
        if (!mp_handle)
        {
            p_logger->printf(Log::Alert, "Event library %s not found.", event_library_name.c_str());
            return;
        }

        p_logger->printf(Log::Information, "Loading event library %s.", event_library_name.c_str());
        
#ifdef _WIN32
        mp_eventlib_initialise = (EVENTLIB_STARTUP_PROC)GetProcAddress(mp_handle, EVENTLIB_INITIALIZE_FUNC_NAME);
        mp_eventlib_teardown = (EVENTLIB_SHUTDOWN_PROC)GetProcAddress(mp_handle, EVENTLIB_TEARDOWN_FUNC_NAME);
        mp_eventlib_getversion = (EVENTLIB_GETVERSION_PROC)GetProcAddress(mp_handle, EVENTLIB_GETVERSION_FUNC_NAME);
        mp_eventlib_notify = (EVENTLIB_NOTIFY_PROC)GetProcAddress(mp_handle, EVENTLIB_NOTIFY_FUNC_NAME);
#else // ifdef _WIN32
        EventlibFuncPtrAlias alias;
        alias.obj = dlsym(mp_handle, EVENTLIB_INITIALIZE_FUNC_NAME);
        mp_eventlib_initialise = alias.eventlib_startup;
        alias.obj = dlsym(mp_handle, EVENTLIB_TEARDOWN_FUNC_NAME);
        mp_eventlib_teardown = alias.eventlib_shutdown;
        alias.obj = dlsym(mp_handle, EVENTLIB_GETVERSION_FUNC_NAME);
        mp_eventlib_getversion = alias.eventlib_getversion;
        alias.obj = dlsym(mp_handle, EVENTLIB_NOTIFY_FUNC_NAME);
        mp_eventlib_notify = alias.eventlib_notify;
#endif // ifdef _WIN32
        
        if (mp_eventlib_initialise == nullptr)
        {
            p_logger->printf(Log::Alert, "Unable to find symbol %s", EVENTLIB_INITIALIZE_FUNC_NAME);
        }
        if (mp_eventlib_teardown == nullptr)
        {
            p_logger->printf(Log::Alert, "Unable to find symbol %s", EVENTLIB_TEARDOWN_FUNC_NAME);
        }
        if (mp_eventlib_getversion == nullptr)
        {
            p_logger->printf(Log::Alert, "Unable to find symbol %s", EVENTLIB_GETVERSION_FUNC_NAME);
        }
        if (mp_eventlib_notify == nullptr)
        {
            p_logger->printf(Log::Alert, "Unable to find symbol %s", EVENTLIB_NOTIFY_FUNC_NAME);
        }
    }
};

class EventManager 
    : public EventManagerBase
{
    public:
    /// @brief Return the singleton instance of the event manager
    /// @return Pointer to the event manager instance
    static EventManagerBase* getInstance()
    {
        if (mp_instance == nullptr)
        {
            mp_instance = new EventManager();
        }

        return mp_instance;
    }

    /// @brief Replace the instance of the event manager with another instance
    /// @param p_event_manager Pointer to the memory that holds the event manager instance
    static void setInstance(EventManagerBase *p_event_manager)
    {
        if (mp_instance != nullptr)
        {
            delete mp_instance;
            mp_instance = nullptr;
        }

        mp_instance = p_event_manager;
    }

    bool initialise(const std::string &event_library_names) override;

    void teardown() override;

    bool notifyStartup(const std::string &udi) override;

    bool notifyShutdown(const std::string &udi) override;

    bool notifyHeartbeat() override;

    bool notifyRegistrationRequired() override;

    bool notifyRegistrationInProgress() override;

    bool notifyRegistrationFailure(const std::string &error) override;

    bool notifyRegistrationSuccess() override;

    bool notifyAuthorizationInProgress() override;

    bool notifyAuthorizationFailure(const std::string &error) override;

    bool notifyAuthorizationSuccess() override;

    bool notifyCertificateReceived() override;

    bool notifyCertificateStored(const std::string &subject_name, const std::string &location, const std::string &provider_name, bool encrypted) override;

    bool notifyCertificateFailure(const std::string &error) override;

    bool notifyCertificateDataReceived() override;

    bool notifyPrivateKeyCreated() override;

    bool notifyPrivateKeyReceived() override;

    bool notifyPrivateKeyStored(const std::string &key_id, const std::string &location, const std::string &provider_name, bool encrypted) override;

    bool notifyPrivateKeyFailure(const std::string &error) override;
    
    bool notifyCSRCreated() override;
    
    bool notifyCSRDelivered() override;
    
    bool notifyCSRFailure(const std::string &error) override;
    
    bool notifyAPMReceived(const std::string &username) override;
    
    bool notifyAPMSuccess(const std::string &username) override;
    
    bool notifyAPMFailure(const std::string &error) override;
    
    bool notifySATReceived() override;
    
    bool notifySATSuccess() override;
    
    bool notifySATFailure(const std::string &error) override;
    
    bool notifyGroupMetadataReceived() override;
    
    bool notifyGroupMetadataSuccess() override;
    
    bool notifyGroupMetadataFailure(const std::string &error) override;

    private:
    /// @brief Singleton instance of EventManager
    static EventManagerBase* mp_instance;

    /// @brief Vector containing the pointers to the loaded event libraries
    std::map<const std::string, std::unique_ptr<EventLib>> m_event_libs;

#if defined(USETHREADING)
    /// @brief Manages access to the event library container
    pthread_mutex_t m_event_libs_mutex;
#endif // #if defined(USETHREADING)

    /// @brief Constructor
    EventManager();

    /// @brief Destructor
    virtual ~EventManager();

    /// @brief Raises an event notification with the external event library
    /// @param event_type The event type string
    /// @param notification_type The notification type string
    /// @param context The associated context data to be delivered with the event
    /// @return True if successfully sent notification or no event library 
    /// loaded, false if failure to notify
    bool notify(const std::string &event_type, const std::string &notification_type, const std::string &context = "{}");

    /// @brief Creates a JSON string containing up to two attributes
    /// @param key1 The first attribute key
    /// @param value1 The first value
    /// @param key2 The second attribute key
    /// @param value2 The second value
    /// @param key3 The third attribute key
    /// @param value3 The third value
    /// @param key4 The forth attribute key
    /// @param value4 The forth value
    /// @return The JSON object as a string
    static const std::string createJsonString(const std::string &key1, const std::string &value1, const std::string &key2 = "", const std::string &value2 = "", const std::string &key3 = "", const std::string &value3 = "", const std::string& key4 = "", const std::string& value4 = "");
};

#endif // #ifndef EVENT_MANAGER_H
