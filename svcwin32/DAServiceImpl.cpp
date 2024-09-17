/****************************** Module Header ******************************\
 * Module Name:  DAServiceImpl.cpp
 * Project:      Credential-Manager
 * Copyright (c) Device Authority Ltd.
 *
 * Provides a DA service class that derives from the service base class -
 * CServiceBase. The DA service logs the service start and stop
 * information to the Application event log, and shows how to run the main
 * function of the service in a thread pool worker thread.
 *
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/
#pragma region Includes
#include "apm_asset_processor.hpp"
#include "asset_manager.hpp"
#include "certificate_asset_processor.hpp"
#include "certificate_data_asset_processor.hpp"
#include "configuration.hpp"
#include "constants.hpp"
#include "dahttpclient.hpp"
#include "deviceauthority.hpp"
#include "group_asset_processor.hpp"
#include "log.hpp"
#include "base64.h"
#include "opensslhelper.h"
#include "timehelper.h"
#include "version.h"
#include "DAServiceImpl.h"
#include "ThreadPool.h"
#include "FileIOHelper.h"
#include "StringHelper.h"
#include "script_asset_processor.hpp"
#include "http_asset_messenger.hpp"
#include "utils.hpp"
#include "event_manager.hpp"
#include "tester_helper.hpp"
#include "app_utils.hpp"
#include "base_worker_loop.hpp"
#include "http_worker_loop.hpp"
#pragma endregion


CDACredentialManagerService::CDACredentialManagerService(PWSTR pszServiceName,
    BOOL fCanStop, BOOL fCanShutdown, BOOL fCanPauseContinue) : CServiceBase(pszServiceName, fCanStop, fCanShutdown, fCanPauseContinue)
{
    mp_worker_loop = nullptr;
}

CDACredentialManagerService::CDACredentialManagerService(PWSTR pszServiceName, LPCSTR pszModuleFullPath, LPCSTR pszConfigFilename,
    BOOL fCanStop, BOOL fCanShutdown, BOOL fCanPauseContinue) : CServiceBase(pszServiceName, fCanStop, fCanShutdown, fCanPauseContinue)
{
    if ((pszModuleFullPath != NULL) && (strlen(pszModuleFullPath) > 0))
    {
        m_sModuleFullPath.assign(pszModuleFullPath);
        if (!endsWith(m_sModuleFullPath, "\\") && !endsWith(m_sModuleFullPath, "/"))
        {
            m_sModuleFullPath.append("\\");
        }
    }
    if ((pszConfigFilename != NULL) && (strlen(pszConfigFilename) > 0))
    {
        m_sConfigFilename.assign(m_sModuleFullPath);
        m_sConfigFilename.append(pszConfigFilename);
    }

    mp_worker_loop = nullptr;

    // Create a manual-reset event that is not signaled at first to indicate
    // the stopped signal of the service
    m_hStoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (m_hStoppedEvent == NULL)
    {
        throw GetLastError();
    }
}

CDACredentialManagerService::~CDACredentialManagerService(void)
{
    if (m_hStoppedEvent)
    {
        CloseHandle(m_hStoppedEvent);
        m_hStoppedEvent = NULL;
    }
}

//
//   FUNCTION: CDACredentialManagerService::OnStart(DWORD, LPWSTR *)
//
//   PURPOSE: The function is executed when a Start command is sent to the
//   service by the SCM or when the operating system starts (for a service
//   that starts automatically). It specifies actions to take when the
//   service starts. In this code sample, OnStart logs a service-start
//   message to the Application log, and queues the main service function for
//   execution in a thread pool worker thread.
//
//   PARAMETERS:
//   * dwArgc   - number of command line arguments
//   * lpszArgv - array of command line arguments
//
//   NOTE: A service application is designed to be long running. Therefore,
//   it usually polls or monitors something in the system. The monitoring is
//   set up in the OnStart method. However, OnStart does not actually do the
//   monitoring. The OnStart method must return to the operating system after
//   the service's operation has begun. It must not loop forever or block. To
//   set up a simple monitoring mechanism, one general solution is to create
//   a timer in OnStart. The timer would then raise events in your code
//   periodically, at which time your service could do its monitoring. The
//   other solution is to spawn a new thread to perform the main service
//   functions, which is demonstrated in this code sample.
//
void CDACredentialManagerService::OnStart(DWORD dwArgc, LPWSTR *lpszArgv)
{
    // Log a service start message to the Application log
    WriteEventLogEntry(TEXT("CDACredentialManagerService in OnStart"), EVENTLOG_INFORMATION_TYPE);
    // Queue the main service function for execution in a worker thread
    CThreadPool::QueueUserWorkItem(&CDACredentialManagerService::ServiceWorkerThread, this);
}

//
//   FUNCTION: CDACredentialManagerService::OnStop(void)
//
//   PURPOSE: The function is executed when a Stop command is sent to the
//   service by SCM. It specifies actions to take when a service stops
//   running. In this code sample, OnStop logs a service-stop message to the
//   Application log, and waits for the finish of the main service function.
//
//   COMMENTS:
//   Be sure to periodically call ReportServiceStatus() with
//   SERVICE_STOP_PENDING if the procedure is going to take long time.
//
void CDACredentialManagerService::OnStop()
{
    // Log a service stop message to the Application log
    WriteEventLogEntry(TEXT("CDACredentialManagerService in OnStop"), EVENTLOG_INFORMATION_TYPE);
    // Indicate that the service is stopping and wait for the finish of the
    // main service function (ServiceWorkerThread)
    if (mp_worker_loop)
    {
        mp_worker_loop->interrupt();
    }

    if (WaitForSingleObject(m_hStoppedEvent, INFINITE) != WAIT_OBJECT_0)
    {
        throw GetLastError();
    }
}

//
//   FUNCTION: CDAService::ServiceWorkerThread(void)
//
//   PURPOSE: The method performs the main function of the service. It runs
//   on a thread pool worker thread.
//
void CDACredentialManagerService::ServiceWorkerThread(void)
{
    WriteEventLogEntry(TEXT("CDACredentialManagerService ServiceWorkerThread wakes up"), EVENTLOG_INFORMATION_TYPE);
    if (!config.parse(m_sConfigFilename.c_str()))
    {
        WriteEventLogEntry(TEXT("CDACredentialManagerService unable to parse config file"), EVENTLOG_ERROR_TYPE);
        // Signal the stopped event
        SetEvent(m_hStoppedEvent);

        return;
    }

    static const std::string DAAPIURL = config.lookup(CFG_DAAPIURL);
    // Initialise the logging
    // Empty string means logging is off
    std::string logfileName;
    // Empty string means syslog logging is off
    std::string syslogHost;
    // 514 is default syslog port
    unsigned int syslogPort = 514;

    if (config.exists(CFG_SYSLOGHOST))
    {
        syslogHost.append(config.lookup(CFG_SYSLOGHOST));
    }
    if (config.exists(CFG_SYSLOGPORT))
    {
        syslogPort = config.lookupAsLong(CFG_SYSLOGPORT);
    }
    if (config.exists(CFG_LOGFILENAME))
    {
        std::string logFilenameFromProperties = config.lookup(CFG_LOGFILENAME);
        size_t pos = logFilenameFromProperties.find_last_of("\\");

        if (pos == std::string::npos)
        {
            pos = logFilenameFromProperties.find_last_of("\\");
        }
        if (pos == std::string::npos)
        {
            // Log filename from properties file does not contain path/directory
            logfileName.assign(m_sModuleFullPath);
            logfileName.append(logFilenameFromProperties);
        }
        else
        {
            // Log filename from properties file does contain path/directory
            std::ofstream ofs(logFilenameFromProperties.c_str(), std::ofstream::out | std::ofstream::app);

            if (ofs.is_open())
            {
                // Log filename (and its path) from properties file is good
                ofs.close();
                logfileName.assign(logFilenameFromProperties);
            }
            else
            {
                // Log filename (and its path) from properties file is not good
                std::string sPath = logFilenameFromProperties.substr(0, pos + 1);

                // Try to create the path recursively
                WriteEventLogEntry(TEXT("CDACredentialManagerService creating directory"), EVENTLOG_INFORMATION_TYPE);
                if (createDirectoryRecursively(sPath.c_str()))
                {
                    logfileName.assign(logFilenameFromProperties);
                }
                else
                {
                    WriteEventLogEntry(TEXT("CDACredentialManagerService unable to create directory"), EVENTLOG_WARNING_TYPE);
                    logfileName.assign(m_sModuleFullPath);
                    logfileName.append(logFilenameFromProperties);
                }
            }
        }
    }

    Log *p_logger = Log::getInstance();
    unsigned long maxLogSize = config.lookupAsLong(CFG_ROTATELOGAFTER);

    // If running as a daemon, can't log to stdout as it will be closed
    if (!p_logger->initialise(string("credentialmanager"), logfileName, maxLogSize, syslogHost, syslogPort))
    {
        WriteEventLogEntry(TEXT("No log setup, please check configuration"), EVENTLOG_ERROR_TYPE);
        // Signal the stopped event
        SetEvent(m_hStoppedEvent);

        return;
    }
    if (config.exists(CFG_CAFILE))
    {
        std::string sCAFile = config.lookup(CFG_CAFILE);

        if (!fileExists(sCAFile.c_str()))
        {
            WriteEventLogEntry(TEXT("CAFile directory or file not found, please check configuration"), EVENTLOG_ERROR_TYPE);
            // Signal the stopped event
            SetEvent(m_hStoppedEvent);

            return;
        }
    }

    app_utils::output_copyright_message(p_logger);

    const std::string custom_provider = config.lookup(CFG_OSSL_PROVIDER);
    if (!custom_provider.empty())
    {
        if (!openssl_load_provider(custom_provider))
        {
            p_logger->printf(Log::Error, "Failed to load custom openSSL provider");
            exit(1);
        }
        SSLWrapper::setUsingCustomStorageProvider(true);
    }

    openssl_init_locks();

    DeviceAuthorityBase* p_da_instance = nullptr;

    mp_worker_loop.reset(new HttpWorkerLoop(
        config.lookup(CFG_DAAPIURL),
        config.lookup(CFG_METADATAFILE),
        true, // daemonise always true as running as a service
        config.lookupAsLong(CFG_SLEEPPERIOD),
        config.lookupAsLong(CFG_POLL_TIME_FOR_REQUESTED_DATA)));
    bool init_success = mp_worker_loop != nullptr;
    if (init_success)
    {
        p_logger->printf(Log::Information, "Credential Manager running in HTTP mode");

        p_da_instance = DeviceAuthority::getInstance();
        init_success = p_da_instance != nullptr;
    }

    if (init_success)
    {
        MarkAsRunning();

        p_logger->printf(Log::Debug, " %s Created DeviceAuthority instance", __func__);

        if (config.lookup(CFG_USE_UDI_AS_DEVICE_IDENTITY) == "TRUE")
        {
            // Provide the UDI to the DDKG to be used as the device identity
            p_da_instance->setUDI(config.lookup(CFG_UDI));
        }

        // Provide the External DDKG UDI property name to the DDKG
        p_da_instance->setExtDdkgUDIPropertyName(config.lookup(CFG_EXT_DDKG_UDI_PROPERTY));

        // Configure the DDKG root filesystem
        p_da_instance->setDdkgRootFilepath(config.lookup(CFG_DDKG_ROOT_FS));

        // Initialise EventManager to handle notifications
        EventManagerBase* p_event_manager = EventManager::getInstance();
        if (p_event_manager->initialise(config.lookup(CFG_EVENT_NOTIFICATION_LIBRARIES)))
        {
            p_da_instance->setEventManager(p_event_manager);
            p_event_manager->notifyStartup(p_da_instance->getUDI());
        }

        mp_worker_loop->initialize();
        mp_worker_loop->run();
        mp_worker_loop->terminate();

        // Teardown EventManager
        p_event_manager->notifyShutdown(p_da_instance->getUDI());
        p_da_instance->setEventManager(nullptr);
        p_event_manager->teardown();
    }
    else
    {
        WriteEventLogEntry(TEXT("CDACredentialManagerService ServiceWorkerThread failed to instantiate DeviceAuthority instance"), EVENTLOG_ERROR_TYPE);
        p_logger->printf(Log::Critical, " %s Failed to instantiate DeviceAuthority instance", __func__);
    }

    if (p_da_instance)
    {
        p_da_instance->destroyInstance();
        p_da_instance = nullptr;
    }

    openssl_kill_locks();
    p_logger->printf(Log::Debug, "Main thread initiating SSL cleanup.");
    openssl_cleanup();
    p_logger->printf(Log::Debug, "Main thread all done.");
    p_logger->destroyInstance();
    WriteEventLogEntry(TEXT("CDACredentialManagerService ServiceWorkerThread all done"), EVENTLOG_INFORMATION_TYPE);
    // Signal the stopped event
    SetEvent(m_hStoppedEvent);
}
