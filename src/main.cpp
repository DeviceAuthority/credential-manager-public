/*
 * Copyright (c) 2016 Device Authority Ltd. - All rights reserved. - www.deviceauthority.com
 *
 * The main functions for the process and the threads.
 */
#include <iostream>
#include <memory>
#include "deviceauthority.hpp"
#include "configuration.hpp"
#include "log.hpp"
#include "version.h"
#if defined(WIN32)
#include "getopt.h"
#include "ServiceInstaller.h"
#include "ServiceBase.h"
#include "DAServiceImpl.h"
#include "StringHelper.h"
#include "win_cert_store_factory.hpp"
#else
#include <getopt.h>
#include <netinet/in.h>
#include <unistd.h>
#endif // #if defined(WIN32)
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include "constants.hpp"
#include "opensslhelper.h"
#include "utils.hpp"
#include "http_worker_loop.hpp"
#include "event_manager.hpp"
#include "app_utils.hpp"
#include "ssl_wrapper.hpp"

#ifndef DISABLE_MQTT
#include "mqtt_worker_loop.hpp"
#endif // DISABLE_MQTT

#if defined(WIN32)
#if defined(_WIN64)
// 64-bits platform
#if defined(OPENSSL_FIPS)
#pragma comment(lib, "../../jeffreysbay/openssl/fips-2.0/win32/amd64/libeayfips32.lib")
#elif OPENSSL_VERSION_NUMBER < 0x10100000L
// OpenSSL 1.0.1 and earlier
#pragma comment(lib, "../../jeffreysbay/openssl/lib/1.0/win32/amd64/lib/libeay32.lib")
#pragma comment(lib, "../../jeffreysbay/openssl/lib/1.0/win32/amd64/lib/ssleay32.lib")
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
// OpenSSL 1.1.0
#pragma comment(lib, "../../jeffreysbay/openssl/lib/1.1/win32/amd64/lib/libcrypto.lib")
#pragma comment(lib, "../../jeffreysbay/openssl/lib/1.1/win32/amd64/lib/libssl.lib")
#else
#pragma comment(lib, "../../jeffreysbay/openssl/lib/3.0.10/win32/amd64/lib/libcrypto.lib")
#pragma comment(lib, "../../jeffreysbay/openssl/lib/3.0.10/win32/amd64/lib/libssl.lib")
#endif // #if defined(OPENSSL_FIPS)
#else
// 32-bits platform
#if defined(OPENSSL_FIPS)
#pragma comment(lib, "../jeffreysbay/openssl/fips-2.0/win32/i386/libeayfips32.lib")
#elif OPENSSL_VERSION_NUMBER < 0x10100000L
// OpenSSL 1.0.1 and earlier
#pragma comment(lib, "../../jeffreysbay/openssl/lib/1.0/win32/i386/lib/libeay32.lib")
#pragma comment(lib, "../../jeffreysbay/openssl/lib/1.0/win32/i386/lib/ssleay32.lib")
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
// OpenSSL 1.1.0
#pragma comment(lib, "../../jeffreysbay/openssl/lib/1.1/win32/i386/lib/libcrypto.lib")
#pragma comment(lib, "../../jeffreysbay/openssl/lib/1.1/win32/i386/lib/libssl.lib")
#else
#pragma comment(lib, "../../jeffreysbay/openssl/lib/3.0.10/win32/i386/lib/libcrypto.lib")
#pragma comment(lib, "../../jeffreysbay/openssl/lib/3.0.10/win32/i386/lib/libssl.lib")
#endif // #if defined(OPENSSL_FIPS)
#endif // #if defined(_WIN64)
#else
#ifndef BOOL
typedef int BOOL;
#endif // #ifndef BOOL

#ifndef TRUE
#define TRUE 1
#endif // #ifndef TRUE

#ifndef FALSE
#define FALSE 0
#endif // #ifndef FALSE
#endif // #if defined(WIN32)

enum eClientMode
{
    HTTP_MODE,
    MQTT_MODE
};

#define CLIENT_MODE_MQTT    "MQTT"
#define CLIENT_MODE_HTTP    "HTTP"

//#define VALGRIND_EXIT 1

std::unique_ptr<BaseWorkerLoop> mp_worker_loop = nullptr;

#ifndef WIN32
// If running as a daemon need to catch SIG_INT so that can exit gracefully
// Define the function to be called when ctrl-c (SIGINT) signal is sent to process
void signal_callback_handler(int signum)
{
    if (mp_worker_loop)
    {
        mp_worker_loop->interrupt();
    }
}
#endif // #ifndef WIN32

static int showUsage(char *argv0)
{
    std::cout << "Usage: " << argv0 << " [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --config <config>   Configuration file to read from" << std::endl;
    std::cout << "  --no-daemon  " << std::endl;
#if defined(WIN32)
    std::cout << "  --install           Install the service" << std::endl;
    std::cout << "  --remove            Remove the service" << std::endl;
    std::cout << "  --start             Start the service" << std::endl;
    std::cout << "  --stop              Stop the service" << std::endl;
    std::cout << "  --uninstall         Remove the service" << std::endl;
#endif // #if defined(WIN32)

    return 0;
}

/// @brief Initialise the logger
/// @param p_logger The logger to initialise
/// @param config Container of the configuration file parameters
/// @return True if configured to use a file, else false
bool initialise_logger(Log *p_logger, const Configuration &config)
{
    // Empty string means logging is off
    std::string log_file_name;
    // Empty string means syslog logging is off
    std::string syslog_host;
    // 514 is default syslog port
    unsigned int syslog_port = 514;

    if (config.exists(CFG_SYSLOGHOST))
    {
        syslog_host.append(config.lookup(CFG_SYSLOGHOST));
    }
    if (config.exists(CFG_SYSLOGPORT))
    {
        syslog_port = config.lookupAsLong(CFG_SYSLOGPORT);
    }
    if (config.exists(CFG_LOGFILENAME))
    {
        log_file_name.append(config.lookup(CFG_LOGFILENAME));
    }

    unsigned long max_log_size = config.lookupAsLong(CFG_ROTATELOGAFTER);
    return p_logger->initialise(std::string("credentialmanager"), log_file_name, max_log_size, syslog_host, syslog_port);
}

int main(int argc, char *argv[])
{
    // By default will run as a daemon
    std::string config_filename_arg;
    std::string mode_arg;
    bool verbose = false;
    BOOL daemonise = TRUE;

    static struct option long_options[] =
    {
        // These options set a flag
        {"no-daemon", no_argument, &daemonise, 0},
        // These options don't set a flag
        // We distinguish them by their indices
        {"config",    required_argument, 0, 'c'},
        {"help",      no_argument, 0, 'h'},
        {"mode",      required_argument, 0, 'm'},
        {"version",   no_argument, 0, 'v'},
#if defined(WIN32)
        {"install",   no_argument, 0, 'i'},
        {"remove",    no_argument, 0, 'r'},
        {"start",     no_argument, 0, 's'},
        {"stop",      no_argument, 0, 'o'},
        {"uninstall", no_argument, 0, 'u'},
#endif // #if defined(WIN32)
        {"verbose",   no_argument, 0, 'a'},
        {0, 0, 0, 0}
    };

    while (true)
    {
        int option_index = 0;
        int c = getopt_long(argc, argv, "c:h:i:m:r:a:v", long_options, &option_index);

        // Detect the end of the options
        if (c == -1)
        {
            break;
        }
        switch (c)
        {
            case 0:
                // If this option set a flag, do nothing else now
                if (long_options[option_index].flag != 0)
                {
                    break;
                }
            break;

            case 'c':
                config_filename_arg.assign(optarg);
            break;

            case 'h':
                return showUsage(argv[0]);

            case 'm':
                mode_arg.assign(optarg);
                break;

#if defined(WIN32)
            case 'i':
            {
                // Install the service when the command is "-install" or "/install"
                InstallService(
                    SERVICE_NAME,               // Name of service
                    SERVICE_DISPLAY_NAME,       // Name to display
                    SERVICE_DESCRIPTION,        // Description of service
                    SERVICE_DESIRED_ACCESS,     // Service desired access
                    SERVICE_START_TYPE,         // Service start type
                    SERVICE_DEPENDENCIES,       // Dependencies
                    SERVICE_ACCOUNT,            // Service running account
                    SERVICE_PASSWORD            // Password of the account
                );

                return 0;
            }

            case 'o':
            {
                StopService(SERVICE_NAME, SERVICE_DISPLAY_NAME);

                return 0;
            }

            case 'r':
            case 'u':
            {
                // Uninstall the service when the command is "-remove" or "/remove".
                UninstallService(SERVICE_NAME, SERVICE_DISPLAY_NAME);

                return 0;
            }

            case 's':
            {
                StartService(SERVICE_NAME, SERVICE_DISPLAY_NAME);

                return 0;
            }
#endif // #if defined(WIN32)
            case 'v':
            {
                app_utils::output_copyright_message(nullptr);
                return 0;
            }
            case 'a':
            {
                verbose = true;
            }
        }
    }

    if (config_filename_arg.empty())
    {
        // Default configuration file is used
#if defined(WIN32)
        config_filename_arg.assign("credentialmanager-win32.conf");
#else
        config_filename_arg.assign("credentialmanager.conf");
#endif // #if defined(WIN32)
    }
    Log *p_logger = Log::getInstance(verbose);
#if defined(WIN32)
    WinCertStoreFactory::useUserStore(!daemonise);

    if (daemonise)
    {
        wchar_t szPath[MAX_PATH];

        if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)) == 0)
        {
            char errMsg[256] = { 0 };

            sprintf_s(errMsg, sizeof(errMsg), "GetModuleFileName failed, error: 0x%08lx", GetLastError());
            std::cerr << errMsg << std::endl;

            return -1;
        }

        // Current working directory
        std::string sModuleFullPath;
        std::string sPath = utf16ToUtf8(szPath);
        std::size_t pos = sPath.find_last_of("\\");

        if (pos == std::string::npos)
        {
            pos = sPath.find_last_of("/");
        }
        if (pos != std::string::npos)
        {
            sModuleFullPath = sPath.substr(0, pos);
            sModuleFullPath.append("\\");
        }

        CDACredentialManagerService service(SERVICE_NAME, sModuleFullPath.c_str(), config_filename_arg.c_str());

        if (!CServiceBase::Run(service))
        {
            char errMsg[256] = { 0 };

            sprintf_s(errMsg, sizeof(errMsg), "Service failed to run, error: 0x%08lx", GetLastError());
            std::cerr << errMsg << std::endl;
        }

        return 0;
    }
#endif // #if defined(WIN32)

    // Read in the configuration
    // Configuration file is provided in the command argument
    if (!config.parse(config_filename_arg.c_str()))
    {
        std::cerr << "Failed reading configuration file " << config_filename_arg << std::endl;

        return 1;
    }

    if (daemonise)
    {
#ifndef WIN32
        // Register signal and signal handler
        signal(SIGINT, signal_callback_handler);

        // Process ID and Session ID
        pid_t pid;

        // Fork off the parent process
        pid = fork();
        if (pid < 0)
        {
            exit(EXIT_FAILURE);
        }
        // If we got a good PID, then we can exit the parent process.
        if (pid > 0)
        {
            exit(EXIT_SUCCESS);
        }
        // Change the file mode mask
        umask(0);
#endif // #WIN32
    }

    // If running as a daemon, can't log to stdout as it will be closed
    if (!initialise_logger(p_logger, config) && daemonise)
    {
        std::cerr << "No log setup, please check configuration." << std::endl;

        return 1;
    }

    app_utils::output_copyright_message(p_logger);;

    if (daemonise)
    {
#if defined(WIN32)
#else
        // Create a new SID for the child process
        pid_t sid;

        sid = setsid();
        if (sid < 0)
        {
            // Log the failure
            p_logger->printf(Log::Alert, "Failed to set SID for process, exiting...");
            p_logger->destroyInstance();
            exit(EXIT_FAILURE);
        }
        // Change the current working directory
        if ((chdir("/")) < 0)
        {
            // Log the failure
            p_logger->printf(Log::Alert, "Failed to set working directory, exiting...");
            p_logger->destroyInstance();
            exit(EXIT_FAILURE);
        }
        // Close out the standard file descriptors
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
#endif // #if defined(WIN32)
    }

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

    DeviceAuthorityBase *p_da_instance = nullptr;

    // This point we should init DAMQTTCLIENT || DAHTTPCLIENT
    int client_mode = (utils::toLower(CLIENT_MODE_MQTT) == utils::toLower(config.lookup(CFG_PROTOCOL)) ? MQTT_MODE : HTTP_MODE);
    if (client_mode == MQTT_MODE)
    {
#ifndef DISABLE_MQTT
        p_logger->printf(Log::Information, "Credential Manager running in MQTT mode");
        mp_worker_loop.reset(new MqttWorkerLoop(
            config.lookup(CFG_BROKER_HOST),
            config.lookupAsLong(CFG_BROKER_PORT),
            config.lookup(CFG_MQTT_TOPIC_IN),
            config.lookup(CFG_MQTT_TOPIC_OUT),
            config.lookupAsLong(CFG_SLEEPPERIOD)));
#else
        p_logger->printf(Log::Error, "MQTT protocol not supported");
#endif // DISABLE_MQTT
    }
    else
    {
        p_logger->printf(Log::Information, "Credential Manager running in HTTP mode");

        mp_worker_loop.reset(new HttpWorkerLoop(
            config.lookup(CFG_DAAPIURL),
            config.lookup(CFG_METADATAFILE),
            daemonise,
            config.lookupAsLong(CFG_SLEEPPERIOD),
            config.lookupAsLong(CFG_POLL_TIME_FOR_REQUESTED_DATA)));
    }

    bool init_success = mp_worker_loop != nullptr;
    if (init_success)
    {
        // Initialise the DA instance
        p_da_instance = DeviceAuthority::getInstance();
        init_success = p_da_instance != nullptr;
    }

     // Ensure that DA instance and worker have initialised successfully - teardown on failure
    if (init_success)
    {
#if defined(WIN32)
#else
        // Ignore SIGPIPE signals
        signal(SIGPIPE, SIG_IGN);
#endif // #if defined(WIN32)

        p_logger->printf(Log::Debug, "Created DeviceAuthority instance.");
        p_logger->printf(Log::Debug, "Daemonise. %d", daemonise);

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
        EventManagerBase *p_event_manager = EventManager::getInstance();
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
        p_logger->printf(Log::Error, " Failed to create DeviceAuthority instance.");
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

    return mp_worker_loop->getExitCode();
}
