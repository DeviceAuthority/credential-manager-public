/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a log writer
 */

#include "log.hpp"
#include <iostream>
#include <ctime>
#define USE_COLOURS // Comment out to switch colours of entirely.
#if defined(WIN32)
#include <Windows.h>
#include <process.h>
#else
#include <unistd.h>
#endif // #if defined(WIN32)
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
#include <string.h>


#if defined(WIN32)
#define ISATTY(x)   0
#define GETPID      _getpid
#if _MSC_VER >= 1400  // VC 8.0 and later deprecate snprintf and _snprintf.
# define SNPRINTF _snprintf_s
#elif _MSC_VER
# define SNPRINTF _snprintf
#endif // #if _MSC_VER >= 1400
#else
#define ISATTY      isatty
#define GETPID      getpid
#define SNPRINTF    snprintf
#endif // #if defined(WIN32)
// Colours for text output
#define RED     "\033[0;31m"
#define GREEN   "\033[0;32m"
#define BLUE    "\033[0;34m"
#define YELLOW  "\033[1;33m"
#define NONE    "\033[0m"

static constexpr unsigned int HEADER_MAX_LEN{ 256 };
static constexpr unsigned int BODY_MAX_LEN{ 2024 };
static constexpr unsigned int TIMESTAMP_MAX_LEN{ 20 };
static constexpr unsigned int MAX_FILE_SIZE{ 1024000 };

Log *Log::m_log_instance = nullptr;
#if defined(USETHREADING)
pthread_mutex_t Log::m_log_lock = PTHREAD_MUTEX_INITIALIZER;
#endif // #if defined(USETHREADING)

#include <stdio.h>
Log *Log::getInstance()
{
    lock();
    if (!m_log_instance)
    {
        m_log_instance = new Log();
    }
    unlock();

    return m_log_instance;
}

Log *Log::getInstance(bool verbose)
{
    lock();
    if (!m_log_instance)
    {
        m_log_instance = new Log(verbose);
    }
    unlock();

    return m_log_instance;
}

bool Log::destroyInstance()
{
    if (m_log_instance)
    {
        delete m_log_instance;
        m_log_instance = NULL;
    }

    return true;
}

Log::Log(bool _verbose) : m_verbose(_verbose)
{
#ifdef USE_COLOURS
    // Don't want to do colour if stdout is a pipe or
    // file redirect, only if it is a terminal.
    m_use_colour = (ISATTY(fileno(stdout)) != 0);
#endif
    m_process_name = "Agent";

    const std::string syslog_host = "";
    const std::string full_path_of_file = "Agent.log";
    const unsigned int syslog_port = 514;

    m_file = NULL;
    m_use_file = false;
    //useSysLog_ = false;
    m_use_colour = false;
    m_full_filename = full_path_of_file;
    m_file_size = 0;
    m_max_file_size = MAX_FILE_SIZE;
    initialise(m_process_name, full_path_of_file, m_max_file_size, syslog_host, syslog_port);
}

Log::~Log()
{
    //syslog_.SetActive(false);
    if (m_file != NULL)
    {
#if defined(WIN32)
        CloseHandle(m_file);
#else // #if defined(WIN32)
        fclose(m_file);
#endif // #if defined(WIN32)
        m_file = NULL;
    }
}

bool Log::initialise(const std::string& processName, const std::string& fullPathOfFile, unsigned long maxFileSize, std::string syslogHost, unsigned int syslogPort)
{
    m_max_file_size = maxFileSize;
    m_process_name = processName;
    //syslog_.SetActive(false);
    //useSysLog_ = false;
    m_use_file = false;
    if (m_file != NULL)
    {
#if defined(WIN32)
        CloseHandle(m_file);
#else // #if defined(WIN32)
        fclose(m_file);
#endif // #if defined(WIN32)
        m_file = NULL;
    }
    // If filename specified then open a log file
    if (!fullPathOfFile.empty())
    {
        m_full_filename = fullPathOfFile;
        // First get the size of the current file (if there is one)
        struct stat st;

        if (stat(fullPathOfFile.c_str(), &st) == 0)
        {
            m_file_size = st.st_size;
        }
        bool success = false;
#if defined(WIN32)
        m_file = CreateFileA(fullPathOfFile.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        success = m_file != NULL && m_file != INVALID_HANDLE_VALUE;
#else // #if defined(WIN32)
        m_file = fopen(fullPathOfFile.c_str(), "ab");
        success = m_file != NULL;
#endif // #if defined(WIN32)
        if (!success)
        {
            fprintf(stderr, "Unable to open log file: %s\n", fullPathOfFile.c_str());
        }
        else
        {
            m_use_file = true;
        }
    }
    // If syslog host specified then open a connection to it
    /*
    if (syslog_host && (syslog_host[0] != '\0'))
    {
        syslog_.SetRemoteHost(syslog_host);
        if (syslogPort > 0)
        {
            syslog_.SetRemotePort(syslogPort);
        }
        syslog_.SetLocalHost("localhost");
        syslog_.SetLocalPort(0);
        syslog_.SetActive(true);
        useSysLog_ = true;
    }
    */

    return m_use_file/* || useSysLog_*/;
}

void Log::useColour(bool value)
{
    m_use_colour = value;
}

void Log::checkAndRotateLogFile(void)
{
    if (m_file_size >= m_max_file_size)
    {
#if defined(WIN32)
        CloseHandle(m_file);
#else // #if defined(WIN32)
        fclose(m_file);
#endif // #if defined(WIN32)
        m_file = NULL;
        remove((m_full_filename + ".old").c_str());
        rename(m_full_filename.c_str(), (m_full_filename + ".old").c_str());

#if defined(WIN32)
        m_file = CreateFileA(m_full_filename.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
#else // #if defined(WIN32)
        m_file = fopen(m_full_filename.c_str(), "wb");
#endif // #if __STDC_WANT_SECURE_LIB__
        if (m_file == NULL)
        {
            fprintf(stderr, "Unable to open log file: %s\n", m_full_filename.c_str());
            m_use_file = false;
        }
        m_file_size = 0;
    }
}

void Log::printf(Severity level, const char *text, ...)
{
    if ((level < Debug) || WRITE_DEBUG || m_verbose)
    {
        Log::lock();

        bool logged = false;

        // Create the log header text
        char ts[TIMESTAMP_MAX_LEN]{ '\0' };
        char header[HEADER_MAX_LEN]{ '\0' };
        snprintf(header, HEADER_MAX_LEN - 1, "%5d %s %s ", GETPID(), timestamp(ts), severityString(level));

        // Create the log body text
        va_list argptr;
        char body[BODY_MAX_LEN]{ '\0' };
        va_start(argptr, text);
        vsnprintf(body, BODY_MAX_LEN - 1, text, argptr);
        va_end(argptr);

        if (m_use_file)
        {
            checkAndRotateLogFile();

#if defined(WIN32)
            DWORD bytes_written{ 0 };
            logged = WriteFile(m_file, &header, strlen(header), &bytes_written, NULL) == TRUE;
            logged &= WriteFile(m_file, &body, strlen(body), &bytes_written, NULL) == TRUE;
            logged &= WriteFile(m_file, "\n", 1, &bytes_written, NULL) == TRUE;
            
            m_file_size = GetFileSize(m_file, NULL);
#else // #if defined(WIN32)
            long int before = ftell(m_file);
            fprintf(m_file, "%s %s\n", header, body);
            fflush(m_file);
            long int after = ftell(m_file);

            m_file_size += (after - before);
            logged = true;
#endif // #if defined(WIN32)
        }
        // If using syslog based logging then write to syslog
        /*
        if (useSysLog_)
        {
            char newtext[1024];

            SNPRINTF(newtext, 1024, "%s: %s", m_process_name, text);
            char buffer[2048];
            va_list argptr;

            va_start(argptr, text);
            vsnprintf(buffer, 2048, newtext, argptr);
            va_end(argptr);
            syslog_.SendPacket(20, level, buffer);
            logged = true;
        }
        */
        // If not logged by either of the previous means, log to terminal.
        if (!logged)
        {
            fprintf((level <= Error) ? stderr : stdout, "%s %s\n", header, body);
        }
        Log::unlock();
    }
}

const char *Log::timestamp(char *buffer) const
{
    time_t now;
    struct tm *timeinfo;

    time(&now);
#if __STDC_WANT_SECURE_LIB__
    struct tm tmNow;

    timeinfo = &tmNow;

    errno_t err = localtime_s(&tmNow, &now);

    UNREFERENCED_PARAMETER(err);
#else
    timeinfo = localtime(&now);
#endif // #if __STDC_WANT_SECURE_LIB__
    // Generate time in YYYY-MM-DD HH24:MM:SS format for use
    // in the log file.
    strftime(buffer, TIMESTAMP_MAX_LEN, "%Y-%m-%d %X", timeinfo);

    return buffer;
}

const char *Log::severityString(Severity level) const
{
    if (m_use_colour)
    {
        switch (level)
        {
            case Emergency:
                return RED "[EMERGENCY]" NONE;
            case Alert:
                return RED "[ALERT]" NONE;
            case Critical:
                return RED "[CRITICAL]" NONE;
            case Error:
                return RED "[ERROR]" NONE;
            case Warning:
                return YELLOW "[WARNING]" NONE;
            case Notice:
                return GREEN "[NOTICE]" NONE;
            case Information:
                return GREEN "[INFORMATION]" NONE;
            default:
                // Debug
                return BLUE "[DEBUG]" NONE;
        }
    }
    else
    {
        switch (level)
        {
            case Emergency:
                return "[EMERGENCY]";
            case Alert:
                return "[ALERT]";
            case Critical:
                return "[CRITICAL]";
            case Error:
                return "[ERROR]";
            case Warning:
                return "[WARNING]";
            case Notice:
                return "[NOTICE]";
            case Information:
                return "[INFORMATION]";
            default:
                // Debug
                return "[DEBUG]";
        }
    }
}

void Log::lock(void)
{
#ifdef USETHREADING
    pthread_mutex_lock(&m_log_lock);
#endif // #ifdef USETHREADING
}

void Log::unlock(void)
{
#ifdef USETHREADING
    pthread_mutex_unlock(&m_log_lock);
#endif // #ifdef USETHREADING
}
