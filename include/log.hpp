/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a log writer
 */
#ifndef LOG_HPP
#define LOG_HPP

#if defined(WIN32)
#include <Windows.h>
#endif // #if defined(WIN32)
#include <stdio.h>
//#include "syslog.h"
#if defined(USETHREADING)
#include <pthread.h>
#endif // #ifdef USETHREADING
#include <string>

#ifndef WRITE_DEBUG
#ifdef DEBUG
#define WRITE_DEBUG true
#else
#define WRITE_DEBUG false
#endif // #ifdef DEBUG
#endif // #ifndef WRITE_DEBUG

#if defined(WIN32)
#if !defined(__func__)
#define __func__ __FUNCTION__
#endif // #if !defined(__func__)
#endif // #if defined(WIN32)

class Log
{
public:
    // The levels (as defined by syslog)
    enum Severity
    {
        Emergency = 0,
        Alert = 1,
        Critical = 2,
        Error = 3,
        Warning = 4,
        Notice = 5,
        Information = 6,
        Debug = 7
    };

    static Log *getInstance();
    static Log *getInstance(bool verbose);
    static bool destroyInstance();

    virtual ~Log();

    bool initialise(const std::string& processName, const std::string& fullPathOfFile, unsigned long maxFileSize = 1024000, std::string syslogHost = "", unsigned int syslogPort = 0);
    void useColour(bool value);
    void printf(Severity level, const char *text, ...);

private:
    Log(bool verbose = false);
    // Helper functions for log file use
    const char *timestamp(char *buffer) const;
    const char *severityString(Severity level) const;
    void checkAndRotateLogFile(void);
    static void lock(void);
    static void unlock(void);

private:
#if defined(USETHREADING)
    static pthread_mutex_t m_log_lock;
#endif // #if defined(USETHREADING)
    static Log *m_log_instance;
    const bool m_verbose = false;
    std::string m_process_name;
    std::string m_full_filename;
    // For writing to a log file
#if defined(WIN32)
    HANDLE m_file = NULL;
#else
    FILE* m_file = nullptr;
#endif // #if defined(_WIN32)
    bool m_use_file = false;
    bool m_use_colour = false;
    unsigned long m_file_size = 0;
    unsigned long m_max_file_size = 0;
};

extern Log logger;

#endif // #ifndef LOG_HPP
