/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 */
#ifndef ASYNC_EXEC_SCRIPT_HPP
#define ASYNC_EXEC_SCRIPT_HPP

#include <pthread.h>
#include <string>
#include "async_exec_script.hpp"

typedef struct ThreadResult
{
	ThreadResult(const std::string& script)
		: m_script(script), m_finished(false), m_success(false)
	{
	}

    const std::string m_script;
    bool m_finished;
    bool m_success;
    std::string m_log_output;
} ThreadResult;

class AsyncExecScript
{
public:
    /// @brief Constructor
    AsyncExecScript(const std::string &script);
    /// @brief Destructor - reaps the thread if executing
    ~AsyncExecScript();

    /// @brief Attempts to consume thread, doing so if its execution has completed
    /// @return True if the thread has completed, else false
    bool tryJoin();

    /// @brief Get whether the script exited with a success exit code
    /// @return True if exit code 0, else false
    bool isSuccess() const;

    /// @brief Get the output from the async script
    /// @return The log returned from the script
    const std::string getScriptOutput() const;

private:
    ThreadResult m_thread_data;

    /// @brief Handle to pthread spawned by this class
    pthread_t m_handle;

	/// @brief Flag indicating if the thread is running
	bool m_thread_running;
};

#endif // #ifndef ASYNC_EXEC_SCRIPT_HPP
