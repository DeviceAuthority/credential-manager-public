/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 */

#include <cstring>
#include "async_exec_script.hpp"
#include "log.hpp"
#include "script_utils.hpp"

void *runScript(void *p_data)
{
    ThreadResult* p_thread_data = (ThreadResult*)p_data;
    if (p_thread_data)
    {
        p_thread_data->m_success = script_utils::execScript(p_thread_data->m_script.c_str(), p_thread_data->m_log_output);
        p_thread_data->m_finished = true;
    }
    return (void*)p_thread_data;
}

AsyncExecScript::AsyncExecScript(const std::string &script)
	: m_thread_data(script), m_thread_running(false)
{
    if (pthread_create(&m_handle, NULL, &runScript, (void *)&m_thread_data) != 0)
    {
        Log::getInstance()->printf(Log::Error, "Failed to create script executing thread");
    }
}

AsyncExecScript::~AsyncExecScript()
{
    if (m_thread_running)
    {
        pthread_cancel(m_handle);
        m_thread_running = false;
    }
}

bool AsyncExecScript::tryJoin()
{
    if (!m_thread_data.m_finished)
    {
        // Thread still running
        return false;
    }
    pthread_join(m_handle, nullptr);
    m_thread_running = false;

    return true;
}

bool AsyncExecScript::isSuccess() const
{
    if (m_thread_running)
    {
        return false;
    }
    return m_thread_data.m_success;
}

const std::string AsyncExecScript::getScriptOutput() const
{
    if (m_thread_running)
    {
        return "";
    }
    return m_thread_data.m_log_output;
}
