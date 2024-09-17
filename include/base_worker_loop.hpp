
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Base class for a credential manager worker
 */
#ifndef BASE_WORKER_LOOP_HPP
#define BASE_WORKER_LOOP_HPP

#include "log.hpp"

class BaseWorkerLoop
{
public:
    /// @brief The period to sleep between auth requests in seconds
    const long m_sleep_period_s;

    /// @brief Constructor
    /// @param sleep_period_ms The sleep period in seconds
    explicit BaseWorkerLoop(long sleep_period_ms)
        : m_sleep_period_s(sleep_period_ms)
    {
		m_interrupted = false;
		m_exit_code = EXIT_SUCCESS;
    }

    /// @brief Default destructor
	virtual ~BaseWorkerLoop() {};

    /// @brief Initialises the worker
    virtual void initialize() = 0;

    /// @brief Runs the worker loop
    virtual void run() = 0;

    /// @brief Terminates the worker
    virtual void terminate() = 0;

    /// @brief Interrupt the worker loop
    void interrupt(int exit_code = EXIT_SUCCESS)
    {
        m_interrupted = true;
        m_exit_code = exit_code;
    }

    /// @brief Get the interrupt state
    /// @return True if the loop should be interrupted
    inline bool isInterrupted() const
    {
        return m_interrupted;
    }

    /// @brief Get the exit code returned when the worker was interrupted
    /// @return The exit code
    inline int getExitCode() const
    {
        return m_exit_code;
    }

    private:
    /// @brief Flag indicating whether the loop should be interrupted and exit
    bool m_interrupted;
    /// @brief The exit code returned when the worker exited
    int m_exit_code;
};

#endif // #ifndef BASE_WORKER_LOOP_HPP
