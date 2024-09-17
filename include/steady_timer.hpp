/*
 * Copyright (c) 2024 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Timer implementation that uses a monotonic clock at its source
 */
#ifndef STEADY_TIMER_HPP
#define STEADY_TIMER_HPP

#ifndef WIN32
#include <chrono>
#else // #ifndef WIN32
#include <Windows.h>
#endif // #ifndef WIN32

class steady_timer
{
public:
    static const short MILLISECONDS_IN_ONE_SECOND = 1000;

    /// @brief Constructor.
    /// @details Initialises the timer at point of creation (RAII)
    steady_timer()
    {
        reset();
    }

    /// @brief Destructor
    ~steady_timer()
    {

    }

    /// @brief Get the elapsed time in milliseconds
    /// @return The elapsed time in milliseconds;
    int64_t get_elapsed_time_in_millseconds() const
    {
#ifndef WIN32
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_start_time).count();
#else // #ifndef WIN32
		return GetTickCount64() - m_start_time;
#endif // #ifndef WIN32
    }

    /// @brief Reset the timer
    void reset()
    {
#ifndef WIN32
        m_start_time = std::chrono::steady_clock::now();
#else // #ifndef WIN32
		m_start_time = GetTickCount64();
#endif // #ifndef WIN32
    }

private:
    /// @brief The timer start time
#ifndef WIN32
    std::chrono::time_point<std::chrono::steady_clock> m_start_time;
#else // #ifndef WIN32
    ULONGLONG m_start_time;
#endif // #ifndef WIN32
};

#endif // #ifndef STEADY_TIMER_HPP
