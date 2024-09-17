/*
 * Copyright (c) 2024 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Class that maintains a heartbeat which informs event notification listeners that the application is running 
 */
#ifndef HEARTBEAT_MANAGER_HPP
#define HEARTBEAT_MANAGER_HPP

#include "event_manager.hpp"
#include "steady_timer.hpp"

class HeartbeatManager
{
public:
    /// @brief Constructor.
    /// @param heartbeat_interval_s The heartbeat interval in seconds
    HeartbeatManager(int heartbeat_interval_s)
        : m_heartbeat_interval_ms(heartbeat_interval_s * steady_timer::MILLISECONDS_IN_ONE_SECOND)
        , m_update_timer()
        , m_total_elapsed_time(0)
    {

    }
 
    /// @brief Destructor
    ~HeartbeatManager()
    {

    }

    /// @brief Periodically called by a worker loop to update the heartbeat interval and
    /// if required, send a heartbeat event notification
    void update()
    {
        if (m_heartbeat_interval_ms <= 0)
        {
            return; // heartbeat reporting is disabled
        }
        
        m_total_elapsed_time += m_update_timer.get_elapsed_time_in_millseconds();
        m_update_timer.reset();

        if (m_total_elapsed_time > m_heartbeat_interval_ms)
        {
            EventManager::getInstance()->notifyHeartbeat();
            m_total_elapsed_time %= m_heartbeat_interval_ms; // Track any overflow of interval milliseconds
        }
    }

private:
    /// @brief The heartbeat interval in milliseconds
    const int m_heartbeat_interval_ms;

    /// @brief Timer that tracks the duration since the last heartbeat
    steady_timer m_update_timer;

    /// @brief The total elapsed time
    int64_t m_total_elapsed_time;
};

#endif // #ifndef HEARTBEAT_MANAGER_HPP
