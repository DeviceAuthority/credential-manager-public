/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Credential manager worker that uses HTTP
 */
#ifndef HTTP_WORKER_LOOP_HPP
#define HTTP_WORKER_LOOP_HPP

#include "asset_manager.hpp"
#include "base_worker_loop.hpp"
#include "dahttpclient.hpp"
#include "log.hpp"

class HttpWorkerLoop :
    public BaseWorkerLoop
{
public:
    /// @brief The HTTP request API URL
    const std::string m_api_url;
    /// @brief The metadata file where metadata is written
    const std::string m_metadata_file;
    /// @brief Flag indicating if the application is running as a daemon
    const bool m_daemon_mode;
    /// @brief The requested data poll time in seconds
    const long m_requested_data_poll_time_s;

    /// @brief Default constructor
    /// @param api_url The KeyScaler SAC API URL
    /// @param metadata_file The metadata file where metadata is written
    /// @param daemon_mode If true the application is running as a daemon
    /// @param sleep_period_s The sleep period between auth requests
    /// @param requested_data_poll_time_s The duration to sleep between polling for a pending request
    HttpWorkerLoop(const std::string &api_url, const std::string &metadata_file, bool daemon_mode, long sleep_period_s, long requested_data_poll_time_s);

    /// @brief Default destructor
	virtual ~HttpWorkerLoop() {};

    void initialize() override;

    void run() override;

    void terminate() override;

    static bool processAssets(AssetManager &asset_manager, const rapidjson::Document &asset_val, const std::string &key, const std::string &iv, const std::string &key_id, AssetMessenger *p_asset_messenger, unsigned int &sleep_period_from_ks);
};

#endif // #ifndef HTTP_WORKER_LOOP_HPP
