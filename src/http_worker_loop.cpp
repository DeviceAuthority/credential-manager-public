/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Credential manager worker that uses HTTP
 */

#include "apm_asset_processor.hpp"
#include "base64.h"
#include "certificate_asset_processor.hpp"
#include "certificate_data_asset_processor.hpp"
#include "dahttpclient.hpp"
#include "deviceauthority.hpp"
#include "event_manager.hpp"
#include "group_asset_processor.hpp"
#include "heartbeat_manager.hpp"
#include "http_asset_messenger.hpp"
#include "http_worker_loop.hpp"
#include "script_asset_processor.hpp"
#include "steady_timer.hpp"
#include "timehelper.h"
#include "utils.hpp"

/// Status codes returned by an auth request
static const int STATUS_CODE_OK = 0;
static const int STATUS_CODE_RETRY_AUTHORIZATION = 5105;

void *credentialManagerLoop(void *param)
{
    HttpWorkerLoop *p_worker_loop = static_cast<HttpWorkerLoop*>(param);

    // Initialise the logging
    Log *p_logger = Log::getInstance();

    p_logger->printf(Log::Notice, "Credential Manager Loop");

    DeviceAuthorityBase *p_da_instance = DeviceAuthority::getInstance();
    if (!p_da_instance)
    {
        p_logger->printf(Log::Notice, " %s Failed to instantiate DeviceAuthority instance", __func__);
        p_logger->destroyInstance();
        p_worker_loop->interrupt(EXIT_FAILURE);
    }
    p_logger->printf(Log::Debug, " %s Created DeviceAuthority instance", __func__);

    unsigned int sleep_period_s = p_worker_loop->m_sleep_period_s;
    DAHttpClient http_client_obj(p_da_instance->userAgentString());

    const std::string dest_url(config.lookup(CFG_DAAPIURL));
    std::unique_ptr<AssetMessenger> p_asset_messenger(new HttpAssetMessenger(dest_url, &http_client_obj));

    AssetManager asset_manager;
    HeartbeatManager heartbeat_manager(config.lookupAsLong(CFG_HEARTBEAT_INTERVAL_S));

    steady_timer loop_timer;
    bool stuff_to_do = true;
    int64_t loop_duration_ms = 0;
    while (stuff_to_do)
    {
        loop_timer.reset();
        bool overwrite_sleep = false;

        std::string new_keyid;
        std::string new_key;
        std::string new_iv;
        std::string message;
        std::string metadata_b64;

        const std::string da_json = p_da_instance->identifyAndAuthorise(new_keyid, new_key, new_iv, message, metadata_b64, &http_client_obj);
        if (!da_json.empty())
        {
            // Metadata may be received at registration time
            // Did we receive device configuration metadata back from Keyscaler?
            if (!metadata_b64.empty())
            {
                GroupAssetProcessor::writeMetadataToFile(p_worker_loop->m_metadata_file, metadata_b64);
            }

            // Decode the Key and IV
            if (!utils::base64DecodeKeyIV(new_key, new_iv))
            {
                p_logger->printf(Log::Error, "Failed to decode key and IV");
            }

            std::string json_response;
            DAErrorCode rc_http_client = http_client_obj.sendRequest(DAHttp::ReqType::ePOST, p_worker_loop->m_api_url + "/auth", json_response, da_json);
            if (rc_http_client != ERR_OK)
            {
                p_logger->printf(Log::Error, " %s sendRequest to KS failed with error code: %d", __func__, rc_http_client);
            }

            rapidjson::Document json;
            if (!json_response.empty())
            {
                json.Parse<0>(json_response.c_str());
                if (json.HasParseError())
                {
                    p_logger->printf(Log::Error, " %s Bad JSON response from KS %s", __func__, json_response.c_str());
                }
            }

            if (!json.IsNull() && json.HasMember("statusCode"))
            {
                const rapidjson::Value& status_code_val = json["statusCode"];
                int status_code = status_code_val.GetInt();
                if (status_code == STATUS_CODE_OK)
                {
                    if (json.HasMember("message"))
                    {
                        const rapidjson::Value& msg_val = json["message"];
                        if (msg_val.HasMember("authenticated"))
                        {
                            const rapidjson::Value& auth_val = msg_val["authenticated"];
                            bool auth = auth_val.GetBool();
                            if (!auth)
                            {
                                p_logger->printf(Log::Error, " %s Authentication failed.", __func__);
                                EventManager::getInstance()->notifyAuthorizationFailure("");
                            }
                            else
                            {
                                p_logger->printf(Log::Information, " %s Authentication successful.", __func__);
                                EventManager::getInstance()->notifyAuthorizationSuccess();
                            }
                        }
                        else
                        {
                            p_logger->printf(Log::Error, " %s No authentication response value from API (was expected).", __func__);
                            EventManager::getInstance()->notifyAuthorizationFailure("No authorization response received from API");
                            break;
                        }
                    }
                }
                else if (status_code == STATUS_CODE_RETRY_AUTHORIZATION)
                {
                    // Implicit authentication success as we can't get a 5105 response without successfully having authenticated
                    // This code indicates we have a pending authorization response and must retry again in interval defined
                    // in the configuration under RETRY_AUTHORIZATION_INTERVAL_S.
                    const long authorization_retry_interval_s = config.lookupAsLong(CFG_RETRY_AUTHORIZATION_INTERVAL_S);
                    p_logger->printf(
                        Log::Information, 
                        " %s Authentication successful. Authorization in progress...", 
                        __func__);
                    p_logger->printf(
                        Log::Debug, 
                        " %s Requesting authorization result in %d seconds",
                        __func__,
                        authorization_retry_interval_s);
                    sleep_period_s = authorization_retry_interval_s;
                    overwrite_sleep = true;
                } 
                else
                {
                    p_logger->printf(Log::Critical, " %s Non zero status code received: %d.", __func__, status_code);
                    if (json.HasMember("errorMessage"))
                    {
                        const rapidjson::Value& err_msg_val = json["errorMessage"];
                        if (!err_msg_val.IsNull())
                        {
                            const std::string error_msg = err_msg_val.GetString();
                            p_logger->printf(Log::Critical, " %s Auth failed with error: %s", __func__, error_msg.c_str());
                        }
                    }
                }

                // Assets
                if (json.HasMember("assets"))
                {
                    // Get the number of assets
                    const rapidjson::Value& assets_val = json["assets"];
                    unsigned int asset_count = assets_val.Size();
                    if (asset_count > 0)
                    {
                        p_logger->printf(Log::Information, " %s Found %d asset(s).", __func__, asset_count);

                        unsigned int asset_sleep_value_s = 0;
                        p_worker_loop->processAssets(asset_manager, json, new_key, new_iv, new_keyid, p_asset_messenger.get(), asset_sleep_value_s);
                        if (asset_sleep_value_s != 0)
                        {
                            sleep_period_s = asset_sleep_value_s;
                            p_logger->printf(Log::Information, " %s Updated pollingRate to %d", __func__, sleep_period_s);
                            overwrite_sleep = true;
                        }
                        else if (asset_manager.assetsProcessingCount() == 0 && !asset_manager.isWaitingForCertificate() && asset_sleep_value_s == 0)
                        {
                            // There are no pending assets, we haven't received a new sleep value and we don't need to 
                            // wait for a new asset, indicating that all assets have been processed. Set to zero so 
                            // that we can exit not in daemon mode
                            asset_count = 0;
                        }
                    }

                    if (asset_count == 0)
                    {
                        p_logger->printf(Log::Information, " %s No more asset to process", __func__);
                        if (!p_worker_loop->m_daemon_mode)
                        {
                            p_worker_loop->interrupt();
                        }
                    }
                }
                else
                {
                    p_logger->printf(Log::Information, " %s No new asset found.", __func__);
                }
            }
        }
        else
        {
            p_logger->printf(Log::Error, " %s Authorization failed with reason: %s", __func__, message.c_str());
            EventManager::getInstance()->notifyAuthorizationFailure("");
            if (!p_worker_loop->m_daemon_mode)
            {
                int error_code = 1;
                if (message.find("DAE code") != std::string::npos)
                {
                    error_code = 2;
                }
                if (message.find("DDKG code") != std::string::npos)
                {
                    error_code = 3;
                }
                if (message.find("cURL code") != std::string::npos)
                {
                    error_code = 5;
                }
                p_worker_loop->interrupt(error_code);
            }
        }

        // Calculate if we need to change the polling time
        unsigned int polling_time_s = 0;
        if (asset_manager.isWaitingForCertificate())
        {
            polling_time_s = p_worker_loop->m_requested_data_poll_time_s;
        }
        else
        {
            if (overwrite_sleep)
            {
                polling_time_s = sleep_period_s;
            }
            else
            {
                polling_time_s = p_worker_loop->m_sleep_period_s;
            }
        }

        // Update pending assets and heartbeat monitor
        asset_manager.update();
        heartbeat_manager.update();

		// Sleep for required period but keep checking for interrupt every second
        const int64_t interval_ms = steady_timer::MILLISECONDS_IN_ONE_SECOND;
        const int64_t polling_time_ms = (int64_t)polling_time_s * steady_timer::MILLISECONDS_IN_ONE_SECOND;
        loop_duration_ms += loop_timer.get_elapsed_time_in_millseconds();
        while ((loop_duration_ms < polling_time_ms) && !p_worker_loop->isInterrupted())
        {
            loop_timer.reset();
            sleep_ms(std::min<int64_t>(interval_ms, polling_time_ms - loop_duration_ms));
            asset_manager.update();
            heartbeat_manager.update();
            loop_duration_ms += loop_timer.get_elapsed_time_in_millseconds();
        }
        loop_duration_ms %= polling_time_ms; // Retain remaining milliseconds to ensure we can correct any overshot of polling interval in next loop
		stuff_to_do = (!p_worker_loop->isInterrupted());
    }

    p_logger->printf(Log::Debug, "credentialManagerLoop All done");

    return 0;
}

HttpWorkerLoop::HttpWorkerLoop(const std::string &api_url, const std::string &metadata_file, bool daemon_mode, long sleep_period_s, long requested_data_poll_time_s)
    : BaseWorkerLoop(sleep_period_s)
    , m_api_url(api_url)
    , m_metadata_file(metadata_file)
    , m_daemon_mode(daemon_mode)
    , m_requested_data_poll_time_s(requested_data_poll_time_s)
{

}

void HttpWorkerLoop::initialize()
{
    DAHttpClient::init();
}

void HttpWorkerLoop::run()
{
    pthread_attr_t attr_thread_cred;
    pthread_attr_init(&attr_thread_cred);
    pthread_attr_setdetachstate(&attr_thread_cred, PTHREAD_CREATE_JOINABLE);

    pthread_t thread_credential;
    pthread_create(&thread_credential, &attr_thread_cred, credentialManagerLoop, this);

    pthread_join(thread_credential, nullptr);
    pthread_attr_destroy(&attr_thread_cred);
}

void HttpWorkerLoop::terminate()
{
    DAHttpClient::terminate();
}

bool HttpWorkerLoop::processAssets(AssetManager &asset_manager, const rapidjson::Document &json, const std::string &key, const std::string &iv, const std::string &key_id, AssetMessenger *p_asset_messenger, unsigned int &sleep_period_from_ks)
{
    // Initialise the logging
    Log *p_logger = Log::getInstance();

    bool result = false; // Assume it hasn't worked
    if (!json.IsNull() && json.HasMember("assets"))
    {
        const rapidjson::Value &assets_val = json["assets"];
        unsigned int success_count = 0;
        unsigned int in_progress_count = 0;
        unsigned int element_count = assets_val.Size(); // Get the number of assets
        for (unsigned int c = 0; c < element_count; ++c)
        {
            p_logger->printf(Log::Information, " %s Processing Asset[%02d]", __func__, (c + 1));

            // Asset Id
            const rapidjson::Value &asset_val = assets_val[c];
            std::string asset_id_str;
            if (asset_val.HasMember("assetId"))
            {
                const rapidjson::Value &asset_id_val = asset_val["assetId"];
                if (!asset_id_val.IsNull())
                {
                    asset_id_str = asset_id_val.GetString();
                }
            }
            if (asset_id_str.empty())
            {
                const std::string message = "No asset identifier specified (was expected)";
                p_logger->printf(Log::Error, " %s Asset[%02d] %s", __func__, (c + 1), message.c_str());
                continue;
            }

            std::string asset_type_str;
            if (asset_val.HasMember("assetType"))
            {
                const rapidjson::Value &asset_type_val = asset_val["assetType"];
                if (!asset_type_val.IsNull())
                {
                    if (asset_manager.isAssetProcessing(asset_id_str))
                    {
                        p_logger->printf(Log::Information, " %s asset is being processed", asset_id_str.c_str());
                        in_progress_count++;
                        continue;
                    }

                    asset_type_str.assign(utils::toLower(asset_type_val.GetString()));
                    p_logger->printf(Log::Debug, " %s Asset[%02d] of type: '%s'", __func__, (c + 1), asset_type_str.c_str());

                    std::unique_ptr<AssetProcessor> p_asset_processor = nullptr;
                    try
                    {                    
                        if (asset_type_str == "certificate")
                        {
                            p_asset_processor.reset(
                                new CertificateAssetProcessor(
                                    asset_id_str,
                                    p_asset_messenger));
                        }
                        else if (asset_type_str == "apm_password")
                        {
                            p_asset_processor.reset(
                                new ApmAssetProcessor(
                                    asset_id_str,
                                    p_asset_messenger));
                        }
                        else if (asset_type_str == "certificatedata")
                        {
                            p_asset_processor.reset(
                                new CertificateDataAssetProcessor(
                                    asset_id_str,
                                    p_asset_messenger));
                        }
                        else if (asset_type_str == "script" || asset_type_str == "code_signing")
                        {
                            p_asset_processor.reset(
                                new ScriptAssetProcessor(
                                    asset_id_str,
                                    p_asset_messenger,
                                    RsaUtils::getRSAPublicKey()));
                        }
                        else if (asset_type_str == "group")
                        {
                            p_asset_processor.reset(
                                new GroupAssetProcessor(
                                    asset_id_str,
                                    p_asset_messenger,
                                    config.lookup(CFG_METADATAFILE)));
                        }

                        if (!p_asset_processor.get())
                        {
                            p_logger->printf(Log::Error, " %s Asset[%02d] Unknown asset type '%s', ignoring asset.",
                                __func__,
                                (c + 1),
                                asset_type_str.c_str());
                            continue;
                        }
                    }
                    catch (const std::exception& ex)
                    {
                        p_logger->printf(Log::Error, " %s:%d, Asset generation failed: %s", __func__, __LINE__, ex.what());
                        continue;
                    }

                    auto asset_status = asset_manager.processAsset(
                        std::move(p_asset_processor), asset_val, key, iv, key_id, sleep_period_from_ks);
                    if (asset_status == Asset::IN_PROGRESS)
                    {
                        in_progress_count++;
                    }
                    else if (asset_status == Asset::SUCCESS)
                    {
                        success_count++;
                    }
                }
            }

            if (asset_type_str.empty())
            {
                const std::string message = "No asset type specified (was expected).";
                p_logger->printf(Log::Error, " %s Asset[%02d] %s", __func__, (c + 1), message.c_str());
            }
        }

        if (success_count > 0 || in_progress_count > 0)
        {
            if (success_count == element_count)
            {
                p_logger->printf(Log::Information, " %s Successfully processed %d asset(s).", __func__, element_count);
            }
            else
            {
                p_logger->printf(
                    Log::Information,
                    " %s %d of %d asset(s) completed successfully. %d assets currently being processed.",
                    __func__,
                    success_count,
                    element_count,
                    in_progress_count);
            }
            result = true;
        }
        else if (element_count > 0)
        {
            p_logger->printf(Log::Information, " %s Failed to process any assets.", __func__);
        }
    }
    else
    {
        const std::string message = "No assets found (was expected).";
        p_logger->printf(Log::Error, " %s %s", __func__, message.c_str());
    }
    return result;
}
