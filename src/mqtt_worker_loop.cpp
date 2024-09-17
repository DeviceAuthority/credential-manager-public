/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Credential manager worker that uses MQTT
 */

#ifndef DISABLE_MQTT

#include <list>
#include <queue>
#include "asset_manager.hpp"
#include "certificate_asset_processor.hpp"
#include "certificate_data_asset_processor.hpp"
#include "configuration.hpp"
#include "damqttclient.hpp"
#include "deviceauthority.hpp"
#include "message_factory.hpp"
#include "mosquitto.h"
#include "mqtt_asset_messenger.hpp"
#include "mqtt_worker_loop.hpp"
#include "timehelper.h"
#include "constants.hpp"
#include "opensslhelper.h"
#include "sat_asset_processor.hpp"

enum WorkerState : int
{
    IDLE,
    CH_REGISTER,
    REGISTER,
    CH_AUTH,
    AUTH,
    AUTH_GET_KEY,
    ACK_ASSET,
    SUBMIT_CSR
};

struct ScriptData
{
    const std::string m_script_id;
    const std::string m_script_key_id;
    const std::string m_script_data;
    std::string m_decryption_key_id;
    std::string m_decryption_key;
    std::string m_decryption_iv;

    ScriptData(const std::string &script_id, const std::string &script_key_id, const std::string &script_data)
        : m_script_id(script_id), m_script_key_id(script_key_id), m_script_data(script_data)
    {

    }
};

static const std::string getDeviceSpecificTopic(const std::string &tid)
{
    return SSLWrapper::md5hashstring(tid);
}

static void subscribeForScripts(DAMqttClientBase *p_mqtt_client)
{
    const std::string device_tid = p_mqtt_client->getTid();
    if (device_tid.empty())
    {
        p_mqtt_client->setSubscribedForScripts(false);
        return; // Cannot subscribe as TID is empty
    }

    std::string script_topic = "device/";
    script_topic.append(getDeviceSpecificTopic(device_tid));
    script_topic.append("/in");

    if (mosquitto_subscribe(p_mqtt_client->getHandle(), nullptr, script_topic.c_str(), 2) == MOSQ_ERR_SUCCESS)
    {
        Log::getInstance()->printf(Log::Debug, "Subscribed to device specific topic: %s", script_topic.c_str());
        p_mqtt_client->setSubscribedForScripts(true);
    }
    else
    {
        Log::getInstance()->printf(Log::Error, "Failed to subscribe to device specific topic: %s", script_topic.c_str());
        p_mqtt_client->setSubscribedForScripts(false);
    }
}

// Callback Functions
static void onConnect(struct mosquitto *p_mosq, void *p_userdata, int result)
{
    Log *p_logger = Log::getInstance();
    if (!result)
    {
        DAMqttClientBase *p_mqtt_client = static_cast<DAMqttClientBase*>(p_userdata);
        const std::string topic = p_mqtt_client->m_mqtt_topic_sub;

        p_logger->printf(Log::Information, "MQTT connected!");

        /* Subscribe to broker information topics on successful connect. */
        p_logger->printf(Log::Information, "Subscribing to MQTT topic %s", topic.c_str());
        if (mosquitto_subscribe(p_mosq, nullptr, topic.c_str(), 2) == MOSQ_ERR_SUCCESS)
        {
            p_logger->printf(Log::Debug, "Subscribed to device specific topic: %s", topic.c_str());

            if (p_mqtt_client->isSubscribedForScripts())
            {
                // As we have previously subscribed and have had to reconnect to MQTT 
                // we will also need to resubscribe to scripts
                subscribeForScripts(p_mqtt_client);
            }
        }
        else
        {
            p_logger->printf(Log::Error, "Failed to subscribe to topic: %s", topic.c_str());
        }
    }
    else
    {
        p_logger->printf(Log::Error, "MQTT connection failed!");
    }
}

static void onMessageReceived(struct mosquitto *p_mosq, void *p_userdata, const struct mosquitto_message *p_message)
{
    Log *p_logger = Log::getInstance();
    if (p_message->payloadlen)
    {
        p_logger->printf(Log::Debug, "MQTT received from topic '%s': mid(%d), payload of %d byte(s)", p_message->topic, p_message->mid, p_message->payloadlen);
        p_logger->printf(Log::Debug, "%s", static_cast<char*>(p_message->payload));

        DAMqttClientBase *p_mqtt_client = static_cast<DAMqttClientBase*>(p_userdata);
        p_mqtt_client->enqueueMessage(
            std::unique_ptr<MqttMessage>(
                new MqttMessage(
                    p_message->mid,
                    std::string(p_message->topic),
                    std::string((const char*)p_message->payload, p_message->payloadlen))));

        p_logger->printf(Log::Debug, "Payload with mid %d inserted", p_message->mid);
    }
    else
    {
        p_logger->printf(Log::Debug, "MQTT received from topic '%s': empty payload", p_message->topic);
    }
    fflush(stdout);
}

static void onSubscribe(struct mosquitto *p_mosq, void *p_userdata, int mid, int qos_count, const int *granted_qos)
{
    Log *p_logger = Log::getInstance();
    p_logger->printf(Log::Debug, "MQTT subscribe (mid: %d): %d", mid, granted_qos[0]);

    for (int i = 1; i < qos_count; i++)
    {
        p_logger->printf(Log::Debug, ", %d", granted_qos[i]);
    }
    p_logger->printf(Log::Debug, "\n");
}

static void onLogReceived(struct mosquitto *p_mosq, void *p_userdata, int level, const char *str)
{
    Log::getInstance()->printf(Log::Debug, "MQTT log str: %s", str);
}

static void onPublish(struct mosquitto *p_mosq, void *obj, int mid)
{
    Log::getInstance()->printf(Log::Debug, "MQTT payload published");
}

void processAssets(
    AssetManager &asset_manager,
    AssetMessenger *p_asset_messenger,
    const rapidjson::Value& assets,
    std::string &key,
    std::string &iv,
    std::string &key_id)
{
    Log *p_logger = Log::getInstance();
    if (assets.Size() > 0)
    {
        p_logger->printf(Log::Information, "Received %d asset(s) in the response", (int)assets.Size());
    }

    for (int c = 0; c < (int)assets.Size(); c++)
    {
        unsigned int time = 1000;

        const rapidjson::Value& asset_id_val = assets[c]["assetId"];
        const std::string asset_id = asset_id_val.GetString();

        const rapidjson::Value& asset_type_val = assets[c]["assetType"];
        const std::string asset_type = asset_type_val.GetString();

        p_logger->printf(Log::Information, "Processing %s asset", asset_type.c_str());

        std::unique_ptr<AssetProcessor> p_asset_processor(nullptr);
        if (asset_type == "certificatedata")
        {
            p_asset_processor.reset(new CertificateDataAssetProcessor(asset_id, p_asset_messenger));
        }
        else if (asset_type == "certificate")
        {
            p_asset_processor.reset(new CertificateAssetProcessor(asset_id, p_asset_messenger));
        }

        if (p_asset_processor)
        {
            asset_manager.processAsset(std::move(p_asset_processor), assets[c], key, iv, key_id, time);
        }
    }
}

void *mqttClientLoop(void *p_param)
{
    DAMqttClientBase *p_mqtt_client = (DAMqttClientBase*)p_param;
    p_mqtt_client->loop();
    return nullptr;
}

void *mqttCredentialManagerLoop(void *p_param)
{
    Log *p_logger = Log::getInstance();
    p_logger->printf(Log::Notice, "Credential Manager MQTT Loop");

    MqttWorkerLoop *p_worker_loop = static_cast<MqttWorkerLoop*>(p_param);

    DeviceAuthorityBase *p_da_instance = DeviceAuthority::getInstance();
    DAMqttClientBase *p_mqtt_client = p_worker_loop->getMqttClient();
    p_mqtt_client->setTid(p_da_instance->getDeviceTid());

    std::unique_ptr<MqttAssetMessenger> p_asset_messenger(new MqttAssetMessenger(p_mqtt_client));

    // Initial attempt to authenticate
    std::string message;
    const std::string udi = config.lookup(CFG_UDI);
    const std::string user_agent = p_da_instance->userAgentString();
    const std::string user_id = p_da_instance->getUserId();
    std::string json_request = "";
    {
        const std::string device_key = p_da_instance->getDeviceKey("", message);
        json_request = MessageFactory::generateMqttPayload("ch", udi, user_agent, user_id, "auth", device_key.c_str());
        p_logger->printf(Log::Debug, "Publish JSON req: %s", json_request.c_str());
        p_mqtt_client->publish(json_request);
    }

    std::string newkeyid;
    std::string newkey;
    std::string newiv;
    AssetManager asset_manager;

    std::queue<ScriptData> pending_scripts{};

    WorkerState state = CH_AUTH;

    bool running = true;
    while (running)
    {
        if (p_mqtt_client->isMessageQueued())
        {
            // We have an MQTT response to handle
            std::unique_ptr<MqttMessage> p_mqtt_message = p_mqtt_client->getNextMessage();

            p_logger->printf(Log::Debug, "MQTT JSON response: %s", p_mqtt_message->m_msg.c_str());

            rapidjson::Document json;
            json.Parse(p_mqtt_message->m_msg.c_str());
            if (json.HasParseError())
            {
                p_logger->printf(Log::Error, "Bad JSON response");
                continue;
            }

            std::string operation;
            if (json.HasMember("op"))
            {
                rapidjson::Value& op_val = json["op"];

                operation = op_val.GetString();
                p_logger->printf(Log::Debug, "Response op: %s", operation.c_str());
            }
            else
            {
                operation = "";
            }

            if (json.HasMember("res"))
            {
                rapidjson::Value& res = json["res"];
                if (res.HasMember("statusCode"))
                {
                    rapidjson::Value& status_code_val = res["statusCode"];

                    p_logger->printf(Log::Debug, "Response status code: %d", status_code_val.GetInt());
                }

                if (res.HasMember("message"))
                {
                    rapidjson::Value& res_message = res["message"];
                    if (res_message.HasMember("errorMessage"))
                    {
                        rapidjson::Value& err = res_message["errorMessage"];
                        const std::string err_msg = err.GetString();
                        p_logger->printf(Log::Error, "Response error message: %s", err_msg.c_str());
                    }

                    if (operation.compare("auth") == 0)
                    {
                        bool authenticated = false;

                        if (res_message.HasMember("authenticated"))
                        {
                            rapidjson::Value& authenticated_val = res_message["authenticated"];
                            authenticated = authenticated_val.GetBool();

                            if (authenticated)
                            {
                                std::string message_type;
                                if (res_message.HasMember("type"))
                                {
                                    rapidjson::Value& message_type_val = res_message["type"];
                                    message_type = message_type_val.GetString();
                                }

                                if (!p_mqtt_client->isSubscribedForScripts())
                                {
                                    subscribeForScripts(p_mqtt_client);
                                }

                                p_logger->printf(Log::Information, "Device authentication successful!");

                                if (message_type.compare("auth-data-message") == 0)
                                {
                                    if (res.HasMember("assets"))
                                    {
                                        processAssets(
                                            asset_manager,
                                            p_asset_messenger.get(),
                                            res["assets"],
                                            newkey,
                                            newiv,
                                            newkeyid);
                                    }
                                    else
                                    {
                                        // Auth response with no asset
                                        p_logger->printf(Log::Debug, "No asset is received in the response");
                                    }
                                }
                                else if (message_type.compare("auth-key-data-message") == 0 && !pending_scripts.empty())
                                {
                                    // Use the (DK) key and iv to decrypt the response key and iv in here.
                                    if (res_message.HasMember("key") && res_message.HasMember("iv"))
                                    {
                                        const auto pending_script = pending_scripts.front();

                                        std::string request_id;
                                        if (res.HasMember("requestId"))
                                        {
                                            rapidjson::Value& request_id_val = res["requestId"];
                                            request_id = request_id_val.GetString();
                                        }

                                        std::unique_ptr<SatAssetProcessor> p_asset_processor(
                                            new SatAssetProcessor(
                                                request_id,
                                                p_asset_messenger.get(),
                                                pending_script.m_script_id,
                                                pending_script.m_script_data,
                                                getDeviceSpecificTopic(p_mqtt_client->getTid())));

                                        unsigned int sleep_time_from_ks = 1000;
                                        asset_manager.processAsset(
                                            std::move(p_asset_processor),
                                            res_message,
                                            pending_script.m_decryption_key,
                                            pending_script.m_decryption_iv,
                                            pending_script.m_decryption_key_id,
                                            sleep_time_from_ks);

                                        pending_scripts.pop();
                                    }
                                    else
                                    {
                                        p_logger->printf(Log::Error, "Missing key or iv in the auth-key-data-message response");
                                    }
                                }
                            }
                            else
                            {
                                p_logger->printf(Log::Error, "Device NOT authenticated!");
                            }
                        }

                        if (!authenticated)
                        {
                            // Attempt to perform smart registration
                            const std::string device_key = p_da_instance->getDeviceKey("", message);
                            json_request = MessageFactory::generateMqttPayload("ch", udi, user_agent, user_id, "auth", device_key.c_str());
                            p_logger->printf(Log::Debug, "Publish JSON req: %s", json_request.c_str());
                        }
                        else
                        {
                            // Request auth challenge
                            json_request = MessageFactory::generateMqttPayload("ch", udi, user_agent, user_id, "auth", "", p_mqtt_client->getTid().c_str());
                        }
                        state = CH_AUTH;
                    }
                    else if (operation.compare("ch") == 0)
                    {
                        std::string challenge_id = "";
                        if (res_message.HasMember("challenge"))
                        {
                            rapidjson::Value& challenge_val = res_message["challenge"];
                            challenge_id = challenge_val.GetString();
                        }

                        std::string next_action = "";
                        if (res_message.HasMember("nextAction"))
                        {
                            rapidjson::Value& next_action_val = res_message["nextAction"];
                            next_action = next_action_val.GetString();
                        }

                        std::string err_msg = "";
                        char theKeyID[1024] = { 0 };
                        char theKey[1024] = { 0 };
                        char theIV[1024] = { 0 };
                        const std::string deviceKey = p_da_instance->getDeviceKey(challenge_id, err_msg, theKeyID, theKey, theIV);

                        if (next_action.compare("register") == 0)
                        {
                            if (state == CH_AUTH || state == CH_REGISTER)
                            {
                                p_logger->printf(Log::Information, "Device registration required");
                                p_mqtt_client->setSubscribedForScripts(false);

                                // Attempt device registration
                                json_request = MessageFactory::generateMqttPayload("register", udi, user_agent, user_id, "", (char*)deviceKey.c_str());
                                state = REGISTER;
                            }
                        }
                        else
                        {
                            p_logger->printf(Log::Debug, "theKeyID: %s", theKeyID);
                            p_logger->printf(Log::Debug, "theKey: %s", theKey);
                            p_logger->printf(Log::Debug, "theIV: %s", theIV);

                            newkeyid = theKeyID;
                            newkey = theKey;
                            newiv = theIV;

                            if (!pending_scripts.empty())
                            {
                                auto &pending_script = pending_scripts.front();
                                // We have encrypted scripts to run so let's request the key to decrypt the next pending script
                                pending_script.m_decryption_key_id = theKeyID;
                                pending_script.m_decryption_key = theKey;
                                pending_script.m_decryption_iv = theIV;
                                // Attempt device authentication (get key)
                                json_request = MessageFactory::generateMqttPayload("auth", udi, user_agent, user_id, "auth-get-key", deviceKey.c_str(), "", "", "", pending_script.m_script_key_id.c_str());
                                state = AUTH_GET_KEY;
                            }
                            else
                            {
                                // Attempt device authentication (basic/adv)
                                json_request = MessageFactory::generateMqttPayload("auth", udi, user_agent, user_id, "", deviceKey.c_str());
                            }
                        }
                    }
                    else if (operation.compare("register") == 0)
                    {
                        rapidjson::Value& status_val = json["status"];
                        const bool success = status_val.GetBool();
                        if (success)
                        {
                            p_logger->printf(Log::Information, "Device registration successful");

                            // reload TID as it will have changed post-registration
                            p_mqtt_client->setTid(p_da_instance->getDeviceTid());

                            if (!p_mqtt_client->isSubscribedForScripts())
                            {
                                subscribeForScripts(p_mqtt_client);
                            }

                            json_request = MessageFactory::generateMqttPayload("ch", udi, user_agent, user_id, "auth", "", p_mqtt_client->getTid().c_str());
                            state = CH_AUTH;
                        }
                        else
                        {
                            // Attempt to perform smart registration
                            const std::string device_key = p_da_instance->getDeviceKey("", message);
                            json_request = MessageFactory::generateMqttPayload("ch", udi, user_agent, user_id, "auth", device_key.c_str());
                            p_logger->printf(Log::Debug, "Publish JSON req: %s", json_request.c_str());
                            state = CH_AUTH;
                        }
                    }
                }
                else
                {
                    // Response with no 'message' member
                    p_logger->printf(Log::Debug, "No 'message' member in the response");

                    if (operation.compare("device-csr") == 0)
                    {
                        json_request = MessageFactory::generateMqttPayload("ch", udi, user_agent, user_id, "auth", "", p_mqtt_client->getTid().c_str());
                        state = CH_AUTH;
                    }
                    else if (operation.compare("asset-status") == 0)
                    {
                        // Response for "asset-status" request
                        if (res.HasMember("requestId"))
                        {
                            rapidjson::Value& request_id_val = res["requestId"];
                            std::string request_id = request_id_val.GetString();
                            p_logger->printf(Log::Debug, "Request id: %s", request_id.c_str());
                        }
                    }
                }
            }
            else
            {
                // Response with no 'res' member
                if (json.HasMember("keyId") && json.HasMember("id") && json.HasMember("data"))
                {
                    rapidjson::Value& script_id_val = json["id"];
                    rapidjson::Value& script_key_id_val = json["keyId"];
                    rapidjson::Value& script_data_val = json["data"];
                    auto script_data = ScriptData(script_id_val.GetString(), script_key_id_val.GetString(), script_data_val.GetString());

                    p_logger->printf(Log::Information, "Secure Asset KeyId: %s", script_data.m_script_key_id.c_str());
                    p_logger->printf(Log::Information, "Secure Asset Id: %s", script_data.m_script_id.c_str());
                    p_logger->printf(Log::Information, "Secure Asset size: %d byte(s)", script_data.m_script_data.length());
                    // p_logger->printf(Log::Debug, "Secure Asset Data: %s", script_data.m_script_data.c_str());

                    pending_scripts.push(script_data);
                    state = AUTH_GET_KEY;
                }
            }

            if (state == CH_AUTH || state == CH_REGISTER)
            {
                // Enforce sleep period even if pending messages - this avoids constantly sending and replying to auth responses messages
                p_logger->printf(Log::Debug, "Going to sleep before sending out next challenge request");

                // Sleep for required period but keep checking for interrupt
                unsigned int interval = 1000;
                long total_sleep = 0;

                while ((total_sleep < (p_worker_loop->m_sleep_period_s * 1000)) && !p_worker_loop->isInterrupted())
                {
                    sleep_ms(interval);
                    total_sleep += interval;
                    asset_manager.update();
                }
            }

            // Now send the pending json request (if any)
            if (!json_request.empty())
            {
                p_mqtt_client->publish(json_request);
                json_request.clear();
            }
        }
        else
        {
            p_logger->printf(Log::Debug, "No MQTT response found. Going to sleep...");

            // Sleep for required period but keep checking for interrupt
            unsigned int interval = 1000;
            long total_sleep = 0;

            while ((total_sleep < (p_worker_loop->m_sleep_period_s * 1000)) && !p_worker_loop->isInterrupted())
            {
                sleep_ms(interval);
                total_sleep += interval;
                asset_manager.update();

                if (p_mqtt_client->isMessageQueued())
                {
                    // Break out from sleep whenever there is MQTT response message
                    p_logger->printf(Log::Debug, "MQTT response is available in the queue. Waking up...");
                    break;
                }
            }
        }

        running = (!p_worker_loop->isInterrupted());
    }

    p_logger->printf(Log::Debug, "mqttCredentialManagerLoop All done");

    p_mqtt_client->disconnect();

    return 0;
}

MqttWorkerLoop::MqttWorkerLoop(
    const std::string &broker_host,
    int broker_port,
    const std::string &mqtt_topic_in,
    const std::string &mqtt_topic_out,
    long sleep_period_ms)
    : BaseWorkerLoop(sleep_period_ms)
{
    mp_mqtt_client.reset(new DAMqttClient(mqtt_topic_out.c_str(), mqtt_topic_in.c_str(), broker_host.c_str(), broker_port, 60));
}

void MqttWorkerLoop::initialize()
{
    if (mp_mqtt_client->init(onLogReceived, onConnect, onMessageReceived, onSubscribe, onPublish) != MOSQ_ERR_SUCCESS)
    {
        mp_mqtt_client->terminate();
        mp_mqtt_client.reset(nullptr);
        openssl_kill_locks();
        exit(EXIT_FAILURE);
    }
}

void MqttWorkerLoop::run()
{
    pthread_attr_t attr_thread_cred;
    pthread_attr_init(&attr_thread_cred);

    pthread_attr_setdetachstate(&attr_thread_cred, PTHREAD_CREATE_JOINABLE);

    pthread_t mqtt_sub_thread;
    pthread_create(&mqtt_sub_thread, &attr_thread_cred, mqttClientLoop, (void*)mp_mqtt_client.get());

    // This appears to give time for the MQTT client to start up
    sleep_ms(1000);

    pthread_t thread_credential;
    pthread_create(&thread_credential, &attr_thread_cred, mqttCredentialManagerLoop, (void*)this);

    pthread_join(mqtt_sub_thread, nullptr);
    pthread_join(thread_credential, nullptr);
    pthread_attr_destroy(&attr_thread_cred);
}

void MqttWorkerLoop::terminate()
{
    if (mp_mqtt_client)
    {
        mp_mqtt_client->terminate();
        mp_mqtt_client.reset(nullptr);
    }
}

DAMqttClientBase *MqttWorkerLoop::getMqttClient() const
{
    return mp_mqtt_client.get();
}

#endif // DISABLE_MQTT
