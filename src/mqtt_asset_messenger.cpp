
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Asset messenger for MQTT mode
 */

#ifndef DISABLE_MQTT

#include <string>
#include "base64.h"
#include "configuration.hpp"
#include "constants.hpp"
#include "deviceauthority.hpp"
#include "message_factory.hpp"
#include "mqtt_asset_messenger.hpp"
#include "utils.hpp"

MqttAssetMessenger::MqttAssetMessenger(DAMqttClientBase *p_mqtt_client)
    : mp_mqtt_client(p_mqtt_client)
{

}

bool MqttAssetMessenger::identifyAndAuthorise(std::string &da_json, std::string &new_key_id, std::string &new_key, std::string &new_iv, std::string &message)
{
    return true;
}


bool MqttAssetMessenger::acknowledgeAPMReceipt(const std::string &receipt_json, std::string &message)
{
    return acknowledgeReceipt(receipt_json, message);
}

bool MqttAssetMessenger::acknowledgeReceipt(const std::string &receipt_json, std::string &message)
{
    if (!mp_mqtt_client)
    {
        return false;
    }

    DeviceAuthorityBase *p_da_instance = DeviceAuthority::getInstance();
    if (p_da_instance == nullptr)
    {
        message = "DeviceAuthority object was not initialized";
        return false;
    }

    const std::string tid = p_da_instance->getDeviceTid();
    const std::string udi = config.lookup(CFG_UDI);
    const std::string user_agent = p_da_instance->userAgentString();
    const std::string user_id = p_da_instance->getUserId();
    const std::string json_request = MessageFactory::generateMqttPayload("asset-status", udi, user_agent, user_id, "", nullptr, receipt_json.c_str());

    mp_mqtt_client->publish(json_request);

    return true;
}

bool MqttAssetMessenger::submitCSRForSigning(
    const std::string &auth_json,
    const std::string &certificate_id,
    const std::string &generated_csr,
    std::string &message)
{
    DeviceAuthorityBase *p_da_instance = DeviceAuthority::getInstance();
    if (p_da_instance == nullptr)
    {
        message = "DeviceAuthority object was not initialized";
        return false;
    }

    const std::string tid = p_da_instance->getDeviceTid();
    const std::string udi = config.lookup(CFG_UDI);
    const std::string user_agent = p_da_instance->userAgentString();
    const std::string user_id = p_da_instance->getUserId();
    const std::string json_request = MessageFactory::generateMqttPayload("ch", udi, user_agent, user_id, "auth", "", (char*)tid.c_str(), certificate_id.c_str(), generated_csr.c_str());

    mp_mqtt_client->publish(json_request);

    return true;
}

bool MqttAssetMessenger::fetchFile(const std::string &apiurl, const std::string &response_file_path)
{
    Log *p_logger = Log::getInstance();
    p_logger->printf(Log::Error, "fetchFile not supported using MQTT protocol");
    return false;
}

bool MqttAssetMessenger::sendScriptOutput(const std::string &script_id, const std::string &device_specific_topic, const std::string &script_output)
{
    Log *p_logger = Log::getInstance();

    if (mp_mqtt_client)
    {
        std::string script_topic = "device/";
        script_topic.append(device_specific_topic);
        script_topic.append("/out");

        p_logger->printf(Log::Information, "Publish to device specific topic: %s", script_topic.c_str());
        p_logger->printf(Log::Debug, "%s", script_output.c_str());

        const std::string json_request = MessageFactory::buildScriptOutputMessage(script_id, script_output);
        mp_mqtt_client->publish(script_topic, json_request);
    }

    return true;
}

#endif // DISABLE_MQTT