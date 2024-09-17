
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Asset messenger for MQTT mode
 */
#ifndef MQTT_ASSET_MESSENGER_HPP
#define MQTT_ASSET_MESSENGER_HPP

#include <string>
#include "asset_messenger.hpp"
#include "damqttclient_base.hpp"

class MqttAssetMessenger : public AssetMessenger
{
public:
    MqttAssetMessenger(DAMqttClientBase *p_mqtt_client);

	virtual ~MqttAssetMessenger() {};

    bool identifyAndAuthorise(std::string &da_json, std::string &new_key_id, std::string &new_key, std::string &new_iv, std::string &message) override;

    bool acknowledgeReceipt(const std::string &receipt_json, std::string &message) override;

    bool acknowledgeAPMReceipt(const std::string &receipt_json, std::string &message) override;

    bool submitCSRForSigning(
        const std::string &auth_json,
        const std::string &certificate_id,
        const std::string &generated_csr,
        std::string &message);

    bool fetchFile(const std::string &apiurl, const std::string &response_file_path);

    bool sendScriptOutput(const std::string &script_id, const std::string &device_specific_topic, const std::string &script_output);


private:
    /// @brief The MQTT client
    DAMqttClientBase *const mp_mqtt_client;
};

#endif // #ifndef MQTT_ASSET_MESSENGER_HPP
