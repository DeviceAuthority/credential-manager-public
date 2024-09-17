
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Base class for asset messengers
 */
#ifndef ASSET_MESSENGER_HPP
#define ASSET_MESSENGER_HPP

#include <string>

class AssetMessenger
{
public:
	virtual ~AssetMessenger() {};

    virtual bool identifyAndAuthorise(std::string &da_json, std::string &new_key_id, std::string &new_key, std::string &new_iv, std::string &message) = 0;

    /**
     * @brief Sends an acknowledge receipt to the KeyScaler
     *
     * @param json_receipt The receipt in JSON format to send
     * @param message The error string in the event of failure to acknowledge
     * @return True on successful acknowledgement, else false
     */
    virtual bool acknowledgeReceipt(const std::string &receipt_json, std::string &message) = 0;

    virtual bool acknowledgeAPMReceipt(const std::string &receipt_json, std::string &message) = 0;

    virtual bool submitCSRForSigning(const std::string &auth_json, const std::string &certificate_id, const std::string &generated_csr, std::string &message) = 0;

    virtual bool fetchFile(const std::string &apiurl, const std::string &response_file_path) = 0;

    virtual bool sendScriptOutput(const std::string &script_id, const std::string &device_specific_topic, const std::string &script_output) = 0;

};

#endif // #ifndef ASSET_MESSENGER_HPP
