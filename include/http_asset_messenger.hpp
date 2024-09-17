
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Asset messenger for HTTP mode
 */
#ifndef HTTP_ASSET_MESSENGER_HPP
#define HTTP_ASSET_MESSENGER_HPP

#include <string>
#include "asset_messenger.hpp"
#include "dahttpclient.hpp"

class HttpAssetMessenger : public AssetMessenger
{
public:
    HttpAssetMessenger(const std::string &dest_url, DAHttpClientBase *p_http_client);

	virtual ~HttpAssetMessenger() {};

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
    /// @brief The destination URL
    const std::string m_dest_url;

    /// @brief The HTTP client
    DAHttpClientBase *const mp_http_client;

    /// @brief Acknowledge receipt of an asset with a success / failure response
    /// @param ack_path The SAC API path to send the acknowledge response to
    /// @param json_receipt The receipt in JSON format to send
    /// @param message The error string in the event of failure to acknowledge
    /// @return True on successful acknowledgement, else false
    bool acknowledgeReceipt(const std::string &ack_path, const std::string &receipt_json, std::string &message);
};

#endif // #ifndef HTTP_ASSET_MESSENGER_HPP
