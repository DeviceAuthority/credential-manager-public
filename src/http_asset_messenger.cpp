
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Asset messenger for HTTP mode
 */

#include <string>
#include "base64.h"
#include "deviceauthority.hpp"
#include "http_asset_messenger.hpp"
#include "message_factory.hpp"
#include "utils.hpp"

HttpAssetMessenger::HttpAssetMessenger(const std::string &dest_url, DAHttpClientBase *p_http_client)
    : m_dest_url(dest_url), mp_http_client(p_http_client)
{

}

bool HttpAssetMessenger::identifyAndAuthorise(std::string &da_json, std::string &new_key_id, std::string &new_key, std::string &new_iv, std::string &message)
{
    DeviceAuthorityBase *p_da_instance = DeviceAuthority::getInstance();
    if (p_da_instance == nullptr)
    {
        message = "DeviceAuthority object was not initialized";
        return false;
    }

    da_json = p_da_instance->identifyAndAuthorise(new_key_id, new_key, new_iv, message, mp_http_client);
    if (da_json.empty())
    {
        message = "Failed to identify and authorize";
        return false;
    }

    return true;
}

bool HttpAssetMessenger::acknowledgeAPMReceipt(const std::string &receipt_json, std::string &message)
{
    return acknowledgeReceipt("/apm/acknowledgement", receipt_json, message);
}

bool HttpAssetMessenger::acknowledgeReceipt(const std::string &receipt_json, std::string &message)
{
    return acknowledgeReceipt("/assets/deliverystatus", receipt_json, message);
}

bool HttpAssetMessenger::acknowledgeReceipt(const std::string &ack_path, const std::string &receipt_json, std::string &message)
{
    Log *p_logger = Log::getInstance();

    std::string da_json, newkeyid, newkey, newiv;
    if (!identifyAndAuthorise(da_json, newkeyid, newkey, newiv, message))
    {
        p_logger->printf(Log::Error, " %s %s", __func__, message.c_str());
        return false;
    }

    da_json = MessageFactory::buildAuthenticationMessage(da_json, receipt_json);
    const std::string ack_dest_url = m_dest_url + ack_path;
    p_logger->printf(Log::Debug, " %s In acknowledgeReceipt: %s", __func__, da_json.c_str());
    p_logger->printf(Log::Debug, " %s In acknowledgeReceipt apiurl: %s", __func__, ack_dest_url.c_str());

    rapidjson::Document json;
    DAErrorCode rc_http_client = ERR_OK;
    std::string json_response("");

    rc_http_client = mp_http_client->sendRequest(DAHttp::ReqType::ePOST, ack_dest_url, json_response, da_json);

    p_logger->printf(Log::Debug, " %s %d sendRequest returns %d\n", __func__, __LINE__, rc_http_client);
    if (rc_http_client != ERR_OK)
    {
        std::ostringstream oss;

        oss << "Connect to API '" << ack_dest_url << "' for asset status update has failed (code " << rc_http_client << ").";
        message = oss.str();
        p_logger->printf(Log::Critical, " %s %s", __func__, message.c_str());

        return false;
    }
    if (!json_response.empty())
    {
        json.Parse<0>(json_response.c_str());
        if (json.HasParseError())
        {
            p_logger->printf(Log::Warning, " %s Bad responseData: %s\n", __func__, json_response.c_str());

            return false;
        }
    }

    std::string jsonStr;
    // JSON writer
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

    json.Accept(writer);
    jsonStr = buffer.GetString();
    Log::getInstance()->printf(Log::Debug, "\n %s:%d policies: %s", __func__, __LINE__, jsonStr.c_str());

    return true;
}

bool HttpAssetMessenger::submitCSRForSigning(const std::string &auth_json, const std::string &certificate_id, const std::string &generated_csr, std::string &message)
{
    Log *p_logger = Log::getInstance();

    bool result = false;

    // Base64 encode the CSR
    std::string base64_encoded_csr;
    unsigned int encoded_block_length = generated_csr.length() * 2u;
    char *encoded_block = new char[encoded_block_length];
    base64Encode((const unsigned char *)generated_csr.c_str(), generated_csr.length(), encoded_block, encoded_block_length);
    base64_encoded_csr.assign(encoded_block);
    delete[] encoded_block;
    encoded_block = nullptr;

    const std::string da_json = "{\"auth\":" + auth_json + ",\"certificateId\":\"" + certificate_id + "\",\"csr\":\"" + base64_encoded_csr + "\",\"hash\":\"base64\"}";
    p_logger->printf(Log::Debug, " %s Certificate signing JSON request: %s", __func__, da_json.c_str());

    std::string json_response;
    const std::string submit_dest_url = m_dest_url + "/certificate/sign";
    DAErrorCode rc_http_client = mp_http_client->sendRequest(DAHttp::ReqType::ePOST, submit_dest_url, json_response, da_json);
    p_logger->printf(Log::Debug, " %s sendRequest returns %d\n", __func__, rc_http_client);
    if (rc_http_client != ERR_OK)
    {
        std::ostringstream oss;
        oss << "Connect to API '" << submit_dest_url << "' for asset status update has failed (code " << rc_http_client << ").";
        message = oss.str();
        p_logger->printf(Log::Critical, " %s", message.c_str());
        return false;
    }

    rapidjson::Document json;
    if ((rc_http_client == ERR_OK) && !json_response.empty())
    {
        json.Parse<0>(json_response.c_str());

        if (json.HasParseError())
        {
            p_logger->printf(Log::Error, " %s Bad responseData: %s\n", __func__, json_response.c_str());
            return false;
        }
    }

    if (json.IsNull())
    {
        message = "Authorization failed before signing request";
        p_logger->printf(Log::Error, " %s %s", __func__, message.c_str());
        return false;
    }

    if (json.HasMember("statusCode"))
    {
        const rapidjson::Value &status_code_val = json["statusCode"];
        int status_code = status_code_val.GetInt();

        result = (status_code == 0);

        if (status_code != 0)
        {
            if (json.HasMember("message"))
            {
                const rapidjson::Value &msg_val = json["message"];
                if (msg_val.HasMember("assetType"))
                {
                    const rapidjson::Value &asset_type_val = msg_val["assetType"];
                    if (!asset_type_val.IsNull())
                    {
                        const std::string asset_type_str = utils::toLower(asset_type_val.GetString());
                        if (!asset_type_str.empty() && (asset_type_str == "csrfailed"))
                        {
                            p_logger->printf(Log::Error, " %s KeyScaler response with expected CSR contents (based on the policy): %s", __func__, asset_type_str.c_str());
                        }
                    }
                }
                if (msg_val.HasMember("errorMessage"))
                {
                    const rapidjson::Value &err_msg_val = msg_val["errorMessage"];
                    if (!err_msg_val.IsNull())
                    {
                        const std::string error_str = err_msg_val.GetString();
                        if (!error_str.empty())
                        {
                            p_logger->printf(Log::Error, " %s Failure reported from KeyScaler: %s", __func__, error_str.c_str());
                        }
                    }
                }
            }
        }
    }

    return result;
}

bool HttpAssetMessenger::fetchFile(const std::string &apiurl, const std::string &response_file_path)
{
    if (!mp_http_client)
    {
        throw std::runtime_error("Unable to fetch file:" + apiurl + " error: No DAHttpClient supplied");
    }

    Log::getInstance()->printf(Log::Debug, "Opening file: %s\n", response_file_path.c_str());

    std::ofstream ofs(response_file_path, std::ofstream::trunc);
    if (!ofs.is_open())
    {
        throw std::runtime_error("Unable to open response file:" + response_file_path);
    }

    Log::getInstance()->printf(Log::Information, "Fetching file:%s to %s\n", apiurl.c_str(), response_file_path.c_str());

    DAErrorCode rc_http_client = mp_http_client->sendRequest(DAHttp::ReqType::eGET, apiurl, &ofs);
    if (rc_http_client != ERR_OK)
    {
        ofs.close();

        std::ostringstream oss;
        oss << "Unable to fetch file:" << apiurl << " code:" << rc_http_client;
        throw std::runtime_error(oss.str());
    }
    ofs.close();

    return true;
}

bool HttpAssetMessenger::sendScriptOutput(const std::string &script_id, const std::string &device_specific_topic, const std::string &script_output)
{
    Log *p_logger = Log::getInstance();
    p_logger->printf(Log::Error, "sendScriptOutput not supported using HTTP protocol");
    return false;
}
