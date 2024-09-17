/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Factory that generates JSON messages
 */

#include <functional>
#include <sstream>
#include <string>
#include "json_utils.hpp"
#include "message_factory.hpp"
#include "utils.hpp"

const std::string MessageFactory::buildAcknowledgeMessage(const std::string &asset_id, bool success, const std::string &failure_reason)
{
    rapidjson::Document root_document;
    root_document.SetObject();
    rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

    rapidjson::Value auth_obj(rapidjson::kObjectType);
    if (!asset_id.empty())
    {
        auth_obj.AddMember("assetId", rapidjson::Value(asset_id.c_str(), allocator).Move(), allocator);
        auth_obj.AddMember("status", success, allocator);
        auth_obj.AddMember("failureReason", rapidjson::StringRef(failure_reason.c_str()), allocator);
    }

    root_document.AddMember("assetDeliveryStatus", auth_obj, allocator);

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    root_document.Accept(writer);

    return std::string(strbuf.GetString());
}

const std::string MessageFactory::buildDFactorAuthenticationMessage(
    const std::string &device_key,
    bool is_edge,
    const std::string &user_agent,
    const std::string &user_id,
    const std::string &key_id,
    const std::string &app_hash,
    const std::string &asset_id)
{
    if (device_key.empty())
    {
        return "";
    }

    rapidjson::Document root_document;
    root_document.SetObject();
    rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

    if (is_edge)
    {
        root_document.AddMember("userAgent", rapidjson::StringRef(user_agent.c_str()), allocator);
    }
    if (!user_id.empty())
    {
        root_document.AddMember("userId", rapidjson::StringRef(user_id.c_str()), allocator);
    }
    if (!key_id.empty())
    {
        root_document.AddMember("keyId", rapidjson::StringRef(key_id.c_str()), allocator);
    }
    if (app_hash.size())
    {
        root_document.AddMember("appHash", rapidjson::StringRef(app_hash.c_str()), allocator);
    }
    if (asset_id.size())
    {
        root_document.AddMember("assetId", rapidjson::StringRef(asset_id.c_str()), allocator);
    }
    root_document.AddMember("deviceKey", rapidjson::StringRef(device_key.c_str()), allocator);

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    root_document.Accept(writer);

    return std::string(strbuf.GetString());
}

const std::string MessageFactory::buildAuthenticationMessage(const std::string &dfactor_auth_json, const std::string &ack_json)
{
    rapidjson::Document root_document;
    root_document.SetObject();
    rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

    rapidjson::Document auth_doc;
    root_document.AddMember("dFactorAuthentication", auth_doc.Parse<0>(dfactor_auth_json.c_str()), allocator);

    rapidjson::Document asset_doc;
    asset_doc.Parse<0>(ack_json.c_str());

    mergeDocuments(root_document, asset_doc, allocator);

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    root_document.Accept(writer);

    return std::string(strbuf.GetString());
}

const std::string MessageFactory::buildScriptResultMessage(const std::string &logs_type, bool compress, const std::string &script_output)
{
    rapidjson::Document root_document;
    root_document.SetObject();
    rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

    // Add sub-object containing base64 encoded data
    std::string data_b64;
    {
        rapidjson::Document data;
        data.SetObject();
        data.AddMember("device_info", "", allocator);

        const std::string script_output_json = buildScriptOutputJson(script_output);

        rapidjson::Document device_logs;
        data.AddMember("device_logs", device_logs.Parse<0>(script_output_json.c_str()), allocator);

        rapidjson::StringBuffer strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
        data.Accept(writer);

        data_b64 = utils::toBase64(compress ? utils::deflate(strbuf.GetString()) : strbuf.GetString());
    }

    rapidjson::Value device_logs(rapidjson::kObjectType);
    device_logs.AddMember("type", rapidjson::StringRef(logs_type.c_str()), allocator);
    device_logs.AddMember("compression", rapidjson::StringRef(compress ? "zlib" : "none"), allocator);
    device_logs.AddMember("data", rapidjson::StringRef(data_b64.c_str()), allocator);
    root_document.AddMember("device_logs", device_logs, allocator);

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    root_document.Accept(writer);

    return std::string(strbuf.GetString());
}

const std::string MessageFactory::buildScriptOutputJson(const std::string &script_output)
{
    rapidjson::Document root_document;
    root_document.SetArray();
    rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

    std::stringstream in(script_output, std::ios_base::in);
    std::string line;
    for (unsigned int count = 1; std::getline(in, line); ++count)
    {
        rapidjson::Value v(rapidjson::kObjectType);
        v.AddMember("line", count, allocator);
        v.AddMember("description", rapidjson::Value(line.c_str(), allocator).Move(), allocator);
        root_document.PushBack(v.Move(), allocator);
    }

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    root_document.Accept(writer);

    return std::string(strbuf.GetString());
}

const std::string MessageFactory::buildScriptOutputMessage(const std::string &script_id, const std::string &script_output)
{
    rapidjson::Document root_document;
    root_document.SetObject();
    rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

    root_document.AddMember("id", rapidjson::StringRef(script_id.c_str()), allocator);
    root_document.AddMember("data", rapidjson::StringRef(script_output.c_str()), allocator);

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    root_document.Accept(writer);

    return std::string(strbuf.GetString());
}

const std::string MessageFactory::buildPasswordChangeStatusMessage(const std::string &asset_id, bool success, const std::string &status)
{
    rapidjson::Document root_document;
    root_document.SetObject();
    rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

    rapidjson::Value password_change_status(rapidjson::kObjectType);
    if (!asset_id.empty())
    {
        password_change_status.AddMember("assetId", rapidjson::Value(asset_id.c_str(), allocator).Move(), allocator);
        password_change_status.AddMember("status", success, allocator);

        rapidjson::Document status_document;
        status_document.Parse<0>(status.c_str());
        if (!status_document.HasParseError())
        {
            // Status is a JSON object, add it here.
            password_change_status.AddMember("apmStatus", rapidjson::Value(status_document.Move(), allocator).Move(), allocator);
        }
        else
        {
            // Status is not a JSON object so just add the raw string
            password_change_status.AddMember("apmStatus", rapidjson::StringRef(status.c_str()), allocator);
        }
    }

    root_document.AddMember("passwordChangeStatus", password_change_status, allocator);

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    root_document.Accept(writer);

    return std::string(strbuf.GetString());
}

const std::string MessageFactory::buildApmPasswordsMessage(const std::vector<account*> &accounts)
{
    rapidjson::Document root_document;
    root_document.SetObject();
    rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

    rapidjson::Value accounts_val(rapidjson::kArrayType);
    for (std::vector<account *>::const_iterator itr = accounts.cbegin(); itr != accounts.cend(); itr++)
    {
        account *p_account = *(itr);
        const std::string name = p_account->getName();
        const std::string result = p_account->getResult();
        const std::string reason = p_account->getReason();

        rapidjson::Value account_val(rapidjson::kObjectType);
        account_val.AddMember("account", rapidjson::Value(name.c_str(), allocator).Move(), allocator);
        account_val.AddMember("result", rapidjson::Value(result.c_str(), allocator).Move(), allocator);
        account_val.AddMember("reason",  rapidjson::Value(reason.c_str(), allocator).Move(), allocator);
        accounts_val.PushBack(account_val.Move(), allocator);
    }

    root_document.AddMember("apmPasswords", accounts_val, allocator);

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    root_document.Accept(writer);

    return std::string(strbuf.GetString());
}

const std::string MessageFactory::mergeJsonObjects(const std::string &json_a, const std::string &json_b)
{
    rapidjson::Document root_document;
    root_document.SetObject();
    rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

    root_document.Parse<0>(json_a.c_str());
    rapidjson::Document document_b;
    document_b.Parse<0>(json_b.c_str());

    mergeDocuments(root_document, document_b, allocator);

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    root_document.Accept(writer);

    return std::string(strbuf.GetString());
}

const std::string MessageFactory::generateMqttPayload(
        const std::string &op,
        const std::string &udi,
        const std::string &user_agent,
        const std::string &user_id,
        const std::string &challenge_type,
        const char *deviceKey,
        const char *data,
        const char *assetId,
        const char *csr,
        const char *keyId)
{
    std::stringstream ss;
    // Begin JSON message
    std::string payload = "{";
    std::string reqIdKey = "\"reqId\":\"" + utils::generateUUID() + "\",";
#ifdef WIN32
    std::time_t t = std::time(0);
#else
    time_t t = time(0);
#endif // #ifdef WIN32

    ss << t;

    std::string tsKey = "\"ts\":" + ss.str() + ",";
    std::string udiKey = "\"device\":\"" + udi + "\",";
    std::string opKey = "\"op\":\"" + op + "\",";
    std::string userAgentKey = "\"userAgent\":\"" + user_agent + "\",";
    std::string userIdKey = "\"userId\":\"" + user_id + "\",";
    // Begin "req" key
    std::string reqKey = "\"req\":{";

    payload += reqIdKey + tsKey + udiKey + opKey + reqKey;

    std::string policyId = "";
    std::string keyID = "";
    std::string type = "\"type\":";

    if (op.compare("ch") == 0)
    {
        type = type + "\"challenge\",";
        payload += type;
        payload += userAgentKey;

        std::string chTypeKey = "\"challengeType\":";

        chTypeKey += "\"" + challenge_type + "\",";
        payload += chTypeKey;
        payload += userIdKey;
        // Request challenge with generic IdKey or DDK
        payload += "\"deviceKey\":\"";
        payload += (utils::isNull(deviceKey)? "" : deviceKey);
        payload += "\",";
        if (challenge_type.compare("auth") == 0)
        {
            // Request challenge with TID
            payload += "\"tid\":\"";
            payload += (utils::isNull(data)? "" : data);
            payload += "\",";
        }

        std::string encryptPolicyIdKey = "\"encryptPolicyId\":\"" + policyId + "\"";

        payload += encryptPolicyIdKey;
    }
    else if (op.compare("register") == 0)
    {
        type = type + "\"register\",";
        payload += type;
        payload += userAgentKey;
        payload += userIdKey;
        payload += "\"deviceKey\":\"";
        payload += (utils::isNull(deviceKey)? "" : deviceKey);
        payload += "\",";
        payload += "\"displayName\":\"" + udi + "\"";
    }
    else if (op.compare("auth") == 0)
    {
        if (challenge_type.compare("auth-get-key") == 0)
        {
            // Auth & Get key
            type = type + "\"auth-get-key\",";
        }
        else
        {
            // Auth Basic
            type = type + "\"auth\",";
        }
        payload += type;
        payload += userAgentKey;
        payload += userIdKey;
        payload += "\"deviceKey\":\"";
        payload += (utils::isNull(deviceKey)? "" : deviceKey);
        payload += "\"";
        if (challenge_type == "auth-get-key")
        {
            payload += ",";
            payload += "\"keyId\":\"";
            payload += (utils::isEmpty(keyId)? "" : keyId);
            payload += "\"";
        }
    }
    else if (op.compare("asset-status") == 0)
    {
        type = type + "\"asset-status\",";
        payload += type;

        std::string dfactor_auth = "\"dFactorAuthentication\":{";

        payload += dfactor_auth;
        payload += userIdKey;
        payload += "\"deviceKey\":\"";
        payload += (utils::isNull(deviceKey)? "" : deviceKey);
        payload += "\",";
        payload += "\"domainPublicIP\":\"\",";
        payload += userAgentKey;
        payload += "},";
        payload += data;
    }
    else if (op.compare("device-csr") == 0)
    {
        type = type + "\"csr\",";
        payload += type;

        std::string dfactor_auth = "\"dFactorAuthentication\":{";

        payload += dfactor_auth;
        payload += userIdKey;
        payload += "\"deviceKey\":\"";
        payload += (utils::isNull(deviceKey)? "" : deviceKey);
        payload += "\",";
        payload += "\"domainPublicIP\":\"\",";
        payload += userAgentKey;
        payload += "},";
        // End of dFactorAuthentication
        payload += "\"certificateId\":\"";
        payload.append(assetId);
        payload += "\",";
        payload += "\"csr\":\"";
        payload.append(csr);
        payload += "\"";
    }
    payload += "},";
    // End "req" key
    payload += "\"tenant\":\"tenant\"";
    payload += "}";

    return payload;
}

void MessageFactory::mergeDocuments(rapidjson::Value &target, rapidjson::Value &source, rapidjson::Value::AllocatorType &allocator)
{
    assert(target.IsObject());
    assert(source.IsObject());
    for (auto itr = source.MemberBegin(); itr != source.MemberEnd(); ++itr)
    {
        target.AddMember(itr->name, itr->value, allocator);
    }
}
