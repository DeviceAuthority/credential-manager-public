#if defined(WIN32)
#include "asset-win.hpp"
#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include "wincrypt.h"
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#else
#include "asset-linux.hpp"
#endif // #if defined(WIN32)
#include <functional>
#include <iomanip>
#include <memory>
#include "base64.h"
#include "async_exec_script.hpp"
#include "asset_processor.hpp"
#include "deviceauthority.hpp"
#include "event_manager.hpp"
#include "recipe_results_parser.hpp"
#include "script_asset_processor.hpp"
#include "utils.hpp"
#include "json_utils.hpp"
#include "script_utils.hpp"
#include "message_factory.hpp"
#include "utils.hpp"

const char *const BLOB_URL = "fileLink";
const char *const LOG_FILE_PATH_STR = "LOGFILEPATH";
const char *const CONFIG_FILE_PATH_STR = "CONFIGFILEPATH";
const char *const DATA_FILE_PATH_STR = "DATAFILEPATH";

ScriptAssetProcessor::ScriptAssetProcessor(const std::string &asset_id, AssetMessenger *p_asset_messenger, const RSAPtr public_key)
	: AssetProcessor(asset_id, p_asset_messenger), m_data_file_path(nullptr), m_public_key(public_key)
{
    // do nothing
}

void ScriptAssetProcessor::handleAsset(
    const rapidjson::Value &json,
    const std::string &key,
    const std::string &iv,
    const std::string &key_id,
    unsigned int &sleep_value_from_ks)
{
    EventManager::getInstance()->notifySATReceived();

    m_complete = false;
    m_success = false;
    m_error_message = "";

    m_asset_type = utils::toLower(JsonUtils::getJSONField(json, "assetType"));
    try
    {
        const std::string recipe_json_str = decrypt(utils::fromBase64(JsonUtils::getJSONField(json, "data")), key, iv);
        
        rapidjson::Document recipe_json;
        recipe_json.Parse(recipe_json_str.c_str());
        if (recipe_json.HasParseError())
        {
            throw std::runtime_error("Bad JSON for recipe:" + recipe_json_str);
        }

        const std::string device_recipe_b64 = JsonUtils::getJSONField(recipe_json, "recipe");
        const std::string device_recipe_sig_b64 = JsonUtils::getJSONField(recipe_json, "sig");

        if (!verify(digest(device_recipe_b64), utils::fromBase64(device_recipe_sig_b64)))
        {
            throw std::runtime_error("Failed to verify recipe");
        }

        const std::string blob_url = JsonUtils::getJSONField(json, BLOB_URL, "");
        if (!blob_url.empty())
        {
            m_data_file_path.reset(new std::string(tmpFilepath(utils::getFileNameFromPath(blob_url))), [this](std::string *s)
                               { removeFile(s); delete s; });
            fetchFile(blob_url, *m_data_file_path);
            setEnv(DATA_FILE_PATH_STR, *m_data_file_path);
        }
        else if (m_asset_type == "code_signing")
        {
            throw std::runtime_error("JSON is missing URL (" + std::string(BLOB_URL) + ") for signed file:");
        }

        setEnv(CONFIG_FILE_PATH_STR, config.path());

        if (config.exists(CFG_LOGFILENAME))
        {
            setEnv(LOG_FILE_PATH_STR, config.lookup(CFG_LOGFILENAME));
        }

        m_script_future.reset(new AsyncExecScript(fixLineEndings(utils::fromBase64(device_recipe_b64))));
    }
    catch (const std::exception &e)
    {
        m_error_message = e.what();
        Log::getInstance()->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
        m_success = false;
        m_complete = true;
    }
}

void ScriptAssetProcessor::onUpdate()
{
    if (!m_script_future->tryJoin())
    {
        // Thread still running
        return;
    }

    m_success = m_script_future->isSuccess();

    const std::string script_output = m_script_future->getScriptOutput();
    std::string device_log_json;
    if (m_success)
    {
        device_log_json = MessageFactory::buildScriptResultMessage(
            m_asset_type == "code_signing" ? "asset-device-data-codesigning" : "asset-device-data-logs",
            RecipeResultsParser().isCompressRequested(),
            script_output);
        Log::getInstance()->printf(Log::Information, " %s:%d Successfully processed recipe", __func__, __LINE__);
        EventManager::getInstance()->notifySATSuccess();
    }
    else
    {
        m_error_message = "Script returned failure. Script output: " + script_output;
        device_log_json = MessageFactory::buildScriptResultMessage(
            m_asset_type == "code_signing" ? "asset-device-data-codesigning" : "asset-device-data-logs",
            false,
            m_error_message);
        Log::getInstance()->printf(Log::Error, " %s:%d %s", __func__, __LINE__, m_error_message.c_str());
        EventManager::getInstance()->notifySATFailure(m_error_message);
    }

    sendReceipt(m_success, device_log_json, m_error_message);
    m_complete = true;
}

bool ScriptAssetProcessor::sendReceipt(bool is_success, const std::string &json_payload, std::string &failure_reason)
{
    const std::string json_receipt = MessageFactory::buildAcknowledgeMessage(m_asset_id, is_success, failure_reason);
    return mp_asset_messenger->acknowledgeReceipt(MessageFactory::mergeJsonObjects(json_receipt, json_payload), failure_reason);
}

const std::string ScriptAssetProcessor::tmpFilepath(const std::string &file_name) const
{
    const std::string tmp_folder = config.lookup(CFG_CERTIFICATEPATH);
    size_t pos = tmp_folder.find_last_of("/\\");
    if (pos == std::string::npos)
    {
        throw std::runtime_error("CERTIFICATEPATH not set in configuration file");
    }
    std::string path = tmp_folder.substr(0, pos + 1);
    if (file_name.empty())
    {
        path += utils::generateUUID();
    }
    else
    {
        path += file_name;
    }
    return path;
}

bool ScriptAssetProcessor::verify(const std::string &hash, const std::string &sig) const
{
    return 1 == RSA_verify(NID_sha256, (const unsigned char *)hash.c_str(), hash.size(),
                           (unsigned char *)sig.c_str(), (unsigned int)sig.size(),
                           m_public_key.get());
}

const std::string ScriptAssetProcessor::decrypt(const std::string &value, const std::string &key, const std::string &iv) const
{
    const std::string res = DeviceAuthority::getInstance()->doCipherAES(key, iv, value, CipherModeDecrypt);
    if (res.empty())
    {
        throw std::runtime_error("Unable to decrypt:" + value);
    }
    return res;
}

const std::string ScriptAssetProcessor::digest(const std::string &data) const
{
    return DeviceAuthority::getInstance()->doDigestSHA256(data);
}

void ScriptAssetProcessor::fetchFile(const std::string &apiurl, const std::string &response_file_path) const
{
    if (!apiurl.empty())
    {
        mp_asset_messenger->fetchFile(apiurl, response_file_path);
    }
}

void ScriptAssetProcessor::removeFile(const std::string *p_filepath) const
{
    if (p_filepath && !p_filepath->empty())
    {
        Log::getInstance()->printf(Log::Information, "Removing file: %s\n", p_filepath->c_str());
        std::remove(p_filepath->c_str());
    }
}
