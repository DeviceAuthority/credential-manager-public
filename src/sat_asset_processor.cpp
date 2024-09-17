#if defined(WIN32)
#include "asset-win.hpp"
#else
#include "asset-linux.hpp"
#endif // #ifndef WIN32
#include <sstream>
#include "asset_processor.hpp"
#include "deviceauthority.hpp"
#include "event_manager.hpp"
#include "message_factory.hpp"
#include "sat_asset_processor.hpp"
#include "script_utils.hpp"
#include "utils.hpp"

SatAssetProcessor::SatAssetProcessor(const std::string &asset_id, AssetMessenger *p_asset_messenger, const std::string &script_id, const std::string &script_data, const std::string &device_specific_topic)
    : AssetProcessor(asset_id, p_asset_messenger), m_script_id(script_id), m_script_data(script_data), m_device_specific_topic(device_specific_topic)
{
    // do nothing
}

void SatAssetProcessor::handleAsset(
    const rapidjson::Value &json,
    const std::string &key,
    const std::string &iv,
    const std::string &key_id,
    unsigned int &sleep_value_from_ks)
{
    Log *p_logger = Log::getInstance();

    m_complete = false;
    m_success = false;

    EventManager::getInstance()->notifySATReceived();
    {
        char *out_key = nullptr;
        char *out_iv = nullptr;
        const rapidjson::Value &key_val = json["key"];
        const rapidjson::Value &iv_val = json["iv"];
        std::string enc_key = key_val.GetString();
        std::string enc_iv = iv_val.GetString();

        int key_length = decryptKeyIv(key, iv, enc_key, &out_key);
        int iv_length = decryptKeyIv(key, iv, enc_iv, &out_iv);

        m_key = std::string(out_key, key_length);
        m_iv = std::string(out_iv, iv_length);

        if (out_key)
        {
            delete[] out_key;
            out_key = nullptr;
        }
        if (out_iv)
        {
            delete[] out_iv;
            out_iv = nullptr;
        }
    }

    // Decrypt the secure asset
    const std::string script = fixLineEndings(
        decryptScript(m_key.c_str(), m_key.length(), m_iv.c_str(), m_iv.length(), m_script_data));
    m_script_future.reset(new AsyncExecScript(script));
}

void SatAssetProcessor::onUpdate()
{
    Log *p_logger = Log::getInstance();

    if (!m_script_future->tryJoin())
    {
        // Thread still running
        return;
    }

    m_success = m_script_future->isSuccess();
    if (m_success)
    {
        const std::string script_output = m_script_future->getScriptOutput();
        if (script_output.empty())
        {
            p_logger->printf(Log::Debug, "No Output for the script");
        }
        p_logger->printf(Log::Information, "execScript = %s", script_output.c_str());

        // Encrypt the script output and return to the KeyScaler
        const std::string encrypted_output_b64 = encryptScriptOutput(m_key.c_str(), m_key.length(), m_iv.c_str(), m_iv.length(), script_output);
        mp_asset_messenger->sendScriptOutput(m_script_id, m_device_specific_topic, encrypted_output_b64);

        EventManager::getInstance()->notifySATSuccess();
    }
    else
    {
        EventManager::getInstance()->notifySATFailure("SAT script failure: " + m_script_future->getScriptOutput());
    }

    m_complete = true;
}

int SatAssetProcessor::decryptKeyIv(const std::string &key, const std::string &iv, const std::string &data, char **out)
{
    std::vector<unsigned char> data_buf(data.size());
    unsigned int data_size = base64Decode(data.c_str(), &data_buf[0], data_buf.size());

    std::vector<unsigned char> key_buf(key.size());
    unsigned int key_size = base64Decode(key.c_str(), &key_buf[0], key_buf.size());

    std::vector<unsigned char> iv_buf(iv.size());
    unsigned int iv_size = base64Decode(iv.c_str(), &iv_buf[0], iv_buf.size());

    return DeviceAuthority::getInstance()->doCipherAES((const char *)&key_buf[0], key_size, (const char *)&iv_buf[0], iv_size, (const char *)&data_buf[0], data_size, CipherModeDecrypt, out);
}

std::string SatAssetProcessor::decryptScript(const char *key, const int key_size, const char *iv, const int iv_size, const std::string &data) const
{
    Log *p_logger = Log::getInstance();

    char *out = nullptr;
    std::vector<unsigned char> data_buf(data.size());
    unsigned int data_size = base64Decode(data.c_str(), &data_buf[0], data_buf.size());
    if (data_size <= 0)
    {
        p_logger->printf(Log::Error, "Failed to decode data");
    }
    else
    {
        DeviceAuthority::getInstance()->doCipherAES(key, key_size, iv, iv_size, (const char *)&data_buf[0], data_size, CipherModeDecrypt, &out);
    }

    std::string script = "";
    if (out)
    {
        script = std::string(out, data_size);
        delete[] out;
        out = nullptr;
    }
    return script;
}

std::string SatAssetProcessor::encryptScriptOutput(const char *key, const int key_size, const char *iv, const int iv_size, const std::string &data) const
{
    char *out = nullptr;
    int res = DeviceAuthority::getInstance()->doCipherAES(key, key_size, iv, iv_size, data.c_str(), data.size(), CipherModeEncrypt, &out);
    const std::string encoded_output_of_script = charPbase64(out, res);
    Log::getInstance()->printf(Log::Information, "encoded_output = %s\n", encoded_output_of_script.c_str());
    delete[] out;
    return encoded_output_of_script;
}

std::string SatAssetProcessor::charPbase64(const char *data, const unsigned int dataSize) const
{
    std::vector<char> buf(dataSize * 2, 0);
    unsigned int sz = base64Encode((unsigned char *)data, (unsigned int)dataSize, &buf[0], (unsigned int)buf.size());

    return std::string(buf.begin(), buf.begin() + sz);
}
