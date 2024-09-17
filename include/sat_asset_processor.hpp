
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An function to process script assets received
 */
#ifndef SAT_ASSET_PROCESSOR_HPP
#define SAT_ASSET_PROCESSOR_HPP

#include <openssl/ssl.h>
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <memory>
#include <pthread.h>
#include <string>
#include "asset_processor.hpp"
#include "async_exec_script.hpp"

class SatAssetProcessor : public AssetProcessor
{
public:
    SatAssetProcessor(
        const std::string &asset_id,
        AssetMessenger *p_asset_messenger,
        const std::string &script_id,
        const std::string &script_data,
        const std::string &device_specific_topic);

    void handleAsset(
        const rapidjson::Value &json,
        const std::string &key,
        const std::string &iv,
        const std::string &key_id,
        unsigned int &sleep_value_from_ks) override;

protected:
    void onUpdate() override;

private:
    /// @brief Thread that manages the execution of the script
    std::unique_ptr<AsyncExecScript> m_script_future;

    /// @brief The script ID
    const std::string m_script_id;

    /// @brief The encrypted script data
    const std::string m_script_data;

    /// @brief Device specific topic
    const std::string m_device_specific_topic;

    /// @brief The symmetric key required to decrypt and encrypt data
    std::string m_key;

    /// @brief The IV required to decrypt and encrypt data
    std::string m_iv;

    int decryptKeyIv(const std::string &key, const std::string &iv, const std::string &data, char **out);

    std::string decryptScript(const char *key, const int key_sz, const char *iv, const int iv_sz, const std::string &data) const;

    std::string encryptScriptOutput(const char *key, const int key_sz, const char *iv, const int iv_sz, const std::string &data) const;

    std::string charPbase64(const char *data, const unsigned int data_sz) const;
};

#endif // #ifndef SAT_ASSET_PROCESSOR_HPP
