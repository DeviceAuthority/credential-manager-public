/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An function to process script assets received
 */
#ifndef SCRIPT_ASSET_PROCESSOR_HPP
#define SCRIPT_ASSET_PROCESSOR_HPP

#include <openssl/ssl.h>
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <string>
#include <pthread.h>
#include "asset_processor.hpp"
#include "async_exec_script.hpp"
#include "rsa_utils.hpp"

class ScriptAssetProcessor : public AssetProcessor
{
public:
    ScriptAssetProcessor(const std::string &asset_id, AssetMessenger *p_asset_messenger, const RSAPtr public_key);
	virtual ~ScriptAssetProcessor() {};

    void handleAsset(
        const rapidjson::Value &json,
        const std::string &key,
        const std::string &iv,
        const std::string &key_id,
        unsigned int &sleep_value_from_ks) override;

protected:
    void onUpdate() override;

private:
    /// @brief Stores filepath of data file downloaded from cloud service - has custom deleter that removes the file when
    /// this object is destroyed
    std::shared_ptr<std::string> m_data_file_path;
    /// @brief Thread that manages the execution of the script
    std::unique_ptr<AsyncExecScript> m_script_future;
    /// @brief The asset type
    std::string m_asset_type;
    /// @brief The public key used to verify the signature of the script
    const RSAPtr m_public_key;

    /**
     * @brief Sends the asset receipt to the KeyScaler
     * @param is_success True if successfully processed, else false
     * @param json_payload Additional JSON to append to the end of the receipt
     * @param failure_reason Optional string indicating why the asset failed to process
     */
    bool sendReceipt(bool is_success, const std::string &json_payload, std::string &failure_reason);

    /**
     * @brief Generate a temporary filepath for storage of the response of a fetched file content
     * @details Uses file_name as the name if not empty, else generates a random UUID value as filename
     * @param file_name The name to use, or if empty a UUID value is generated
     * @return The full filepath (CERTIFICATE_PATH + filename)
     */
    const std::string tmpFilepath(const std::string& file_name) const;

    bool verify(const std::string &hash, const std::string &sig) const;

    const std::string decrypt(const std::string &value, const std::string &key, const std::string &iv) const;

    const std::string digest(const std::string &data) const;

    void fetchFile(const std::string &api_url, const std::string &response_file_path) const;

    void removeFile(const std::string *p_filepath) const;
};

#endif // #ifndef SCRIPT_ASSET_PROCESSOR_HPP
