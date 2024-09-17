/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An function to process group assets received
 */
#ifndef GROUP_ASSET_PROCESSOR_HPP
#define GROUP_ASSET_PROCESSOR_HPP

#include <openssl/ssl.h>
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <string>
#include <pthread.h>
#include "asset_processor.hpp"

class GroupAssetProcessor : public AssetProcessor
{
public:
    GroupAssetProcessor(const std::string &asset_id, AssetMessenger *p_asset_messenger, const std::string &metadata_filepath);
	virtual ~GroupAssetProcessor() {};

    void handleAsset(
        const rapidjson::Value &json,
        const std::string &key,
        const std::string &iv,
        const std::string &key_id,
        unsigned int &sleep_value_from_ks) override;

    /// @brief Write a received metadata in base64 format to a decoded string stored in the file
    /// @param metadata_file The file to write the decoded metadata to
    /// @param metadata_b64 The metadata string in a base64 encoded format
    static bool writeMetadataToFile(const std::string &metadata_file, const std::string &metadata_b64);

protected:
    void onUpdate() override;

private:
    /// @brief The path to write the group metadata to
    std::string m_metadata_filepath;

    /// @brief Sends the asset receipt to the KeyScaler
    /// @param is_success True if successfully processed, else false
    /// @param failure_reason Optional string indicating why the asset failed to process
    bool sendReceipt(bool is_success, std::string &failure_reason);
};

#endif // #ifndef GROUP_ASSET_PROCESSOR_HPP
