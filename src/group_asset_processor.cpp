#include <sstream>
#include <fstream>
#include "asset_processor.hpp"
#include "deviceauthority.hpp"
#include "event_manager.hpp"
#include "group_asset_processor.hpp"
#include "json_utils.hpp"
#include "message_factory.hpp"
#include "utils.hpp"

GroupAssetProcessor::GroupAssetProcessor(const std::string &asset_id, AssetMessenger *p_asset_messenger, const std::string &metadata_filepath)
	: AssetProcessor(asset_id, p_asset_messenger), m_metadata_filepath(metadata_filepath)
{
    // do nothing
}

void GroupAssetProcessor::handleAsset(
    const rapidjson::Value &json,
    const std::string &key,
    const std::string &iv,
    const std::string &key_id,
    unsigned int &sleep_value_from_ks)
{
    EventManager::getInstance()->notifyGroupMetadataReceived();

    const rapidjson::Value &metadata_64_obj = json["metadata"];
    const std::string metadata_b64 = metadata_64_obj.GetString();
    m_success = GroupAssetProcessor::writeMetadataToFile(m_metadata_filepath, metadata_b64);

    if (!m_success)
    {
        m_error_message = "Failed to write to file " + m_metadata_filepath;
        EventManager::getInstance()->notifyGroupMetadataFailure(m_error_message);
    }
    else
    {
        EventManager::getInstance()->notifyGroupMetadataSuccess();
    }

    sendReceipt(m_success, m_error_message);
    m_complete = true;
}

void GroupAssetProcessor::onUpdate()
{

}

bool GroupAssetProcessor::sendReceipt(bool is_success, std::string &failure_reason)
{
    const std::string json_receipt = MessageFactory::buildAcknowledgeMessage(m_asset_id, is_success, failure_reason);
    return mp_asset_messenger->acknowledgeReceipt(json_receipt, failure_reason);
}

bool GroupAssetProcessor::writeMetadataToFile(const std::string &metadata_file, const std::string &metadata_b64)
{
    unsigned int cbDecodedMetadata = 0;
    std::vector<unsigned char> decoded_metadata(metadata_b64.length(), 0);

    cbDecodedMetadata = base64Decode(metadata_b64.c_str(), decoded_metadata.data(), metadata_b64.length());
    if (cbDecodedMetadata == 0)
    {
        Log::getInstance()->printf(Log::Error, "Failed to decode metadata");
        return false;
    }

    std::ofstream outfile(metadata_file.c_str(), std::ios::binary | std::ios::out);
    outfile.write((char*)decoded_metadata.data(), cbDecodedMetadata);
    outfile.close();
    if (!outfile)
    {
        Log::getInstance()->printf(Log::Error, "Failed to write data to %s", metadata_file.c_str());
        return false;
    }
    return true;
}

