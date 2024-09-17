/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An function to process any assets
 */
#ifndef ASSET_MANAGER_HPP
#define ASSET_MANAGER_HPP

#include <map>
#include <memory>
#include <openssl/ssl.h>
#include <string>
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include "rapidjson/prettywriter.h" // for stringify JSON
#include "rapidjson/stringbuffer.h" // for stringify JSON
#include "account.hpp"
#include "asset_processor.hpp"
#include "rsa_utils.hpp"
#include "ssl_wrapper.hpp"

namespace Asset
{
	enum Status
	{
		IN_PROGRESS,
		FAILURE,
		SUCCESS
	};
}

class AssetManager
{
public:
	AssetManager();

    Asset::Status processAsset(std::unique_ptr<AssetProcessor> p_asset_processor, const rapidjson::Value &asset_val, const std::string &key, const std::string &iv, const std::string &key_id, unsigned int &sleep_value_from_ks);

    /**
     * @brief Calls update on all in-progress asset processors
     */
    void update();

    size_t assetsProcessingCount() const
    {
        return m_asset_processors.size();
    }

    bool isWaitingForCertificate() const
    {
        return m_waiting_for_certificate;
    }

    bool isAssetProcessing(const std::string &asset_id)
    {
        return m_asset_processors.find(asset_id) != m_asset_processors.end();
    }

private:
    std::map<const std::string, std::unique_ptr<AssetProcessor>> m_asset_processors;

    bool m_waiting_for_certificate;
};

#endif // #ifndef ASSET_MANAGER_HPP
