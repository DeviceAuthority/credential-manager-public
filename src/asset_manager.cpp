/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An function to process any assets (only certificates at the moment)
 */
#if defined(WIN32)
#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
//#include <openssl/applink.c>
#include <openssl/ssl.h>
#else
#include <pwd.h>
#endif // #if defined(WIN32)
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <memory>
#include <sstream>
#include <fstream>
#include <limits>
#include <iomanip>
#include <functional>
#include <list>

#include "account.hpp"
#include "asset_manager.hpp"
#include "base64.h"
#include "configuration.hpp"
#include "constants.hpp"
#include "deviceauthority.hpp"
#include "json_utils.hpp"
#include "log.hpp"
#include "message_factory.hpp"
#include "sat_asset_processor.hpp"
#include "ssl_wrapper.hpp"
#include "utils.hpp"

#ifndef DEBUG_PRINT
#define DEBUG_PRINT 0
#endif // #ifndef DEBUG_PRINT

AssetManager::AssetManager()
{
	m_waiting_for_certificate = false;
}

Asset::Status AssetManager::processAsset(std::unique_ptr<AssetProcessor> p_asset_processor, const rapidjson::Value &asset_val, const std::string &key, const std::string &iv, const std::string &key_id, unsigned int &sleep_period_from_ks)
{
    Log *p_logger = Log::getInstance();
    
    Asset::Status asset_status = Asset::FAILURE;

    p_asset_processor->handleAsset(asset_val, key, iv, key_id, sleep_period_from_ks);
    if (!(*p_asset_processor).isComplete())
    {
        asset_status = Asset::IN_PROGRESS;
        m_asset_processors.emplace(std::make_pair(p_asset_processor->getAssetId(), std::move(p_asset_processor)));
    }
    else
    {
        if ((*p_asset_processor).isSuccess())
        {
            asset_status = Asset::SUCCESS;

            if ((*p_asset_processor).waitForCertificate())
            {
                m_waiting_for_certificate = true;
            }
        }

        if ((*p_asset_processor).certificateReceived())
        {
            m_waiting_for_certificate = false;
        }
    }

    return asset_status;
}

void AssetManager::update()
{
    if (m_asset_processors.empty())
    {
        return;
    }

    Log::getInstance()->printf(Log::Debug, "%s Processing %d assets...", __FILE__, m_asset_processors.size());

    std::list<std::map<const std::string, std::unique_ptr<AssetProcessor>>::const_iterator> processors_to_remove;
    for (auto processor = m_asset_processors.begin(); processor != m_asset_processors.end(); ++processor)
    {
        auto asset_processor = processor->second.get();
        asset_processor->update();
        if (asset_processor->isComplete())
        {
            Log::getInstance()->printf(Log::Debug, "%s asset completed", __FILE__);
            processors_to_remove.emplace_back(processor);
        }
        else
        {
            Log::getInstance()->printf(Log::Debug, "%s asset in-progress", __FILE__);
        }
    }

    for (auto processorIter = processors_to_remove.cbegin(); processorIter != processors_to_remove.cend(); processorIter++)
    {
        m_asset_processors.erase((*processorIter));
    }
    processors_to_remove.clear();
}
