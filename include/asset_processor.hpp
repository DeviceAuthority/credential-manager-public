
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Base class for implementations that process received assets
 */
#ifndef ASSET_PROCESSOR_HPP
#define ASSET_PROCESSOR_HPP

#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <string>
#include "asset_messenger.hpp"

class AssetProcessor
{
public:
    AssetProcessor(const std::string &asset_id, AssetMessenger *p_asset_messenger) :
        m_asset_id(asset_id), mp_asset_messenger(p_asset_messenger), m_complete(false), m_success(false)
    {

    }

    /**
     * @brief Handle the received asset
     *
     * @param json The asset json as a RapidJson value
     * @param key The key returned from the authenticated challenge
     * @param iv The IV returned from the authenticated challenge
     * @param key_id The key ID
     * @param sleep_value_from_ks The sleep value received from KeyScaler
     * @return True if successfully processed, else false
     */
    virtual void handleAsset(
        const rapidjson::Value &json,
        const std::string &key,
        const std::string &iv,
        const std::string &key_id,
        unsigned int &sleep_value_from_ks) = 0;

    /**
     * @brief Called periodically to manage asset processing
     */
    void update()
    {
        if (m_complete)
        {
            return; // nothing to do here
        }

        onUpdate();
    }

    const std::string &getAssetId() const
    {
        return m_asset_id;
    }

    bool isComplete() const
    {
        return m_complete;
    }

    bool isSuccess() const
    {
        return m_success;
    }

    virtual bool waitForCertificate() const
    {
        return false;
    }

    virtual bool certificateReceived() const
    {
        return false;
    }

    const std::string getErrorMessage() const
    {
        return m_error_message;
    }

protected:
    /// @brief The identifier of the asset
    const std::string m_asset_id;

    /// @brief The asset messenger to allow sending responses to the SAC
    AssetMessenger *const mp_asset_messenger;

    /// @brief Flag indicating whether the asset processor has finished
    bool m_complete;

    /// @brief Flag indicating whether the asset was processed successfully
    bool m_success;

    /// @brief Storage of error message returned from the asset, when failure.
    std::string m_error_message;

    /// @brief Called periodically to manage the asset while its processing
    virtual void onUpdate() {};

};

#endif // #ifndef ASSET_PROCESSOR_HPP
