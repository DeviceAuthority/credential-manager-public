
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Process apm assets
 */
#ifndef APM_ASSET_PROCESSOR_HPP
#define APM_ASSET_PROCESSOR_HPP

#include <openssl/ssl.h>
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <string>
#include "account.hpp"
#include "asset_processor.hpp"
#include "asset_messenger.hpp"

class ApmAssetProcessor : public AssetProcessor
{
public:
    ApmAssetProcessor(const std::string &assetId, AssetMessenger* p_asset_messenger);

    void handleAsset(
        const rapidjson::Value &json,
        const std::string &key,
        const std::string &iv,
        const std::string &keyId,
        unsigned int &sleep_value_from_ks) override;

protected:
    void onUpdate() override;

private:
    /**
     * Get for all users:name,salt,hash from JSON and stuff into accounts vector.
     * Validate the received JSON. If any mandatory component is missing populate the result member with "FAILED"
     * For accounts with result=SUCCESS try changing password and update the results
     *
     * @return : true if password update for all accounts was successful false otherwise.
     *         : In case of failure message sting is populated with the account name and result of failure (JSON)
     */
    bool processPasswordManagementRequest(const rapidjson::Value &json, const std::string &key, const std::string &iv, std::string &message, unsigned int &sleep_value_from_ks);

    /**
     * 1. Check account exists on local device by name
     * 2. Generate account password
     *    hash(crypto key + account salt) = 50aabe4c64c17755125e939d2c9bd862f048bb0
     * 3. Generate validation hash
     *    hash(new password + account name) = adeb2ca63c690d98ff8ae0e95531cb8a0f34b80d
     * 4. Compare generated validation hash with one sent in policy and set account password
     */
    bool updatePasswords(std::vector<account *> &vectAccount, const std::string &key, std::string &message);

    /* Updates the specified account object with results */
    void updateFailure(account *accountObj, const std::string &result);
};

#endif // #ifndef APM_ASSET_PROCESSOR_HPP
