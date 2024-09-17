
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Process certificate assets
 */
#ifndef CERTIFICATE_ASSET_PROCESSOR_HPP
#define CERTIFICATE_ASSET_PROCESSOR_HPP

#include <openssl/ssl.h>
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <string>
#include "account.hpp"
#include "asset_processor.hpp"

class CertificateAssetProcessor : public AssetProcessor
{
public:
    CertificateAssetProcessor(const std::string &asset_id, AssetMessenger *p_asset_messenger);
    virtual ~CertificateAssetProcessor() {};

    void handleAsset(
        const rapidjson::Value &json,
        const std::string &key,
        const std::string &iv,
        const std::string &key_id,
        unsigned int &sleep_value_from_ks) override;

    bool certificateReceived() const override
    {
        return true;
    }

protected:
    void onUpdate() override;

private:
    bool handleCertificate(const rapidjson::Value &json, const std::string &key, const std::string &iv, const std::string &key_id, unsigned int &sleep_value_from_ks);
    bool writeKeyAndCertificate(const std::string &pk_name, const std::string &private_key, const std::string &cert_name, const std::string &certificate, bool store_encrypted);
    bool decryptData(const std::string &key, const std::string &iv, const std::string &encrypted_data, std::string &decrypted_data) const;
};

#endif // #ifndef CERTIFICATE_ASSET_PROCESSOR_HPP
