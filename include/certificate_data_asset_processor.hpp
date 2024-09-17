
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Process certificatedata assets
 */
#ifndef CERTIFICATE_DATA_ASSET_PROCESSOR_HPP
#define CERTIFICATE_DATA_ASSET_PROCESSOR_HPP

#include <openssl/ssl.h>
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <string>
#include "account.hpp"
#include "asset_processor.hpp"
#include "ssl_wrapper.hpp"

class CertificateDataAssetProcessor : public AssetProcessor
{
public:
    CertificateDataAssetProcessor(const std::string &asset_id, AssetMessenger *p_asset_messenger);
    virtual ~CertificateDataAssetProcessor() {};

    void handleAsset(
        const rapidjson::Value &json,
        const std::string &key,
        const std::string &iv,
        const std::string &key_id,
        unsigned int &sleep_value_from_ks) override;

        bool waitForCertificate() const override
        {
            return m_waiting_for_certificate;
        }

protected:
    void onUpdate() override;

private:
    bool m_waiting_for_certificate;

    bool handleCSRData(const rapidjson::Value &json, CsrInstructions &csr_info, unsigned int &sleep_value_from_ks);

    bool submitCertificateForSigning(const CsrInstructions &csr_info, std::string &newkeyid, std::string &newkey, std::string &newiv, std::string &pk_output);
};

#endif // #ifndef CERTIFICATE_DATA_ASSET_PROCESSOR_HPP
