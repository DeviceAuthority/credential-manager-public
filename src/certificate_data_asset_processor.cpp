
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Process certificate data assets
 */

#include "certificate_data_asset_processor.hpp"
#include "dacryptor.hpp"
#include "deviceauthority_base.hpp"
#include "deviceauthority.hpp"
#include "event_manager.hpp"
#include "message_factory.hpp"
#include "ssl_wrapper.hpp"
#include "tpm_wrapper.hpp"
#include "utils.hpp"
#include "win_cert_store_factory.hpp"

CertificateDataAssetProcessor::CertificateDataAssetProcessor(const std::string &asset_id, AssetMessenger *p_asset_messenger)
    : AssetProcessor(asset_id, p_asset_messenger)
{
	m_waiting_for_certificate = false;
}

void CertificateDataAssetProcessor::handleAsset(
    const rapidjson::Value &json,
    const std::string &key,
    const std::string &iv,
    const std::string &key_id,
    unsigned int &sleep_value_from_ks)
{
    EventManager::getInstance()->notifyCertificateDataReceived();

    Log *p_logger = Log::getInstance();

    CsrInstructions csr_info;
    m_success = handleCSRData(json, csr_info, sleep_value_from_ks);
    const std::string json_receipt = MessageFactory::buildAcknowledgeMessage(m_asset_id, m_success, m_error_message);
    mp_asset_messenger->acknowledgeReceipt(json_receipt, m_error_message);

    if (m_success)
    {
        std::string private_key, newkeyid, newkey, newiv;
        m_success = submitCertificateForSigning(csr_info, newkeyid, newkey, newiv, private_key);
        if (!m_success)
        {
            p_logger->printf(Log::Error, " %s Failed to obtain signed certificate.", __func__);
            EventManager::getInstance()->notifyCSRFailure(m_error_message);
        }
        else
        {
            m_waiting_for_certificate = true;
        }

        bool store_encrypted = csr_info.shouldStoreEncrypted();
#if defined(WIN32)
		bool private_key_stored = false;
        if (SSLWrapper::isUsingCustomStorageProvider())
        {
            SSLWrapper ssl_wrapper{};
            if (!ssl_wrapper.writePrivateKeyToStorageProvider(private_key, csr_info.getFileName(), store_encrypted))
            {
                m_error_message = "Failed to store private key using OpenSSL storage provider.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
            }
            else
            {
                EventManager::getInstance()->notifyPrivateKeyStored("", csr_info.getFileName(), "", store_encrypted);
            }
        }
        else if (store_encrypted)
        {
            WinCertStoreBase* p_win_cert_store{WinCertStoreFactory::getInstance()};
            private_key_stored = p_win_cert_store->importPrivateKey(private_key, csr_info.getCommonName());
            if (private_key_stored)
            {
                EventManager::getInstance()->notifyPrivateKeyStored(csr_info.getCommonName(), "", p_win_cert_store->getProviderName(), store_encrypted);
            }
        }
        else
        {
            std::string message;
            private_key_stored = utils::writeToFileSystem(csr_info.getFileName(), private_key, message);
            if (private_key_stored)
            {
                EventManager::getInstance()->notifyPrivateKeyStored(csr_info.getCommonName(), csr_info.getFileName(), "", store_encrypted);
            }
        }
#else
        if (SSLWrapper::isUsingCustomStorageProvider())
        {
            SSLWrapper ssl_wrapper{};
            if (!ssl_wrapper.writePrivateKeyToStorageProvider(private_key, csr_info.getFileName(), store_encrypted))
            {
                m_error_message = "Failed to store private key using OpenSSL storage provider.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
            }
            else
            {
                EventManager::getInstance()->notifyPrivateKeyStored("", csr_info.getFileName(), "", store_encrypted);
            }
        }
        else if (store_encrypted)
        {
            TpmWrapperBase *p_tpm_wrapper = TpmWrapper::getInstance();
            if (p_tpm_wrapper->initialised() && p_tpm_wrapper->isTpmAvailable())
            {
                // TPM available - let's encrypt and store the private key using the TPM SRK
                if (!utils::encryptAndStoreUsingTPM(private_key, csr_info.getFileName()))
                {
                    m_error_message = "Failed to store private key using TPM.";
                    p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                    EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
                }
                else
                {
                    EventManager::getInstance()->notifyPrivateKeyStored("", csr_info.getFileName(), "", store_encrypted);
                }
            }
            else
            {
                bool sign_apphash = false;
                if (json.HasMember("signAppHash"))
                {
                    sign_apphash = json["signAppHash"].GetBool();
                }

                // There is no TPM on the device so we will store the private key using secure soft storage
                if (!utils::encryptAndStorePK(private_key, newkey, newiv, newkeyid, m_asset_id, csr_info.getFileName(), true, sign_apphash))
                {
                    m_error_message = "Failed to store private key.";
                    p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                    EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
                }
                else
                {
                    EventManager::getInstance()->notifyPrivateKeyStored("", csr_info.getFileName(), "", store_encrypted);
                }
            }
        }
        else
        {
            std::string message;
            if (!utils::writeToFileSystem(csr_info.getFileName(), private_key, message))
            {
                m_error_message = "Failed to store private key.";
                p_logger->printf(Log::Error, " %s %s Message: %s", __func__, m_error_message.c_str(), message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
            }
            else
            {
                EventManager::getInstance()->notifyPrivateKeyStored("", csr_info.getFileName(), "", store_encrypted);
            }
        }
#endif // #if defined(WIN32)
    }

    m_complete = true;
}

void CertificateDataAssetProcessor::onUpdate()
{

}

/* Handles CSR generation instruction coming from DAE*/
bool CertificateDataAssetProcessor::handleCSRData(const rapidjson::Value &json, CsrInstructions &csr_info, unsigned int &sleep_value_from_ks)
{
    bool store_encrypted = false;
    bool is_ca = false;
    Log *p_logger = Log::getInstance();

    p_logger->printf(Log::Debug, " %s:%d ", __func__, __LINE__);

    std::string json_str;
    // JSON writer
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

    json.Accept(writer);
    json_str = buffer.GetString();
    p_logger->printf(Log::Debug, "\n %s:%d input: %s", __func__, __LINE__, json_str.c_str());
    // store_encrypted (mandatory)
    if (!json.IsNull() && json.HasMember("storeEncrypted"))
    {
        const rapidjson::Value &store_encrypted_val = json["storeEncrypted"];

        store_encrypted = store_encrypted_val.GetBool();
    }
    else
    {
        m_error_message = "No store encrypted flag specified (was expected).";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

        return false;
    }

    std::string file_path;
    std::string common_name;
    std::string certificate_id;
    std::string asset_id;
    std::string pk_file_name;

    // CA
    if (json.HasMember("ca"))
    {
        const rapidjson::Value &ca_val = json["ca"];
        is_ca = ca_val.GetBool();
    }
    // auto_rotate
    if (json.HasMember("autoRotate"))
    {
        const rapidjson::Value &auto_rotate_val = json["autoRotate"];
        bool auto_rotate = auto_rotate_val.GetBool();

        if (auto_rotate && json.HasMember("pollingRate"))
        {
            const rapidjson::Value &polling_rate_val = json["pollingRate"];

            sleep_value_from_ks = polling_rate_val.GetInt();
            p_logger->printf(Log::Debug, " %s pollingRate: %d", __func__, sleep_value_from_ks);
        }
    }
    // file_path (mandatory)
    if (json.HasMember("filePath"))
    {
        const rapidjson::Value &file_path_val = json["filePath"];

        if (!file_path_val.IsNull())
        {
            file_path = file_path_val.GetString();
            p_logger->printf(Log::Debug, " %s filePath: %s", __func__, file_path.c_str());
        }
    }
    if (file_path.empty())
    {
        m_error_message = "No file_path found in the CSR generation instruction.";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

        return false;
    }
#ifdef WIN32 // if storing encrypted on windows we don't use file storage so path is irrelevant
    if (!store_encrypted)
    {
#endif
        if (!utils::keyPathExists(file_path))
        {
            p_logger->printf(Log::Information, " %s %s file or directory not found", __func__, file_path.c_str());
            p_logger->printf(Log::Information, " %s Creating %s directory", __func__, file_path.c_str());
            if (!utils::createFolder(file_path))
            {
                m_error_message = "Fail to create certificate storage path " + file_path + "";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                return false;
            }
        }
#ifdef WIN32
    }
#endif


    // commonName (mandatory)
    if (json.HasMember("commonName"))
    {
        const rapidjson::Value &common_name_val = json["commonName"];

        if (!common_name_val.IsNull())
        {
            common_name = common_name_val.GetString();
        }
    }
    if (common_name.empty())
    {
        m_error_message = "No commonName found in the CSR generation instruction.";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

        return false;
    }
    // certificateId (mandatory)
    if (json.HasMember("certificateId"))
    {
        const rapidjson::Value &certificate_id_val = json["certificateId"];

        if (!certificate_id_val.IsNull())
        {
            certificate_id = certificate_id_val.GetString();
        }
    }
    if (certificate_id.empty())
    {
        m_error_message = "No certificateId found in the CSR generation instruction.";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

        return false;
    }
    // assetId (mandatory)
    if (json.HasMember("assetId"))
    {
        const rapidjson::Value &asset_id_val = json["assetId"];

        if (!asset_id_val.IsNull())
        {
            asset_id = asset_id_val.GetString();
        }
    }
    if (asset_id.empty())
    {
        m_error_message = "No assetId found in the CSR generation instruction.";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

        return false;
    }
    if (store_encrypted && !SSLWrapper::isUsingCustomStorageProvider())
    {
        utils::generateKeyPath(file_path, "private_inter.pem", pk_file_name);
    }
    else
    {
        std::string cert_name;
        utils::getPKAndCertName(pk_file_name, cert_name, file_path);
    }
    csr_info.setCSRInfo(certificate_id, asset_id, common_name, pk_file_name, store_encrypted, is_ca);

    return true;
}

bool CertificateDataAssetProcessor::submitCertificateForSigning(const CsrInstructions &csr_info, std::string &newkeyid, std::string &newkey, std::string &newiv, std::string &pk_output)
{
    Log *p_logger = Log::getInstance();

    std::string da_json;
    if (!mp_asset_messenger->identifyAndAuthorise(da_json, newkeyid, newkey, newiv, m_error_message))
    {
        return false;
    }

    std::string generated_csr;
    SSLWrapper ssl_wrapper;

    bool success = ssl_wrapper.generateCSR(csr_info, newkey, newiv, newkeyid, generated_csr, pk_output);
    if (!success)
    {
        m_error_message = "Failed to generate CSR.";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
        EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);

        return false;
    }
    p_logger->printf(Log::Debug, " %s generated CSR: %s", __func__, generated_csr.c_str());

    EventManager::getInstance()->notifyPrivateKeyCreated();
    EventManager::getInstance()->notifyCSRCreated();

    success = mp_asset_messenger->submitCSRForSigning(da_json, csr_info.getCertificateId(), generated_csr, m_error_message);
    if (!success)
    {
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
        EventManager::getInstance()->notifyCSRFailure(m_error_message.c_str());

        return false;
    }
    EventManager::getInstance()->notifyCSRDelivered();
    return true;
}
