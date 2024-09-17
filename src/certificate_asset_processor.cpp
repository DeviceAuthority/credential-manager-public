
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Process certificate assets
 */
#if defined(WIN32)
#include <Windows.h>
#endif //WIN32

#include "certificate_asset_processor.hpp"
#include "dacryptor.hpp"
#include "event_manager.hpp"
#include "message_factory.hpp"
#include "utils.hpp"
#include "tpm_wrapper.hpp"
#include "win_cert_store_factory.hpp"
#include "ssl_wrapper.hpp"

CertificateAssetProcessor::CertificateAssetProcessor(const std::string &asset_id, AssetMessenger *p_asset_messenger)
    : AssetProcessor(asset_id, p_asset_messenger)
{
    // do nothing
}

void CertificateAssetProcessor::handleAsset(
    const rapidjson::Value &json,
    const std::string &key,
    const std::string &iv,
    const std::string &key_id,
    unsigned int &sleep_value_from_ks)
{
    m_success = handleCertificate(json, key, iv, key_id, sleep_value_from_ks);
    const std::string json_receipt = MessageFactory::buildAcknowledgeMessage(m_asset_id, m_success, m_error_message);
    mp_asset_messenger->acknowledgeReceipt(json_receipt, m_error_message);

    m_complete = true;
}

void CertificateAssetProcessor::onUpdate()
{

}

#ifndef WIN32
bool CertificateAssetProcessor::handleCertificate(const rapidjson::Value &json, const std::string &key, const std::string &iv, const std::string &key_id, unsigned int &sleep_value_from_ks)
{
    Log *p_logger = Log::getInstance();

    std::string file_path;
    if (!json.IsNull() && json.HasMember("filePath"))
    {
        const rapidjson::Value &filePathVal = json["filePath"];

        if (!filePathVal.IsNull())
        {
            file_path = filePathVal.GetString();
        }
    }
    if (file_path.empty())
    {
        m_error_message = "No file path specified (was expected).";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

        return false;
    }

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

    std::string pk_path;
    std::string cert_path;
    utils::getPKAndCertName(pk_path, cert_path, file_path);
    p_logger->printf(Log::Debug, " %s:%d pk_name: %s, cert_name: %s", __func__, __LINE__, pk_path.c_str(), cert_path.c_str());

    bool store_encrypted = false;
    if (json.HasMember("storeEncrypted"))
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

    std::string certificate;
    if (json.HasMember("certificate"))
    {
        const rapidjson::Value &certificate_val = json["certificate"];
        if (!certificate_val.IsNull())
        {
            certificate = certificate_val.GetString();
        }
    }

    if (certificate.empty())
    {
        m_error_message = "No certificate specified (was expected).";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
        EventManager::getInstance()->notifyCertificateFailure(m_error_message);
        return false;
    }
    EventManager::getInstance()->notifyCertificateReceived();

    std::string key_id_str;
    if (json.HasMember("keyId"))
    {
        const rapidjson::Value &key_id_val = json["keyId"];

        if (!key_id_val.IsNull())
        {
            key_id_str = key_id_val.GetString();
        }
    }

    // There should be a privateKey element in the JSON if CSR is DAE generated.
    std::string private_key;
    if (json.HasMember("privateKey"))
    {
        const rapidjson::Value &private_key_val = json["privateKey"];

        if (!private_key_val.IsNull())
        {
            private_key = private_key_val.GetString();
        }
    }

    if (!private_key.empty())
    {
        p_logger->printf(Log::Debug, " %s DAE generated CSR and private key", __func__);
        EventManager::getInstance()->notifyPrivateKeyReceived();
    }

    // Must use storage provider. We don't do anything with encrypting as the provider must manage this
    if (SSLWrapper::isUsingCustomStorageProvider())
    {
        if (!private_key.empty())
        {
            if (!decryptData(key, iv, private_key, private_key))
            {
                m_error_message = "Unable to decrypt private key.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
                return false;
            }
        }

        if (!decryptData(key, iv, certificate, certificate))
        {
            m_error_message = "Unable to decrypt certificate.";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyCertificateFailure(m_error_message);
            return false;
        }

        SSLWrapper ssl_wrapper{};
        if (!private_key.empty())
        {
            if (!ssl_wrapper.writePrivateKeyToStorageProvider(private_key, pk_path, store_encrypted))
            {
                m_error_message = "Failed to store private key using OpenSSL storage provider.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
                return false;
            }
            EventManager::getInstance()->notifyPrivateKeyStored("", pk_path, "", store_encrypted);
        }

        if (!ssl_wrapper.writeCertificateToStorageProvider(certificate, cert_path, store_encrypted))
        {
            m_error_message = "Failed to store certificate using OpenSSL storage provider.";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyCertificateFailure(m_error_message);
            return false;
        }
        EventManager::getInstance()->notifyCertificateStored("", cert_path, "", store_encrypted);

        return true;
    }

    if (!private_key.empty()) // DAE generated CSR and private key
    {
        // Decrypt certificates that need to be stored in an unencrypted state.
        if (!store_encrypted)
        {
            if (!decryptData(key, iv, certificate, certificate))
            {
                m_error_message = "Unable to decrypt certificate.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyCertificateFailure(m_error_message);
                return false;
            }

            if (!decryptData(key, iv, private_key, private_key))
            {
                m_error_message = "Unable to decrypt private key.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
                return false;
            }

            return writeKeyAndCertificate(pk_path, private_key, cert_path, certificate, store_encrypted);
        }

        // Try to store the private key in {"key-id":"XX", "ciphertext":"YYY"} format
        if (key_id_str.empty())
        {
            m_error_message = "No KeyId was specified in the KeyScaler response (was expected).";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
            return false;
        }

        auto p_tpm_wrapper = TpmWrapper::getInstance();
        if (p_tpm_wrapper->initialised() && p_tpm_wrapper->isTpmAvailable())
        {
            if (!decryptData(key, iv, certificate, certificate))
            {
                m_error_message = "Unable to decrypt certificate.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyCertificateFailure(m_error_message);
                return false;
            }

            if (!decryptData(key, iv, private_key, private_key))
            {
                m_error_message = "Unable to decrypt private key.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
                return false;
            }

            if (!utils::encryptAndStoreUsingTPM(private_key, pk_path))
            {
                m_error_message = "Failed to encrypt and store private key on certificate receipt.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
                return false;
            }
            EventManager::getInstance()->notifyPrivateKeyStored("", pk_path, "", store_encrypted);

            if (!utils::encryptAndStoreUsingTPM(certificate, cert_path))
            {
                m_error_message = "Failed to encrypt and store certificate on certificate receipt.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyCertificateFailure(m_error_message);
                return false;
            }
            EventManager::getInstance()->notifyCertificateStored("", cert_path, "", store_encrypted);
            return true;
        }

        bool sign_apphash = false;
        if (json.HasMember("signAppHash"))
        {
            sign_apphash = json["signAppHash"].GetBool();
        }

        std::string private_key_json;
        utils::createJsonEncryptionBlock(key_id, m_asset_id, private_key, private_key_json, false, sign_apphash);
        private_key = private_key_json;

        std::string certificate_json;
        utils::createJsonEncryptionBlock(key_id, m_asset_id, certificate, certificate_json, false, sign_apphash);
        certificate = certificate_json;

        return writeKeyAndCertificate(pk_path, private_key, cert_path, certificate, store_encrypted);
    }

    // Private Key resides on the device in encrypted or unencrypted form
    if (store_encrypted)
    {
        std::string pk;
        std::string pk_file_name;
        const std::string inter("private_inter.pem");
        utils::generateKeyPath(file_path, inter, pk_file_name);
        p_logger->printf(Log::Debug, " %s Decrypt the private key...preparing to reencrypt with new Key & IV", __func__);

        auto p_tpm_wrapper = TpmWrapper::getInstance();
        if (p_tpm_wrapper->initialised() && p_tpm_wrapper->isTpmAvailable())
        {
            if (!utils::decryptJsonBlockFile(pk, pk_file_name))
            {
                m_error_message = "Failed to decrypt with key from TPM.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
                return false;
            }

            if (!decryptData(key, iv, certificate, certificate))
            {
                m_error_message = "Unable to decrypt certificate.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyCertificateFailure(m_error_message);
                return false;
            }

            if (!utils::encryptAndStoreUsingTPM(pk, pk_path))
            {
                m_error_message = "Failed to encrypt and store private key on certificate receipt.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
                return false;
            }
            EventManager::getInstance()->notifyPrivateKeyStored("", pk_path, "", store_encrypted);

            if (!utils::encryptAndStoreUsingTPM(certificate, cert_path))
            {
                m_error_message = "Failed to encrypt and store certificate on certificate receipt.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyCertificateFailure(m_error_message);
                return false;
            }
            EventManager::getInstance()->notifyCertificateStored("", cert_path, "", store_encrypted);

            if (!pk_file_name.empty() && (remove(pk_file_name.c_str()) != 0))
            {
                m_error_message = "Failed to delete intermediate private key file";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            }

            return true;
        }

        std::string json_key;
        // Get key and iv returned from DAE with generated CERT to decrypt the private key
        if (json.HasMember("key"))
        {
            const rapidjson::Value &key_val = json["key"];

            if (!key_val.IsNull())
            {
                json_key = key_val.GetString();
            }
        }
        if (json_key.empty())
        {
            m_error_message = "No key specified to decrypt private key";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
            return false;
        }

        std::string json_iv;
        if (json.HasMember("iv"))
        {
            const rapidjson::Value &iv_val = json["iv"];
            if (!iv_val.IsNull())
            {
                json_iv = iv_val.GetString();
            }
        }
        if (json_iv.empty())
        {
            m_error_message = "No iv specified to decrypt PK";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
            return false;
        }
#ifdef DEBUG_PRINT
        // For production we should not log the auth key and IV
        p_logger->printf(Log::Debug, " %s Cipher Key: %s", __func__, json_key.c_str());
        p_logger->printf(Log::Debug, " %s Cipher IV: %s", __func__, json_iv.c_str());
#endif // #if DEBUG_PRINT

        // We got json_key and json_iv..now decrypt them with auth key & iv
        std::string decrypted_key;
        if (!decryptData(key, iv, json_key, decrypted_key))
        {
            m_error_message = "Unable to decrypt the key.";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
            return false;
        }

        if (!decrypted_key.empty())
        {
#ifdef DEBUG_PRINT
                // For production we should not log the key
            p_logger->printf(Log::Debug, " %s Obtained key: %s", __func__, decrypted_key.c_str());
#else
            p_logger->printf(Log::Debug, " %s Obtained key: ************", __func__);
#endif // #if DEBUG_PRINT
        }

        std::string decrypted_iv;
        if (!decryptData(key, iv, json_iv, decrypted_iv))
        {
            m_error_message = "Unable to decrypt the IV.";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
            return false;
        }

        if (!decrypted_iv.empty())
        {
            // For production we should not log the IV
#ifdef DEBUG_PRINT
            p_logger->printf(Log::Debug, " %s Obtained IV: %s", __func__, decrypted_iv.c_str());
#else
            p_logger->printf(Log::Debug, " %s Obtained IV: ************", __func__, decrypted_iv.c_str());
#endif // #if DEBUG_PRINT
        }
        p_logger->printf(Log::Debug, " %s:%d pk_file_name: %s", __func__, __LINE__, pk_file_name.c_str());

        bool sign_apphash = false;
        if (!utils::decryptJsonBlockFile(pk, sign_apphash, decrypted_key, decrypted_iv, pk_file_name, true))
        {
            m_error_message = "Failed to decrypt with key and iv from DAE.";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
            return false;
        }

        p_logger->printf(Log::Debug, " %s:%d pk_name: %s", __func__, __LINE__, pk_path.c_str());

        if (!utils::encryptAndStorePK(pk, key, iv, key_id, m_asset_id, pk_path, false, sign_apphash))
        {
            m_error_message = "Failed to encrypt and store private key on certificate receipt.";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
            return false;
        }
        EventManager::getInstance()->notifyPrivateKeyStored("", pk_path, "", store_encrypted);

        if (!pk_file_name.empty() && (remove(pk_file_name.c_str()) != 0))
        {
            m_error_message = "Failed to delete intermediate private key";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
        }

        std::string certificate_json;
        utils::createJsonEncryptionBlock(key_id, m_asset_id, certificate, certificate_json, false, sign_apphash);
        certificate = certificate_json;
    }
    else // !store_encrypted
    {
        if (!decryptData(key, iv, certificate, certificate))
        {
            m_error_message = "Unable to decrypt certificate.";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyCertificateFailure(m_error_message);
            return false;
        }
    }
    p_logger->printf(Log::Debug, " %s:%d key_id: %s", __func__, __LINE__, key_id.c_str());

    return writeKeyAndCertificate(pk_path, private_key, cert_path, certificate, store_encrypted);
}

#else // WIN32

bool CertificateAssetProcessor::handleCertificate(const rapidjson::Value &json, const std::string &key, const std::string &iv, const std::string &key_id, unsigned int &sleep_value_from_ks)
{
    Log *p_logger = Log::getInstance();

    std::string file_path;
    if (!json.IsNull() && json.HasMember("filePath"))
    {
        const rapidjson::Value &filePathVal = json["filePath"];

        if (!filePathVal.IsNull())
        {
            file_path = filePathVal.GetString();
        }
    }
    if (file_path.empty())
    {
        m_error_message = "No file path specified (was expected).";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

        return false;
    }

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

    std::string pk_name;
    std::string cert_name;
    utils::getPKAndCertName(pk_name, cert_name, file_path);
    p_logger->printf(Log::Debug, " %s:%d pk_name: %s, cert_name: %s", __func__, __LINE__, pk_name.c_str(), cert_name.c_str());

    bool store_encrypted = false;
    if (json.HasMember("storeEncrypted"))
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

    std::string certificate;
    if (json.HasMember("certificate"))
    {
        const rapidjson::Value &certificate_val = json["certificate"];
        if (!certificate_val.IsNull())
        {
            certificate = certificate_val.GetString();
        }
    }
    if (certificate.empty())
    {
        m_error_message = "No certificate specified (was expected).";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

        return false;
    }

    EventManager::getInstance()->notifyCertificateReceived();

    std::string asset_id;
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
        m_error_message = "No assetId specified (was expected).";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

        return false;
    }

    std::string key_id_str;
    if (json.HasMember("keyId"))
    {
        const rapidjson::Value &key_id_val = json["keyId"];

        if (!key_id_val.IsNull())
        {
            key_id_str = key_id_val.GetString();
        }
    }

    // There should be a private_key element in the JSON if CSR is DAE generated.
    std::string private_key;
    if (json.HasMember("privateKey"))
    {
        const rapidjson::Value &private_key_val = json["privateKey"];

        if (!private_key_val.IsNull())
        {
            private_key = private_key_val.GetString();
        }
    }

    // Must use storage provider. We don't do anything with encrypting as the provider must manage this
    if (SSLWrapper::isUsingCustomStorageProvider())
    {
        if (!private_key.empty())
        {
            if (!decryptData(key, iv, private_key, private_key))
            {
                m_error_message = "Unable to decrypt private key.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
                return false;
            }
        }

        if (!decryptData(key, iv, certificate, certificate))
        {
            m_error_message = "Unable to decrypt certificate.";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyCertificateFailure(m_error_message);
            return false;
        }

        SSLWrapper ssl_wrapper{};
        if (!private_key.empty())
        {
            if (!ssl_wrapper.writePrivateKeyToStorageProvider(private_key, pk_name, store_encrypted))
            {
                m_error_message = "Failed to store private key using OpenSSL storage provider.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
                return false;
            }
            EventManager::getInstance()->notifyPrivateKeyStored("", pk_name, "", store_encrypted);
        }

        if (!ssl_wrapper.writeCertificateToStorageProvider(certificate, cert_name, store_encrypted))
        {
            m_error_message = "Failed to store certificate using OpenSSL storage provider.";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            EventManager::getInstance()->notifyCertificateFailure(m_error_message);
            return false;
        }
        EventManager::getInstance()->notifyCertificateStored("", cert_name, "", store_encrypted);

        return true;
    }

    // Decrypt certificates that need to be stored in an unencrypted state.
    if (!store_encrypted)
    {
        if (!decryptData(key, iv, certificate, certificate))
        {
            m_error_message = "Unable to decrypt certificate.";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
            return false;
        }

        if (!private_key.empty()) // DAE generated CSR and private key
        {
            p_logger->printf(Log::Debug, " %s DAE generated CSR and private key", __func__);
			EventManager::getInstance()->notifyPrivateKeyReceived();

            // Decrypt certificates that need to be stored in an unencrypted state.
            if (!decryptData(key, iv, private_key, private_key))
            {
                m_error_message = "Unable to decrypt private key.";
                p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());
                return false;
            }
        }

        // Write key and cert to files in unencrypted state
        return writeKeyAndCertificate(pk_name, private_key, cert_name, certificate, store_encrypted);
    }

    // Store in Windows cert store
    bool retval = false;

    // store in windows certificate store
    DWORD dwBufferLen = 0;

    WinCertStoreBase* p_win_cert_store{ WinCertStoreFactory::getInstance() };

    // Decrypting cert
    if (!decryptData(key, iv, certificate, certificate))
    {
        m_error_message = "Unable to decrypt certificate.";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

        return false;
    }

    if (!private_key.empty())
    {
	    EventManager::getInstance()->notifyPrivateKeyReceived();

		// Decrypting key
        if (!decryptData(key, iv, private_key, private_key))
        {
            m_error_message = "Unable to decrypt the key.";
            p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

            return false;
        }
    }

    std::vector<std::string> certs{};
    if (!p_win_cert_store->extractCertsFromCertificateChain(certificate, certs) || certs.empty())
    {
        m_error_message = "Failed to extract certs";
        p_logger->printf(Log::Error, " %s %s", __func__, m_error_message.c_str());

        return false;
    }

    const std::string leaf_cert = certs.back();

    std::string subject_name;
    if (p_win_cert_store->getSubjectNameFromCertificate(leaf_cert, subject_name))
    {
        const auto provider_name{ p_win_cert_store->getProviderName() };
        if (!private_key.empty())
        {
            if (p_win_cert_store->importPrivateKey(private_key, subject_name))
            {
                EventManager::getInstance()->notifyPrivateKeyStored(subject_name, "", provider_name, store_encrypted);
                retval = true;
            }
        }

        retval = p_win_cert_store->importCertChain(certs);
        if (retval)
        {
            EventManager::getInstance()->notifyCertificateStored(subject_name, "", provider_name, store_encrypted);
        }
    }

    return retval;
}
#endif

bool CertificateAssetProcessor::writeKeyAndCertificate(const std::string &pk_path, const std::string &private_key, const std::string &cert_path, const std::string &certificate, bool store_encrypted)
{
    Log *p_logger = Log::getInstance();
    p_logger->printf(Log::Debug, " %s Call writeKeyAndCertificate with file_path: %s, certSize: %d, privKeySize: %d", __func__, cert_path.c_str(), certificate.length(), private_key.length());

    bool success = utils::writeToFileSystem(pk_path, private_key, m_error_message, cert_path, certificate);
    if (success)
    {
        if (private_key.size() > 0)
        {
            EventManager::getInstance()->notifyPrivateKeyStored("", pk_path, "", store_encrypted);
        }
        if (certificate.size() > 0)
        {
            EventManager::getInstance()->notifyCertificateStored("", cert_path, "", store_encrypted);
        }
    }
    else
    {
        if (private_key.size() > 0)
        {
            EventManager::getInstance()->notifyPrivateKeyFailure(m_error_message);
        }
        if (certificate.size() > 0)
        {
            EventManager::getInstance()->notifyCertificateFailure(m_error_message);
        }
    }

    return success;
}
bool CertificateAssetProcessor::decryptData(const std::string &key, const std::string &iv, const std::string &encrypted_data, std::string &decrypted_data) const
{
    dacryptor cryptor;
    cryptor.setCryptionKey(key);
    cryptor.setInitVector(iv);
    cryptor.setInputData(encrypted_data);

    if (!cryptor.decrypt())
    {
        return false;
    }

    const unsigned char *output = nullptr;
    unsigned int length = 0;
    cryptor.getCryptedData(output, length);
    decrypted_data = std::string(reinterpret_cast<const char*>(output), length);

    return true;
}
