/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An function to process any assets (only certificates at the moment)
 */
#ifndef SSLWRAPPER_HPP
#define SSLWRAPPER_HPP

#include <string>
#include "log.hpp"
#include "tpm_wrapper.hpp"

/*
 * Stores the CSR generation instructions obtained from KeyScaler
 */
class CsrInstructions
{
public:
    CsrInstructions() 
        : caSubject{ false }
        , storeEncrypted{ false } 
    { 
    }

    virtual ~CsrInstructions() = default;

    inline std::string getFileName() const
    {
        return fileName;
    }

    inline bool applyCaExtension() const
    {
        return caSubject;
    }

    inline bool shouldStoreEncrypted() const
    {
        return storeEncrypted;
    }

    inline std::string getAssetId() const
    {
        return assetId;
    }

    inline std::string getCommonName() const
    {
        return commonName;
    }

    inline const std::string getCertificateId() const
    {
        return certificateId;
    }

    inline void printCSR() const
    {
        Log *logger = Log::getInstance();

        logger->printf(Log::Debug, " %s certificateId: %s, assetId: %s, commonName: %s, fileName: %s, storeEncrypted: %d, caSubject %d", __func__, certificateId.c_str(), assetId.c_str(), commonName.c_str(), fileName.c_str(), storeEncrypted,caSubject);
    }

    void setCSRInfo(const std::string certId, const std::string assetId,const std::string commonName,const std::string fileName,const bool storeEncrypted,bool caSubject)
    {
        this->certificateId = certId;
        this->assetId = assetId;
        this->commonName = commonName;
        this->fileName = fileName;
        this->storeEncrypted = storeEncrypted;
        this->caSubject = caSubject;
    }

private:
    std::string certificateId;
    std::string assetId;
    std::string commonName;
    std::string fileName;
    bool storeEncrypted;
    bool caSubject;
};

// Uses openssl APIs tp generate key pair and CSR
class SSLWrapper
{
public:
    static const std::string md5hashstring(const std::string& md5_string);

    /// @brief Set whether we are using a custom storage provider
    /// @param state The state to set the flag
    static void setUsingCustomStorageProvider(bool state);

    /// @brief Get whether we are using a custom storage provider
    /// @return True if using custom storage provider
    static bool isUsingCustomStorageProvider();

    SSLWrapper();
    virtual ~SSLWrapper();

    /// @brief Generate key pair and store the key in encrypted form.
    /// @details Generates CSR using supplied commonName from csr info
    /// @param csr_info [in] pointer to csrInstruction object.
    /// @param key [in] for key encyption.
    /// @param value [in] for key encyption.
    /// @param key_id [in] for encrypted key storage
    /// @param csr [out] generated CSR for signing.
    /// @param private_key [out] generated private key
    /// @return 0 on failure.
    bool generateCSR(const CsrInstructions& csr_info, const std::string& key, const std::string& iv, const std::string& key_id, std::string& csr, std::string& private_key);
    const std::string createSelfSignedCert(const std::string &private_key, const std::string &common_name);
    
    /// @brief Write a private key to the openssl custom storage provider
    /// @details This method loads a raw private key into an OpenSSL BIO then attaches it to the OpenSSL 
    /// storage provider. We then load that private key using the storage provider to enable it to store
    /// the private key. 
    /// @param private_key The raw private key in string format
    /// @param key_id Identifier for this private key
    /// @param store_encrypted Flag indicating whether the private key should be stored encrypted
    /// @return True on success, else false.
    bool writePrivateKeyToStorageProvider(const std::string &private_key, const std::string &key_id, bool store_encrypted);

    /// @brief Write a certificate to the openssl custom storage provider
    /// @details This method loads a raw certificate into an OpenSSL BIO then attaches it to the OpenSSL 
    /// storage provider. We then load that certificate using the storage provider to enable it to store
    /// the certificate. 
    /// @param certificate The raw certificate string format
    /// @param cert_id Identifier for this certificate
    /// @param store_encrypted Flag indicating whether the certificate should be stored encrypted
    /// @return True on success, else false.
    bool writeCertificateToStorageProvider(const std::string &certificate, const std::string &cert_id, bool store_encrypted);

private:
    static bool m_use_custom_storage_provider;

    bool generateKeyPair(const std::string& key, const std::string& iv, std::string &priv_str, EVP_PKEY** public_key);
    bool createX509Request(const CsrInstructions& csr_info, EVP_PKEY* p_key, std::string &csr_out_str);
    void freeAll(void *x509_req, void *pKey, void *bne, void *r, void *bio_key, void *bio_csr);
};

#endif // #ifndef SSLWRAPPER_HPP
