
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Contains TPM wrapper that provides TPM functionality
 */

#include <algorithm>
#include "tpm_wrapper.hpp"
#include "utils.hpp"

TpmWrapperBase* TpmWrapper::m_instance = nullptr;

TpmWrapperBase* TpmWrapper::getInstance()
{
    if (!m_instance)
    {
        m_instance = new TpmWrapper();
    }

    return m_instance;
}

void TpmWrapper::setInstance(TpmWrapperBase* p_tpm_wrapper)
{
    if (m_instance)
    {
        delete m_instance;
        m_instance = nullptr;
    }

    m_instance = p_tpm_wrapper;
}

#ifndef DISABLE_TPM
TpmWrapper::TpmWrapper()
{
    TSS2_RC rc = Fapi_Initialize(&mp_context, nullptr);
    if (rc == TSS2_RC_SUCCESS)
    {
        rc = Fapi_Provision(mp_context, nullptr, nullptr, nullptr);
    }

    m_host_has_tpm = (rc != TSS2_FAPI_RC_NO_TPM);

    m_initialised = rc == TSS2_RC_SUCCESS || rc == TSS2_FAPI_RC_ALREADY_PROVISIONED;
}

TpmWrapper::~TpmWrapper()
{
    if (mp_context)
    {
        Fapi_Finalize(&mp_context);
        mp_context = nullptr;
    }
}

bool TpmWrapper::getRandom(size_t num_bytes, std::vector<char> &random_bytes) const
{
    uint8_t *rnd_buf = nullptr;
    TSS2_RC rc = Fapi_GetRandom(mp_context, num_bytes, &rnd_buf);
    if (rc == TSS2_RC_SUCCESS)
    {
        random_bytes = std::vector<char>(rnd_buf, rnd_buf + num_bytes);
        Fapi_Free(rnd_buf);

        return true;
    }

    random_bytes.clear();
    return false;
}

bool TpmWrapper::createSeal(const std::string &path, const std::vector<char> &data, bool overwrite)
{
    Log* p_logger = Log::getInstance();

    // Hash the path to create a key ID which doesn't contain any unexpected characters
    std::string keystore_path;
    if (!generateKeystorePath(path, keystore_path))
    {
        p_logger->printf(Log::Error, "Failed to obtain keystore path");
        return false;
    }

    // Use system type to ensure all users will read and write to the same system location on the filesystem
    TSS2_RC rc = Fapi_CreateSeal(
        mp_context,
        keystore_path.c_str(),
        "noda,system",
        data.size(),
        nullptr,
        nullptr,
        (uint8_t*)&data[0]);
    if (rc == TSS2_FAPI_RC_PATH_ALREADY_EXISTS)
    {
        if (!overwrite)
        {
            p_logger->printf(Log::Error, "Failed to generate key %s, already exists", keystore_path.c_str());
            return false;
        }

        p_logger->printf(Log::Debug, "Key already exists at %s. Overwriting...", keystore_path.c_str());
        rc = Fapi_Delete(mp_context, keystore_path.c_str());
        if (rc != TSS2_RC_SUCCESS)
        {
            p_logger->printf(Log::Error, "Failed to delete key at path %s", keystore_path.c_str());
            return false;
        }

        // Set overwrite to false to ensure that we don't get stuck repeatedly overwriting and failing to create seal
        return createSeal(path, data, false);
    }

    return rc == TSS2_RC_SUCCESS;
}

bool TpmWrapper::unseal(const std::string &path, std::vector<char> &data)
{
    Log* p_logger = Log::getInstance();

    std::string keystore_path;
    if (!generateKeystorePath(path, keystore_path))
    {
        p_logger->printf(Log::Error, "Failed to obtain keystore path");
        return false;
    }

    uint8_t* raw_data{nullptr};
    size_t size;
    TSS2_RC rc = Fapi_Unseal(
        mp_context,
        keystore_path.c_str(),
        &raw_data,
        &size);
    if (rc == TSS2_RC_SUCCESS)
    {
        data = {raw_data, raw_data + size};
        Fapi_Free(raw_data);
        return true;
    }

    p_logger->printf(Log::Error, "Failed to unseal key at %s", keystore_path.c_str());
    return false;
}

bool TpmWrapper::deleteKey(const std::string &path)
{
    return Fapi_Delete(mp_context, (m_root_path + path).c_str()) == TSS2_RC_SUCCESS;
}

bool TpmWrapper::generateKeystorePath(const std::string &orig_path, std::string &keystore_path) const
{
    keystore_path = orig_path;
    // sanitise orig_path into a format compatible with the TPM2-TSS keystore key naming convention
    std::replace(keystore_path.begin(), keystore_path.end(), '/', '_');
    std::replace(keystore_path.begin(), keystore_path.end(), '\\', '_');
    std::replace(keystore_path.begin(), keystore_path.end(), '.', '_');
    keystore_path = m_root_path + keystore_path;
    return true;
}

#endif // DISABLE_TPM
