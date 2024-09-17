
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Contains TPM wrapper that provides TPM functionality
 */
#ifndef TPM_WRAPPER_HPP
#define TPM_WRAPPER_HPP

#include <string>
#ifndef WIN32
#ifndef DISABLE_TPM
#include "tss2/tss2_fapi.h"
#endif // DISABLE_TPM
#endif // WIN32
#include "log.hpp"
#include "tpm_wrapper_base.hpp"

#ifndef DISABLE_TPM
class TpmWrapper : public TpmWrapperBase
{
public:
    static TpmWrapperBase* getInstance();
    static void setInstance(TpmWrapperBase* p_tpm_wrapper);

    bool getRandom(size_t num_bytes, std::vector<char> &random_str) const override;

    bool createSeal(const std::string &path, const std::vector<char> &data, bool overwrite = false) override;

    bool unseal(const std::string &path, std::vector<char> &data) override;

    bool deleteKey(const std::string &path) override;

private:
    /// @brief The root path for any keys / seals / etc. ensuring that they are held within
    /// the storage root key hierarchy
    static constexpr const char* m_root_path{"SRK/"};

    static TpmWrapperBase *m_instance;

    /// @brief The FAPI context
    FAPI_CONTEXT *mp_context{nullptr};

    /// @brief Constructor - Initialises the FAPI context and provisions the TPM if not already
    /// provisioned.
    TpmWrapper();

    /// @brief Destructor - cleans up the FAPI context
    virtual ~TpmWrapper();

    /// @brief Generate a unique keystore path from a seed value
    /// @details Uses SHA256 to create a deterministic value for the key then prepends the SRK path
    /// @param seed The seed value that will be hashed to create a key ID
    /// @param[out] keystore_path The path containing the SRK root and the key ID
    /// @return True on success, else false
    bool generateKeystorePath(const std::string &seed, std::string &keystore_path) const;
};

#else

class TpmWrapper : public TpmWrapperBase
{
public:

    static TpmWrapperBase* getInstance();

    static void setInstance(TpmWrapperBase* p_tpm_wrapper);

    bool getRandom(size_t num_bytes, std::vector<char> &random_str) const override
    {
        return false;
    }

    bool createSeal(const std::string &path, const std::vector<char> &data, bool overwrite = false) override
    {
        return false;
    }

    bool unseal(const std::string &path, std::vector<char> &data) override
    {
        return false;
    }

    bool deleteKey(const std::string &path) override
    {
        return false;
    }

private:
    static TpmWrapperBase *m_instance;

    /// @brief Constructor - Initialises the TPM wrapper as a system that never has a TPM available as
    /// TPM is disabled by the DISABLE_TPM preprocessor directive
    TpmWrapper()
    {
        m_initialised = true;
        m_host_has_tpm = false;
    }

    virtual ~TpmWrapper()
    {

    }
};

#endif // DISABLE_TPM

#endif // #ifndef TPM_WRAPPER_HPP
