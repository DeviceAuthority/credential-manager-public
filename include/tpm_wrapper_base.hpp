
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Contains TPM wrapper base class that defines the TPM wrapper interface
 */
#ifndef TPM_WRAPPER_BASE_HPP
#define TPM_WRAPPER_BASE_HPP

#include <string>
#include <vector>
#include "log.hpp"

class TpmWrapperBase
{
public:
    /// @brief Constructor
	TpmWrapperBase() {
		m_initialised = false;
		m_host_has_tpm = false;
	};

    /// @brief Destructor
	virtual ~TpmWrapperBase() {};

    /// @brief Get whether the TPM wrapper has initialised successfully
    /// @return True on success, else false
    bool initialised() const
    {
        return m_initialised;
    }

    /// @brief Get whether the host has a TPM device
    /// @return True if TPM is available, else false
    bool isTpmAvailable() const
    {
        return m_host_has_tpm;
    }

    /// @brief Get a random string of num_bytes in length
    /// @param num_bytes The number of random bytes to generate
    /// @param random_str The string object that will contain the random bytes
    /// @return true on success, else false
    virtual bool getRandom(size_t num_bytes, std::vector<char> &random_str) const = 0;

    /// @brief Creates a seal on the given data
    /// @details This encrypts and binds the data to the TPM host. The data can only be decrypted
    /// successfully on the machine that it is bound to by this seal.
    /// @param path The path to store the sealed object
    /// @param data The data to encrypt and seal
    /// @param override If true will overwrite an existing value, else returns failure (defaults to false)
    /// @return true on success, false on failure
    virtual bool createSeal(const std::string &path, const std::vector<char> &data, bool overwrite = false) = 0;

    /// @brief Unseals a sealed object returning the decrypted data
    /// @param path The path of the object to unseal
    /// @param data The object that will contain the returned data on success
    /// @return True if successfully unsealed, else false
    virtual bool unseal(const std::string &path, std::vector<char> &data) = 0;

    /// @brief Delete a key held by the TPM
    /// @param path The path of the key to delete
    /// @return True on success, else false
    virtual bool deleteKey(const std::string &path) = 0;

protected:
    /// @brief Stores whether the TPM was initialised successfully
    bool m_initialised;

    /// @brief Flag indicating if the host has a TPM
    bool m_host_has_tpm;
};

#endif // #ifndef TPM_WRAPPER_BASE_HPP
