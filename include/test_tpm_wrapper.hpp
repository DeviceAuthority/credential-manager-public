
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Contains a test implementation of a TPM wrapper to simulate using a TPM during testing
 */
#ifndef TEST_TPM_WRAPPER_HPP
#define TEST_TPM_WRAPPER_HPP

#include <algorithm>
#include <fcntl.h>
#include <map>
#include <string>
#include "log.hpp"
#include "tpm_wrapper_base.hpp"

#ifndef _WIN32

class TestTpmWrapper : public TpmWrapperBase
{
public:
    /// @brief Constructor
    TestTpmWrapper(bool host_has_tpm = true)
    {
        m_initialised = host_has_tpm;
        m_host_has_tpm = host_has_tpm;
    }

    virtual ~TestTpmWrapper()
    {

    }

    void addRandomDataResult(const std::vector<char> &random_bytes)
    {
        m_random_bytes_queue[random_bytes.size()] = random_bytes;
    }

    bool getRandom(size_t num_bytes, std::vector<char> &random_bytes) const override
    {
        // Use fixed value if given, else generate random using /dev/urandom
        const auto random_bytes_iter = m_random_bytes_queue.find(num_bytes);
        if (random_bytes_iter != m_random_bytes_queue.cend())
        {
            random_bytes = random_bytes_iter->second;
            return true;
        }

        uint8_t *rnd_buf = new uint8_t[num_bytes + 1]{'\0'};
        int fd = open("/dev/urandom", O_RDONLY);
        read(fd, rnd_buf, num_bytes);

        random_bytes = {rnd_buf, rnd_buf + num_bytes};
        delete[] rnd_buf;

        return true;
    }

    bool createSeal(const std::string &path, const std::vector<char> &data, bool overwrite = false) override
    {
        Log::getInstance()->printf(Log::Debug, "Adding data to path %s", path.c_str());

        if (!overwrite)
        {
            auto iter = m_sealed_data.emplace(std::make_pair(path, data));
            return iter.second; // success indicator second item in pair
        }

        m_sealed_data[path] = data;
        return true;
    }

    bool unseal(const std::string &path, std::vector<char> &data) override
    {
        auto iter = m_sealed_data.find(path);
        if (iter != m_sealed_data.end())
        {
            data = iter->second;
            return true;
        }

        return false;
    }

    bool hasKey(const std::string &path) const
    {
        return m_sealed_data.find(path) != m_sealed_data.end();
    }

    bool deleteKey(const std::string &path) override
    {
        auto iter = m_sealed_data.find(path);
        if (iter != m_sealed_data.end())
        {
            m_sealed_data.erase(iter);
            return true;
        }

        return false;
    }

private:
    // Stores data keyed by its path in memory
    std::map<std::string, std::vector<char>> m_sealed_data{};

    std::map<int, std::vector<char>> m_random_bytes_queue;

};

#else

class TestTpmWrapper : public TpmWrapperBase
{
public:
    /// @brief Constructor
    TestTpmWrapper(bool host_has_tpm = true)
    {
    }

    virtual ~TestTpmWrapper()
    {
    }

    void addRandomDataResult(const std::vector<char> &random_bytes)
    {

    }

    bool getRandom(size_t num_bytes, std::vector<char> &random_bytes) const override
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

    bool hasKey(const std::string &path) const
    {
        return false;
    }

    bool deleteKey(const std::string &path) override
    {
        return false;
    }
};

#endif // #ifndef _WIN32

#endif // #ifndef TPM_WRAPPER_HPP
