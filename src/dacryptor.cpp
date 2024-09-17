/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class provides encryption and decryption functionality using AES
 */
#include "dacryptor.hpp"
#include "base64.h"
#include "log.hpp"
#include <cstring>
#include <vector>
#include "deviceauthority.hpp"

namespace
{
    std::string crypt(const std::vector<char> &key, const std::vector<char> &iv, std::string &input, CipherMode mode)
    {
        std::string output;
        if (DeviceAuthorityBase* da = DeviceAuthority::getInstance())
        {
            char *out_buf = nullptr;
            int out_len = da->doCipherAES(&key[0], key.size(), &iv[0], iv.size(), input.c_str(), input.size(), mode, &out_buf);
            if (out_len >= 0)
            {
                output = std::string(out_buf, out_buf + static_cast<size_t>(out_len));
                delete[] out_buf;
            }
            else
            {
                Log::getInstance()->printf(Log::Error, "%s Failed to crypt %d", __func__, out_len);
            }
        }
        else
        {
            Log::getInstance()->printf(Log::Error, "%s Unable to obtain DeviceAuthority instance", __func__);
        }
        return output;
    }

} //end anon namepace

dacryptor::dacryptor()
{
}

dacryptor::~dacryptor()
{
}

void dacryptor::setInputData(const std::string& input_data)
{
    m_input = input_data;
}

bool dacryptor::setInitVector(const std::string& iv)
{
    m_iv = std::vector<char>(iv.begin(), iv.end());
    return true;
}

bool dacryptor::setInitVector(const std::vector<char>& iv)
{
    m_iv = std::vector<char>(iv.begin(), iv.end());
    return true;
}

bool dacryptor::setCryptionKey(const std::string& key)
{
	m_key = std::vector<char>(key.begin(), key.end());
    return true;
}

bool dacryptor::setCryptionKey(const std::vector<char>& key)
{
    m_key = std::vector<char>(key.begin(), key.end());
    return true;
}

bool dacryptor::encrypt()
{
    // Encrypt input to raw string
    std::string raw = crypt(m_key, m_iv, m_input, CipherModeEncrypt);

    // Base64 encode raw to output buffer
    std::vector< char > out_buf( raw.size() * 2/* Factor to ensure buf big enough to hold base64 data*/ );
    unsigned sz = base64Encode( (const unsigned char*)raw.c_str(), raw.size(), &out_buf[0], out_buf.size() );

    // Copy out buffer to output string
    m_output.assign( &out_buf[0], sz );

    // Success if we have some data
    return !m_output.empty();
}

bool dacryptor::decrypt()
{
    // Base64 decode input string before decryption
    std::vector< unsigned char > rawBuf( m_input.size() );
    unsigned sz = base64Decode( m_input.c_str(), (unsigned char *)&rawBuf[0], rawBuf.size() );

    // Copy rawBuf to string
    std::string raw_str((const char*)&rawBuf[0], sz);

    // Decrypt the raw string
    m_output = crypt(m_key, m_iv, raw_str, CipherModeDecrypt);

    // Success if we have some data
    return !m_output.empty();
}

void dacryptor::getCryptedData(const unsigned char *& outputData, unsigned int& dataLength)
{
    outputData = (unsigned char*)m_output.c_str();
    dataLength = m_output.size();
}
