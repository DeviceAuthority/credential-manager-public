/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class provides encryption and decryption functionality using AES
 */
#ifndef DACRYPTOR_HPP
#define DACRYPTOR_HPP

#include <string>
#include <vector>

class dacryptor
{
public:
    dacryptor();
    virtual ~dacryptor();

    // Supply the data to be encrypted/decrypted
    void setInputData(const std::string& input);
    // Supply an initialisation vector to be used (if not supplied one is automatically generated)
    bool setInitVector(const std::string& ivStr);
    bool setInitVector(const std::vector<char>& iv_str);
    // Supply a key directly
    bool setCryptionKey(const std::string& keyStr);
    bool setCryptionKey(const std::vector<char>& key_str);
    // Encrypt the input data
    bool encrypt();
    // Decrypt the input data
    bool decrypt();

    // Get the encrypted/decrypted result
    void getCryptedData(const unsigned char*& outputData, unsigned int& dataLength);

private:

    std::string m_output;
    std::string m_input;
    std::vector<char> m_key;
    std::vector<char> m_iv;
};

#endif // #ifndef DACRYPTOR_HPP
