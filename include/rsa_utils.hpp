
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Contains RSA utility functions
 */
#ifndef RSA_UTILS_HPP
#define RSA_UTILS_HPP

#if defined(WIN32)
#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include "wincrypt.h"
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
//#include <openssl/applink.c>
#include <openssl/ssl.h>
#else
#include <pwd.h>
#endif
#include <openssl/ssl.h>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include "configuration.hpp"
#include "constants.hpp"

typedef std::shared_ptr<RSA> RSAPtr;
typedef std::shared_ptr<BIO> BIOPtr;

class RsaUtils
{
public:
    static RSAPtr getRSAPublicKey()
    {
        std::string public_key_path;
        if (config.exists(CFG_CERTIFICATEPATH))
        {
            public_key_path = config.lookup(CFG_CERTIFICATEPATH);
        }

        if (public_key_path.empty())
        {
            throw std::runtime_error("KeyScaler Public Key Certificate Path not set");
        }

        std::ifstream in(public_key_path);
        if (!in.good())
        {
            throw std::runtime_error("Unable to open KeyScaler public key");
        }

        std::stringstream buf;
        buf << in.rdbuf();
        const std::string key = buf.str();
        in.close();

        // RSA pointer to hold generated key;
        RSAPtr rsa_key(PEM_read_bio_RSA_PUBKEY(createBIO(key).get(), 0, 0, 0), RSA_free);

        // Did we manage to create an RSA object?
        if (!rsa_key)
        {
            // No => throw exception
            throw std::runtime_error("Invalid RSA public key read from: " + public_key_path);
        }

        return rsa_key;
    }

private:
    // Create a BIO object from the given string holding an RSA key or Certificate
    static std::shared_ptr<BIO> createBIO(const std::string &key)
    {
        // Shared BIO pointer with custom deleter - ensures BIO freed correctly
        std::shared_ptr<BIO> bio(BIO_new(BIO_s_mem()), BIO_free);

        // Check if we created BIO correctly and can load the key string
        if (!bio)
        {
            // Failed to create BIO, so throw exception
            throw std::runtime_error("Failed to create buffer for Public Key");
        } // Created, so now try and write data into BIO from key string
        else if ((unsigned)key.size() != (unsigned)BIO_write(bio.get(), key.c_str(), (int)key.size()))
        {
            // Failed to write data, so throw exception
            throw std::runtime_error("Failed to write RSA Key into internal buffer");
        }

        return bio;
    }
};

#endif // #ifndef RSA_UTILS_HPP
