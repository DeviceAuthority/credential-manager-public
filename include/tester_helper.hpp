
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Base class for implementations that process received assets
 */
#ifndef TESTER_HELPER_HPP
#define TESTER_HELPER_HPP

#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <memory>
#include <string>
#include <vector>
#include "base64.h"
#include "deviceauthority.hpp"
#include "utils.hpp"
#include "rsa_utils.hpp"

class TesterHelper
{
public:
    static const char * m_privateKey;

    static const char *m_publicKeyStr;
    static const char *m_certificate;

    static const char *m_aesKey;
    static const char *m_aesIv;

    static std::string makeRecipeAsset(const std::string &assetId, const std::string &script, const std::string &dataurl, bool is_code_signing = false)
    {
        const std::string scriptB64 = utils::toBase64(script);
        const std::string sig = utils::toBase64(TesterHelper::sign(TesterHelper::digest(scriptB64), TesterHelper::getRSAPrivateKey()));
        const std::string data = "{ \"recipe\":\"" + scriptB64 + "\",\n" + "  \"sig\":\"" + sig + "\" }";
        std::stringstream ss;
        // Duplicated asset type property as this appears to be what SAC sends us currently.
        ss << "{\n"
           << "  \"assetType\": " << (is_code_signing ? "\"CODE_SIGNING\"" : "\"SCRIPT\"") << ",\n"
           << "  \"assetId\": \"" << assetId << "\",\n"
           << "  \"assetType\": " << (is_code_signing ? "\"CODE_SIGNING\"" : "\"SCRIPT\"") << ",\n"
           << "  \"azureFileLink\":\"" << dataurl << "\",\n"
           << "  \"fileLink\":\"" << dataurl << "\",\n"
           << "  \"data\":\"" << TesterHelper::encrypt(data, TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv()) << "\"\n"
           << "}";
        return ss.str();
    }

    static std::string makeInvalidAsset(const std::string &assetId)
    {
        std::stringstream ss;
        ss << "{\n"
           << "  \"assetType\": \"UnknownAssetType\",\n"
           << "  \"assetId\": \"" << assetId << "\"\n"
           << "}";
        return ss.str();
    }

    // Create a BIO object from the given string holding an RSA key or Certificate
    static BIOPtr createBIO(const std::string &key)
    {
        BIOPtr bio(BIO_new(BIO_s_mem()), BIO_free);
        if (!bio)
        {
            throw std::runtime_error("Failed to create buffer for Public Key");
        }
        else if ((unsigned)key.size() != (unsigned)BIO_write(bio.get(), key.c_str(), (int)key.size()))
        {
            throw std::runtime_error("Failed to write RSA Key into internal buffer");
        }
        return bio;
    }

    static std::string sign(const std::string &data, const std::string &key)
    {
        RSAPtr rsaKey(PEM_read_bio_RSAPrivateKey(createBIO(key).get(), 0, 0, 0), RSA_free);
        if (!rsaKey)
        {
            throw std::runtime_error("Failed to create private key!");
        }

        unsigned int sigLen = RSA_size(rsaKey.get());
        std::vector<unsigned char> sig(sigLen, 0);

        if (0 == RSA_sign(NID_sha256, (const unsigned char *)data.c_str(), data.size(), &sig[0], &sigLen, rsaKey.get()))
        {
            throw std::runtime_error("Failed to sign data:" + data);
        }

        return std::string(sig.begin(), sig.begin() + sigLen);
    }

    static std::string digest(const std::string &data)
    {
        return DeviceAuthority::getInstance()->doDigestSHA256(data);
    }

    static std::string encrypt(const std::string &value, const std::string &key, const std::string &iv)
    {
        dacryptor cryptor;
        cryptor.setCryptionKey(key);
        cryptor.setInitVector(iv);
        cryptor.setInputData(value);

        std::string res = "";
        if (cryptor.encrypt())
        {
            const unsigned char *output = nullptr;
            unsigned int length = 0;
            cryptor.getCryptedData(output, length);
            res = std::string((const char *)output, length);
        }

        return res;
    }

    static std::string decrypt(const std::string &value, const std::string &key, const std::string &iv)
    {
        dacryptor cryptor;
        cryptor.setCryptionKey(key);
        cryptor.setInitVector(iv);
        cryptor.setInputData(value);

        std::string res = "";
        if (cryptor.decrypt())
        {
            const unsigned char *output = nullptr;
            unsigned int length = 0;
            cryptor.getCryptedData(output, length);
            res = std::string((const char *)output, length);
        }

        return res;
    }

    static std::string makeSatAssetData(const std::string &key, const std::string &iv)
    {
        const std::string encryptedKeyB64 = encrypt(key, m_aesKey, m_aesIv);
        const std::string encryptedIvB64 = encrypt(iv, m_aesKey, m_aesIv);

        std::stringstream ss;
        ss << "{\n"
           << "  \"key\": \"" << encryptedKeyB64 << "\",\n"
           << "  \"iv\": \"" << encryptedIvB64 << "\"\n"
           << "}";
        return ss.str();
    }

    static RSAPtr getRSAPublicKey()
    {
        // RSA pointer to hold generated key;
        RSAPtr rsaKey(PEM_read_bio_RSA_PUBKEY(createBIO(m_publicKeyStr).get(), 0, 0, 0), RSA_free);

        // Did we manage to create an RSA object?
        if (!rsaKey)
        {
            // No => throw exception
            throw std::runtime_error("Failed to read RSA public key from:\n" + std::string(m_publicKeyStr));
        }

        return rsaKey;
    }

    static std::string getRSAPrivateKey()
    {
        return m_privateKey;
    }

    static std::string getSymmetricKey()
    {
        return m_aesKey;
    }

    static std::string getSymmetricIv()
    {
        return TesterHelper::m_aesIv;
    }

    static bool checkFileContentsMatch(const std::string &filename, const std::string &expected)
    {
        std::ifstream ifs(filename);
        if (!ifs.good()) // file exists?
        {
            std::cerr << "File not found: " << filename.c_str() << std::endl;
            return false;
        }
		
		std::stringstream ss;
		ss << ifs.rdbuf(); //read the file
		const std::string line = ss.str(); //str holds the content of the file
        ifs.close();
        if (expected != line)
        {
            std::cerr << "Expected string " << expected.c_str() << " does not match " << line << std::endl;
            return false;
        }

        return true;
    }
};


const char *TesterHelper::m_privateKey =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpQIBAAKCAQEAowBa409fWPTqZsN+8G/U2riw95Gxj3AXUGq+IpXfFUphljZf\n"
    "feQs0Mm5OI97QX2IM20xqHYZW32qNETdpBQtmWjQlKxSbAon6LTSr1D8kdH8Koic\n"
    "hRc/ciZdso9HEzykPhyHEJGkh+61g66JMDKVmL/Z+y8sZCyeIJwXG57q2cuVUh9g\n"
    "B+B12gvRibMsY/dVJFeYL3+7G5y8Erngg+YZsGCpjLmKiyCiWdGOWRrFj1nE18Xh\n"
    "mjQY99MHiuX1AfYn8m9PF4gq2zXhZmQp8BXhtkGSjLJG4FL5g/Ce33sIbMa5IudH\n"
    "BXksXJ0SRGdx1ToQYN+JNM/E/CMNiEIW+nsGOwIDAQABAoIBAQCZxYH4oy5t+08O\n"
    "dytPpBCH7mh0hWuex74WzTxl4EE+EpeRX+YiG5nztfoYU7ORit1stnx8Uj2FxD1H\n"
    "Zhg57BdAfFMZjp+K8OHJdJy1a495+UEM1yfhnpbqFyuZgfUpPrIrLjp09RDkc9ul\n"
    "SIh/gZkDKyp2/n/AWR8r4FUkZ31izFy7QvU0TuP7wk84xaGa72j6j0RgY1T2gvc8\n"
    "7KOJ09vGuJExMlXZHTPa1xqzCY3+9v8OQiKCYHby7S/JB3dxxGv/hN1DoVi7A5CW\n"
    "RBsrNftqYYnSYeZFqyTPEBQyuFvE0vTfo5Rwi0os9ZlXrIWrzbOUawhc1dLsBFay\n"
    "GCh/qxixAoGBAMzcKaCBlLiWLBGE5UNiREM72S6rWoMEmr0RzwKOjfYS2oNN9zqg\n"
    "OTp5I9Eo5OPmlYQEkErZ2uHRuHiuYpH4fYGkVpLfCOdNBA4xHhqnyGlJ/Fg6/u+M\n"
    "+4R920RXuhhAqVPis59g+Rv6NFjhWaDndJj4hroUAtbb4OVS17WSkPgvAoGBAMux\n"
    "Kg8pIXqF/aIcSV3Ha3QdxlK6O1dV/Meo+pEDzDQI5ePSYBEU0c3afRJaSWeOueBs\n"
    "6ek/Y1JH6m60ROklyz10qLoysHyJoWJXx2yftQAtR2NtiQEec4ubJKs4U0qqYHvO\n"
    "fUI+6iLiQb4o8/CUHtt+tlGAUxi75n0EBbXiXQO1AoGBAIhyf9tjU65af8GvdZCb\n"
    "LAJoI3D9Os0XTQVvjiUS1CU5S4e3b1sCCvwSYbPXfBT7qUyESaNBVZOhPzBKXmcB\n"
    "Tn8B+ZPbsC93UaMuPfHdHRRb7hLKQLFHguMtfNUZZV7v+phf3+nhCisDTMiCWFNe\n"
    "tn+I0RuxZm67hyDXO8u5couLAoGASBm4B5HJlfMj6mQU3CsgsANyFgpxwuJfDdWU\n"
    "jAxKFgkoRtJKywERmspCB2MKJKvyw6wJyFR1tcRbCUCqO9Ty8hf/OZmDuzGEfKkR\n"
    "oDOQADYG1P0Kx+idgccy3aCcawuQB4L5958JhbuNBeC9KGVl3tAlfQftYg3w8kOg\n"
    "OdeckRkCgYEAlBnMXgOfzYUi4RaRYe3/yWjWDQzaWlZMk6Eif/InxTNBKBbNb2FX\n"
    "gxG2XPI4vReY/P6ZY31wOLnrm1tMuCPm4LLWtWq1p8mmTfWyiTAvkIwkY3wfLgNc\n"
    "/OiVkltk090cklFjydsJ/KMfzpySQHEqrEnxSyx/qzCR0mWqKJl6MLQ=\n"
    "-----END RSA PRIVATE KEY-----";

const char *TesterHelper::m_publicKeyStr =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAowBa409fWPTqZsN+8G/U\n"
    "2riw95Gxj3AXUGq+IpXfFUphljZffeQs0Mm5OI97QX2IM20xqHYZW32qNETdpBQt\n"
    "mWjQlKxSbAon6LTSr1D8kdH8KoichRc/ciZdso9HEzykPhyHEJGkh+61g66JMDKV\n"
    "mL/Z+y8sZCyeIJwXG57q2cuVUh9gB+B12gvRibMsY/dVJFeYL3+7G5y8Erngg+YZ\n"
    "sGCpjLmKiyCiWdGOWRrFj1nE18XhmjQY99MHiuX1AfYn8m9PF4gq2zXhZmQp8BXh\n"
    "tkGSjLJG4FL5g/Ce33sIbMa5IudHBXksXJ0SRGdx1ToQYN+JNM/E/CMNiEIW+nsG\n"
    "OwIDAQAB\n"
    "-----END PUBLIC KEY-----";

const char *TesterHelper::m_certificate = "-----BEGIN CERTIFICATE-----\nMIIDETCCAfkCFBWeseQkSi3duBP6ieYfi5hx88kaMA0GCSqGSIb3DQEBCwUAMEUx\nCzAJBgNVBAYTAkdCMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\ncm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjQwMzA0MTcyNDI1WhcNMjUwMzA0MTcy\nNDI1WjBFMQswCQYDVQQGEwJHQjETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE\nCgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC\nAQ8AMIIBCgKCAQEAk90/qjsel7r2xxhdShWxb7WkAajrzK+2PTZZ5LKmx7WHHSHy\n+geU5qYPgk7Po1UUouOKnTAwxglLe3d0pAgNHoYzAHHCK9LXNntpgz4XrnL2LJhT\n7YCuwMN3TBzqXHmZy2BPa7tyDOoqljyewD5+ggT3slftnGvXKBhUZMQ4pxQBjAeY\n7d8LRBwZoK2DfuGFgicgpna+pjr6k+P7oWDLcUkjOGCHBx2JX52dpTz3jGWbYnEc\n+QY4NBgOVZ49Y6dbk6MONGsdlo5HYm1XnotpZKrdHXzqEGqKJV+L1xgJzd1vU6XL\n5xrNCWY0SdVkK3f3sPfRkUcXdLnNLztBun2AMwIDAQABMA0GCSqGSIb3DQEBCwUA\nA4IBAQAi8cSB2ko9gVikjc9s70Lr2gNzsLEEM7zWvNz+zFr0yczRkoxG/3xxMLan\nTvdKjHzGBUXXpwSmqBziVqkYyx6C0e3Z77ql0XGnWVIFLepsqVvYxyHezo2Lp4+M\nKwG3f1sYOrg3LAQPsrcwi1fFJTj82uNv6QrGnnjitzPs4RKiTTnF+tAkNP/d6Y8G\nCX0mZa68lsM9VQ939yTZ7qT+W7kfvWPc6eZ8gz+PtnEEViFBW7Sn6aub7y4VmRXT\n8QGsR7mduEEh3EIos61bmI8JkS7/asRcFd5o92eXRbs/R5+kTKqRSoq5lbhEXE0J\nVDSEnab86efNI852k/r3gWgzaw6n\n-----END CERTIFICATE-----\n";
const char *TesterHelper::m_aesKey = "E8B6C00C9ADC5E75BB656ECD429CB1643A25B111FCD22C6622D53E0722439993";
const char *TesterHelper::m_aesIv = "E486BB61EB213ED88CC3CFB938CD58D7";


#endif // #ifndef TESTER_HELPER_HPP
