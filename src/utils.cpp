/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a string of bytes.
 */
#include <sstream>
#include <fstream>
#include <cstring>
#include <list>
#include <vector>
#include <algorithm>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#if defined(WIN32)
#include <Windows.h>
#include <io.h>
#include <string>
#include <list>
#else
#include <unistd.h>
#endif // #if defined(WIN32)
#include <algorithm>
#include <sys/stat.h>
#include <errno.h>
#include <random>
#include <climits>
#if __cplusplus > 199711L
#include <chrono>
#else
#include <ctime>
#endif // #if __cplusplus > 199711L
#include "base64.h"
#include "dacryptor.hpp"
#include "log.hpp"
#include "utils.hpp"
#include "deviceauthority.hpp"
#include "tpm_wrapper_base.hpp"
#include "tpm_wrapper.hpp"


#ifndef MAX_PATH
#define MAX_PATH 256
#endif // #ifndef MAX_PATH
#define DEBUG_PRINT 0

namespace utils
{

    bool stringEndsWith(std::string const &src, std::string const &ending)
    {
        if (src.length() >= ending.length())
        {
            return (0 == src.compare(src.length() - ending.length(), ending.length(), ending));
        }

        return false;
    }

    std::string toLower(const std::string& str)
    {
        std::string lcStr = str;

        std::transform(lcStr.begin(), lcStr.end(), lcStr.begin(), tolower);

        return lcStr;
    }

    std::string toUpper(const std::string& str)
    {
        std::string ucStr = str;

        std::transform(ucStr.begin(), ucStr.end(), ucStr.begin(), toupper);

        return ucStr;
    }

    bool isEmpty(const char *str)
    {
        if ((str == NULL) || (strlen(str) == 0))
        {
            return true;
        }

        return false;
    }

    bool isNull(const char *str)
    {
        return (str == NULL);
    }

    int caseInsensitiveCompare(const char *str1, const char *str2)
    {
        std::string str1Cpy(str1);
        std::string str2Cpy(str2);

        toLowerCase(str1Cpy);
        toLowerCase(str2Cpy);

        return str1Cpy.compare(str2Cpy);
    }

    char *toUpperCase(char *data, size_t cbData)
    {
        if ((data == NULL) || (cbData == 0))
        {
            // Nothing to convert, bails out
            return data;
        }

        char *pCh = data;

        for (uint32_t i = 0; i < cbData; i++)
        {
            char c = *(pCh + i);

            // Lowercase?
            if ((c >= 'a') && (c <= 'z'))
            {
                // Converts to uppercase
                *(pCh + i) = (c - 32);
            }
        }

        return data;
    }

    void toUpperCase(std::string &data)
    {
        std::transform(data.begin(), data.end(), data.begin(), ::toupper);
    }

    char *toLowerCase(char *data, size_t cbData)
    {
        if ((data == NULL) || (cbData == 0))
        {
            // Nothing to convert, bails out
            return data;
        }

        char *pCh = data;

        for (uint32_t i = 0; i < cbData; i++)
        {
            char c = *(pCh + i);

            // Uppercase?
            if ((c >= 'A') && (c <= 'Z'))
            {
                // Converts to lowercase
                *(pCh + i) = (c + 32);
            }
        }

        return data;
    }

    void toLowerCase(std::string &data)
    {
        std::transform(data.begin(), data.end(), data.begin(), ::tolower);
    }

    bool base64DecodeKeyIV(std::string &key, std::string &iv)
    {
        Log *logger = Log::getInstance();
        static const int BUFLEN = 1024;
        unsigned char decodedData[BUFLEN] = {0};
        unsigned int decodedLength = base64Decode(key.c_str(), decodedData, sizeof(decodedData));

        if (decodedLength == 0)
        {
            logger->printf(Log::Error, " %s Unable to encode Key (E)..", __func__);

            return false;
        }
        key.assign((const char *)decodedData, decodedLength);
        memset(decodedData, 0, BUFLEN);
        decodedLength = base64Decode(iv.c_str(), decodedData, BUFLEN);
        if (decodedLength == 0)
        {
            logger->printf(Log::Error, " %s Unable to encode IV (E)..", __func__);

            return false;
        }
        iv.assign((const char *)decodedData, decodedLength);

        return true;
    }

    bool base64EncodeKeyIV(std::string &key, std::string &iv)
    {
        Log *logger = Log::getInstance();
        unsigned int encodedBlockLength = ((unsigned int)key.length()) * 2u;
        char *encodedBlock = new char[encodedBlockLength];

        memset(encodedBlock, 0, encodedBlockLength);

        int ret = base64Encode((const unsigned char *)key.c_str(), (unsigned int)key.length(), encodedBlock, encodedBlockLength);
        if (ret == 0)
        {
            logger->printf(Log::Error, " %s Unable to encode Key (E)..", __func__);
            delete[] encodedBlock;
            encodedBlock = NULL;

            return false;
        }
        key.assign(encodedBlock, ret);
        delete[] encodedBlock;
        encodedBlockLength = ((unsigned int)iv.length()) * 2u;
        encodedBlock = new char[encodedBlockLength];
        memset(encodedBlock, 0, encodedBlockLength);
        ret = base64Encode((const unsigned char *)iv.c_str(), (unsigned int)iv.length(), encodedBlock, encodedBlockLength);
        if (ret == 0)
        {
            logger->printf(Log::Error, " %s Unable to encode IV (E)..", __func__);
            delete[] encodedBlock;
            encodedBlock = NULL;

            return false;
        }
        iv.assign(encodedBlock, ret);
        delete[] encodedBlock;
        encodedBlock = NULL;

        return true;
    }

    /*
     * Constructs a JSON strcture using "key-id" & "ciphertext".
     * @param key_id reference to KeyId value.
     * @param asset_id The ID of the asset
     * @param encrypted_string The ciphertext to store in the JSON block.
     * @param encrypted_json_block The output containing the encrypted JSON block.
     * @param use_base64 If true entire json structure is base64 encoded.
     * @param sign_apphash Indicate whether the apphash requires a signature in the response.
     * @return JSON in string format.
     */
    void createJsonEncryptionBlock(const std::string &key_id, const std::string &asset_id, const std::string &encrypted_string, std::string &encrypted_json_block, bool use_base64, bool sign_apphash)
    {
        Log *p_logger = Log::getInstance();

        rapidjson::Document root_document;
        root_document.SetObject();
        rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

        root_document.AddMember("key-id", rapidjson::StringRef(key_id.c_str()), allocator);
        if (!asset_id.empty())
        {
            root_document.AddMember("asset-id", rapidjson::StringRef(asset_id.c_str()), allocator);
        }
        root_document.AddMember("ciphertext", rapidjson::StringRef(encrypted_string.c_str(), encrypted_string.size()), allocator);
        root_document.AddMember("sign-apphash", sign_apphash, allocator);

        rapidjson::StringBuffer strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
        root_document.Accept(writer);
        encrypted_json_block = (use_base64) ? toBase64(strbuf.GetString()) : strbuf.GetString();

        p_logger->printf(Log::Debug, " %s:%d JSON: %s", __func__, __LINE__, encrypted_json_block.c_str());
    }

    const std::string toBase64(const std::string &data)
    {
        std::vector<char> buf(data.size() * 2, 0);
        unsigned int sz = base64Encode((unsigned char *)data.c_str(), (unsigned int)data.size(), &buf[0], (unsigned int)buf.size());
        return std::string(buf.begin(), buf.begin() + sz);
    }

    const std::string fromBase64(const std::string &data)
    {
        std::vector<unsigned char> buf(data.size());
        unsigned int sz = base64Decode(data.c_str(), &buf[0], buf.size());
        return std::string(buf.begin(), buf.begin() + sz);
    }

    /*
     * Generates fileName with complete path under directory filePath with given name.
     */
    bool generateKeyPath(const std::string &file_path, const std::string &name, std::string &pk_file_name)
    {
        std::ostringstream sstr("");
        size_t last = file_path.find_last_of("/");

        if (last == std::string::npos)
        {
            last = file_path.find_last_of("\\");
        }
        if (last != std::string::npos)
        {
            std::string path = file_path.substr(0, last);

            sstr << path;
        }
        else
        {
            sstr << file_path;
        }
        // logger->printf(Log::Information, " %s pk_file_name path: %s", __func__, sstr.str().c_str());
#if defined(WIN32)
        sstr << "\\" << name;
#else
        sstr << "/" << name;
#endif // #if defined(WIN32)
        pk_file_name = sstr.str();
        // logger->printf(Log::Information, " %s pk_file_name: %s", __func__, pk_file_name.c_str());

        return true;
    }

#if defined(WIN32)
    std::wstring toWideString(const char *s)
    {
        int wchars_num = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
        LPWSTR lpwStr = new WCHAR[wchars_num];

        MultiByteToWideChar(CP_UTF8, 0, s, -1, lpwStr, wchars_num);
        std::wstring wstr = lpwStr;

        delete[] lpwStr;

        return wstr;
    }

    std::wstring toWideString(const std::string& s)
    {
        return toWideString(s.c_str());
    }
#endif // WIN32

    // Return true if the folder exists, false otherwise
    bool folderExists(const char *folderName)
    {
#ifdef WIN32
        if (_access(folderName, 0) == -1)
        {
            // File or directory not found
            return false;
        }

        DWORD attr = GetFileAttributes(toWideString(folderName).c_str());

        if (!(attr & FILE_ATTRIBUTE_DIRECTORY))
        {
            // File is not a directory
            return false;
        }

        return true;
#else
        struct stat info;

        if (stat(folderName, &info) != 0)
        {
            return false;
        }

        return (info.st_mode & S_IFDIR) != 0;
#endif // #ifdef WIN32
    }

    // Returns true on success, false on error
    bool createFolder(std::string folderName)
    {
        std::list<std::string> folderLevels;
        char *c_str = (char *)folderName.c_str();
        // Point to end of the string
        char *strPtr = &c_str[strlen(c_str) - 1];

        if ((*strPtr != '\\') && (*strPtr != '/'))
        {
            do
            {
                strPtr--;
            } while ((*strPtr != '\\') && (*strPtr != '/'));
            strPtr[1] = 0;
        }
        // Create a list of the folders which do not currently exist
        do
        {
            if (folderExists(c_str))
            {
                break;
            }
            // Break off the last folder name, store in folderLevels list
            do
            {
                strPtr--;
            } while ((*strPtr != '\\') && (*strPtr != '/') && (strPtr >= c_str));
            folderLevels.push_front(std::string(strPtr + 1));
            strPtr[1] = 0;
        } while (strPtr >= c_str);
        /*
        if (_chdir(c_str))
        {
            return false;
        }
        */

        std::string fullPath = c_str;

        // Create the folders iteratively
        for (std::list<std::string>::iterator it = folderLevels.begin(); it != folderLevels.end(); it++)
        {
            fullPath.append(*it);
#ifdef WIN32
            if (CreateDirectory(toWideString(fullPath.c_str()).c_str(), NULL) == 0)
            {
                return false;
            }
#else
            mode_t mode = 0755;
            int ret = mkdir(fullPath.c_str(), mode);

            if (ret < 0)
            {
                return false;
            }
#endif // #ifdef WIN32
            //_chdir(it->c_str());
        }

        return true;
    }

    /**
     * @brief Checks that the key path exists
     */
    bool keyPathExists(const std::string &file_path)
    {
        std::ostringstream sstr("");
        size_t last = file_path.find_last_of("/");

        if (last == std::string::npos)
        {
            last = file_path.find_last_of("\\");
        }
        if (last == std::string::npos)
        {
            // Invalid path
            return false;
        }

        std::string path = file_path.substr(0, last);
        struct stat path_info;
        int rc = stat(path.c_str(), &path_info);

        if (rc != 0)
        {
            if (errno == ENOENT || errno == ENOTDIR)
            {
                return false;
            }
        }

        return (path_info.st_mode) & S_IFDIR ? true : false;
    }

    /*
     * Extracts "key-id" & "ciphertext"  from the JSON structure.
     * @param [out] key_id reference to key_id value.
     * @param [out] asset_id reference to asset_id value.
     * @param [out] cipher_text reference to cipher_text value.
     * @param sign_apphash[out] reference to the sign_apphash value.
     * @param data [in] pointer to encrypted data.
     * @param useBase64[in] true value indicates that the json structure is base64 encoded.
     * @return true on success, false otherwise.
     */
    bool getTextFromJsonEncryptionBlock(std::string &key_id, std::string &asset_id, std::string &cipher_text, bool &sign_apphash, const std::string &data, bool useBase64)
    {
        rapidjson::Document document;
        std::string json_str = data;
        Log *p_logger = Log::getInstance();
        bool retVal = false;

        p_logger->printf(Log::Debug, " %s:%d data: %s, useBase64: %d", __func__, __LINE__, data.c_str(), useBase64);
        key_id = "";
        asset_id = "";
        cipher_text = "";
        sign_apphash = false;
        if (!useBase64)
        {
            // "key-id" must be present
            document.Parse(json_str.c_str());
            if (!document.HasParseError())
            {
                if (document.HasMember("key-id"))
                {
                    const rapidjson::Value &key_id_val = document["key-id"];

                    if (!key_id_val.IsNull())
                    {
                        key_id = key_id_val.GetString();
                    }
                }
            }
            else
            {
                p_logger->printf(Log::Error, " %s Failed parsing JSON strcture", __func__);
            }
        }
        else
        {
            // Couldn't find the key-id so perhaps the data is base64 encoded, decode and try again
            size_t s = data.size();
            char *decoded_block = new char[s];

            memset(decoded_block, 0, s);

            int dataLen = base64Decode(data.c_str(), (unsigned char *)decoded_block, (unsigned int)s);

            json_str.assign(decoded_block, dataLen);
            delete[] decoded_block;
            document.Parse(json_str.c_str());
            if (document.HasParseError())
            {
                p_logger->printf(Log::Error, " %s:%d Failed parsing JSON structure", __func__, __LINE__);

                return false;
            }
            if (document.HasMember("key-id"))
            {
                const rapidjson::Value &key_id_val = document["key-id"];

                if (!key_id_val.IsNull())
                {
                    key_id = key_id_val.GetString();
                }
            }
        }
        // KeyId should be obtained by now and must not be empty
        if (key_id.empty())
        {
            p_logger->printf(Log::Error, "Invalid key ID");

            return false;
        }
        p_logger->printf(Log::Debug, " %s KeyId: %s", __func__, key_id.c_str());
        // Asset Id is only present for encrypted private Key when CSR is generated on the device
        if (document.HasMember("asset-id"))
        {
            const rapidjson::Value &asset_id_val = document["asset-id"];
            if (!asset_id_val.IsNull())
            {
                asset_id = asset_id_val.GetString();
            }
        }

        // Get the cipherText "ciphertext" must be present.
        if (document.HasMember("ciphertext"))
        {
            const rapidjson::Value &cipher_text_val = document["ciphertext"];

            if (!cipher_text_val.IsNull())
            {
                cipher_text = cipher_text_val.GetString();
                p_logger->printf(Log::Debug, " %s:%d ciphertext size: %ld", __func__, __LINE__, cipher_text.length());
                retVal = true;
            }
        }
        else
        {
            p_logger->printf(Log::Error, " %s:%d ciphertext is missing in the input json", __func__, __LINE__);
        }

        // Get the optional property that defines whether we need to send a signature for an apphash with the
        // apphash when requesting the encryption key and IV from KeyScaler
        if (document.HasMember("sign-apphash"))
        {
            sign_apphash = document["sign-apphash"].GetBool();
        }

        return retVal;
    }

    bool getTextFromJsonEncryptionBlockWithTpm(const std::string &json, std::string &ciphertext, std::vector<char> &iv)
    {
        Log *p_logger = Log::getInstance();
        bool retVal = false;

        rapidjson::Document document;
        document.Parse(json.c_str());
        if (document.HasParseError())
        {
            p_logger->printf(Log::Error, "Failed parsing JSON structure");
            return false;
        }

        if (document.HasMember("ciphertext"))
        {
            const rapidjson::Value &ciphertext_val = document["ciphertext"];

            if (!ciphertext_val.IsNull())
            {
                ciphertext = ciphertext_val.GetString();
            }
        }

        if (document.HasMember("iv"))
        {
            const rapidjson::Value &iv_b64_val = document["iv"];

            if (!iv_b64_val.IsNull())
            {
                const std::string iv_b64 = iv_b64_val.GetString();
                std::vector<unsigned char> iv_buf(json.size() * 2);
                unsigned int buf_size = base64Decode(iv_b64.c_str(), &iv_buf[0], iv_buf.size());
                iv = std::vector<char>(iv_buf.begin(), iv_buf.begin() + buf_size);
            }
        }

        if (ciphertext.empty() || iv.empty())
        {
            p_logger->printf(Log::Error, "Invalid encryption block");
            return false;
        }

        return true;
    }

    /*
     * Writes pk and cert data to to respective locations.
     * @param [in] pk_path filePath  to be written to.
     * @param [in] pk pointer to raw data to be written at pk_path.
     * @param [out] message to return any errors.
     * @param [in] optional certPath filePath  to be written to.
     * @param [in] cert pointer to raw data to be written at certPath.
     * @return true on success, false otherwise.
     */
    bool writeToFileSystem(const std::string &pk_path, const std::string &pk, std::string &message, const std::string &certPath, const std::string &cert)
    {
        Log *p_logger = Log::getInstance();

        p_logger->printf(Log::Debug, " %s certPath: %s, certSize: %d, pk_path: %s, pkSize: %d", __func__, certPath.c_str(), cert.size(), pk_path.c_str(), pk.size());
        if (pk.size())
        {
            std::ofstream ofs(pk_path.c_str());

            if (!ofs.good())
            {
                message = "Problem writing to file path " + pk_path + "";
                p_logger->printf(Log::Error, " %s %s", __func__, message.c_str());

                return false;
            }
            ofs << pk;
            ofs.close();
        }
        // Write the certificate out to the file path specified
        if (cert.size())
        {
            std::ofstream ofs(certPath.c_str());

            if (!ofs.good())
            {
                message = "Problem writing to file path \\\"" + certPath + "\\\"";
                p_logger->printf(Log::Error, " %s %s", __func__, message.c_str());

                return false;
            }
            ofs << cert;
            ofs.close();
        }

        return true;
    }

    /* Decrypts data stored in file filePath using passed key and iv */
    bool decryptJsonBlockFile(std::string &out_data, bool &sign_apphash, const std::string &key, const std::string &iv, const std::string &file_path, bool key_iv_base64_encoded)
    {
        bool ret = false;
        Log *p_logger = Log::getInstance();

        if (key.empty() || iv.empty())
        {
            p_logger->printf(Log::Error, " %s key or iv is empty..can't proceed with decryption", __func__);

            return false;
        }

        std::string data;
        std::ifstream ifs(file_path.c_str());
        if (!ifs.good())
        {
            p_logger->printf(Log::Error, " %s Problem reading file: %s", __func__, file_path.c_str());

            return false;
        }
        ifs >> data;
        ifs.close();

        std::string extracted_key_id;
        std::string asset_id;
        std::string cipher_text;
        if (getTextFromJsonEncryptionBlock(extracted_key_id, asset_id, cipher_text, sign_apphash, data, false))
        {
            p_logger->printf(Log::Debug, " %s extracted_key_id from file: %s, size: %d", __func__, extracted_key_id.c_str(), extracted_key_id.size());

            std::string base64_decoded_key = key;
            std::string base64_decoded_iv = iv;

            if (key_iv_base64_encoded)
            {
                p_logger->printf(Log::Debug, " %s Key and IV encoded", __func__);
                base64DecodeKeyIV(base64_decoded_key, base64_decoded_iv);
            }
            else
            {
                p_logger->printf(Log::Debug, " %s Key and IV not encoded", __func__);
            }

            dacryptor component;
            component.setInitVector(base64_decoded_iv);
            component.setCryptionKey(base64_decoded_key);
            component.setInputData(cipher_text);
            if (component.decrypt())
            {
                const da::byte *output;
                unsigned int length = 0;

                component.getCryptedData(output, length);
                if (length > 0)
                {
                    out_data.assign((const char *)output, length);
                    ret = true;
                }
                else
                {
                    p_logger->printf(Log::Error, "%s Decryption of PK failed..Decrypted data length is 0 ", __func__);
                }
            }
            else
            {
                p_logger->printf(Log::Error, "%s Decryption of PK failed ", __func__);
            }
        }

        return ret;
    }

    /* Decrypts data stored in file file_path using TPM held key */
    bool decryptJsonBlockFile(std::string &out_data, const std::string &file_path)
    {
        Log *p_logger = Log::getInstance();

        std::string file_content;
        std::ifstream ifs(file_path.c_str());
        if (!ifs.good())
        {
            p_logger->printf(Log::Error, " %s Problem reading file: %s", __func__, file_path.c_str());

            return false;
        }
        ifs >> file_content;
        ifs.close();

        std::string ciphertext;
		std::vector<char> iv;
        if (!getTextFromJsonEncryptionBlockWithTpm(file_content, ciphertext, iv))
        {
            p_logger->printf(Log::Error, " %s Failed to read encryption block", __func__);
            return false;
        }
        auto p_tpm_wrapper = TpmWrapper::getInstance();
        std::vector<char> key;
        if (!p_tpm_wrapper->unseal(file_path, key))
        {
            p_logger->printf(Log::Error, " %s Failed to get key", __func__);
            return false;
        }

        dacryptor component;
        component.setCryptionKey(key);
        component.setInitVector(iv);
        component.setInputData(ciphertext);
        if (!component.decrypt())
        {
            p_logger->printf(Log::Error, "%s Decryption of PK failed ", __func__);
            return false;
        }

        const da::byte *output;
        unsigned int length = 0;

        component.getCryptedData(output, length);
        if (length <= 0)
        {
            p_logger->printf(Log::Error, "%s Decryption of PK failed..Decrypted data length is 0 ", __func__);
            return false;
        }

        out_data.assign((const char *)output, length);
        return true;
    }

    /*
     * Encrypt and writes data to the given filePath.
     * @param [in] data pointer to data to be written.
     * @param [in] key value for encryption.
     * @param [in] iv value for encryption.
     * @param [in] key_id value for encryption.
     * @param [in] asset_id value for encryption.
     * @param [in] file_path storage path for encrypted data.
     * @param [in] key_iv_base64_encoded flag indicating whether to encode key and iv in base64.
     * @return  true on success, false otherwise.
     */
    bool encryptAndStorePK(const std::string &data, const std::string &key, const std::string &iv, const std::string &key_id, const std::string &asset_id, const std::string &file_path, bool key_iv_base64_encoded, bool sign_apphash)
    {
        Log *p_logger = Log::getInstance();

        bool ret = false;
        if (key.empty() || iv.empty())
        {
            p_logger->printf(Log::Error, " %s key or iv is empty, cannot proceed with encryption", __func__);

            return false;
        }

        if (!data.empty())
        {
            dacryptor component;

            if (key_iv_base64_encoded)
            {
                // logger.printf(Log::Information, " %s key: %s, iv: %s", __func__, key.c_str(), iv.c_str());
                std::string newkey = key;
                std::string newiv = iv;

                if (base64DecodeKeyIV(newkey, newiv))
                {
                    component.setInitVector(newiv);
                    component.setCryptionKey(newkey);
                }
                else
                {
                    p_logger->printf(Log::Error, " %s base64DecodeKeyIV failed", __func__);

                    return false;
                }
            }
            else
            {
                component.setInitVector(iv);
                component.setCryptionKey(key);
            }
#ifdef DEBUG_PRINT
            if (!key_iv_base64_encoded)
            {
                std::string base64_encoded_key = key;
                std::string base64_encoded_iv = iv;

                base64EncodeKeyIV(base64_encoded_key, base64_encoded_iv);
                p_logger->printf(Log::Debug, " %s base64_encoded_key: %s, size: %d", __func__, base64_encoded_key.c_str(), base64_encoded_key.length());
                p_logger->printf(Log::Debug, " %s base64_encoded_iv: %s, size: %d", __func__, base64_encoded_iv.c_str(), base64_encoded_iv.length());
            }
#endif // #if DEBUG_PRINT
            component.setInputData(data);
            if (component.encrypt())
            {
                std::string ciphertextJson;
                std::string cryptoStr;
                const da::byte *output;
                unsigned int length;

                component.getCryptedData(output, length);
                cryptoStr.assign((const char *)output, length);
                // logger.printf(Log::Error, " %s Private Key data After encryption: %s, size: %d", __func__, output, length);
                createJsonEncryptionBlock(key_id, asset_id, cryptoStr, ciphertextJson, false, sign_apphash);
                if (!file_path.empty())
                {
                    std::string message;
                    ret = writeToFileSystem(file_path, ciphertextJson, message);
                }
            }
            else
            {
                p_logger->printf(Log::Error, " %s Key Encryption failed", __func__);
            }
        }

        return ret;
    }

    std::string createJsonEncryptionBlockForTpm(const std::string &ciphertext, const std::vector<char> &iv)
    {
        rapidjson::Document root_document;
        root_document.SetObject();
        rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

        root_document.AddMember("ciphertext", rapidjson::StringRef(ciphertext.c_str()), allocator);

        std::vector<char> buf(iv.size() * 2, 0);
        unsigned int sz = base64Encode((unsigned char*)&iv[0], (unsigned int)iv.size(), &buf[0], (unsigned int)buf.size());

        const std::string iv_b64 = std::string(buf.begin(), buf.end());
        root_document.AddMember("iv", rapidjson::StringRef(iv_b64.c_str()), allocator);

        rapidjson::StringBuffer strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
        root_document.Accept(writer);

        return strbuf.GetString();
    }

    bool encryptDataUsingTPM(const std::string &data, const std::string &key_path, std::vector<char> &key, std::vector<char> &iv, std::string &ciphertext)
    {
        const unsigned int AES_CFB_KEY_LENGTH = 32;
        const unsigned int AES_CFB_IV_LENGTH = 16;

        Log *p_logger = Log::getInstance();
        TpmWrapperBase *p_tpm_wrapper = TpmWrapper::getInstance();

        // 128 bit key and iv for use with AES CFB algorithm used by dacryptor
        if (!(p_tpm_wrapper->getRandom(AES_CFB_KEY_LENGTH, key) && p_tpm_wrapper->getRandom(AES_CFB_IV_LENGTH, iv)))
        {
            p_logger->printf(Log::Error, "Failed to generate random bytes using the TPM");
            return false;
        }

        if (!p_tpm_wrapper->createSeal(key_path, key, true))
        {
            p_logger->printf(Log::Error, "Failed to generate seal");
            return false;
        }

        dacryptor component;
        component.setCryptionKey(key);
        component.setInitVector(iv);
        component.setInputData(data);
        if (!component.encrypt())
        {
            p_logger->printf(Log::Error, "Key encryption failed");
            return false;
        }

        const unsigned char* encrypted_data = nullptr;
        unsigned int encrypted_data_length = 0;
        component.getCryptedData(encrypted_data, encrypted_data_length);
		ciphertext = std::string(encrypted_data, encrypted_data + encrypted_data_length);
        return true;
    }

    bool encryptAndStoreUsingTPM(const std::string &plaintext, const std::string &file_path)
    {
        Log *p_logger = Log::getInstance();

        std::vector<char> key, iv;
        std::string ciphertext;
        encryptDataUsingTPM(plaintext, file_path, key, iv, ciphertext);

        std::string encrypted_data_json = createJsonEncryptionBlockForTpm(
            ciphertext,
            iv);

        std::string message;
        return writeToFileSystem(file_path, encrypted_data_json, message);
    }

    /*
    * Pass the filePath and private key name and certificate name.
    */
    void getPKAndCertName(std::string &pk_name, std::string &cert_name, const std::string &file_path)
    {
        Log *p_logger = Log::getInstance();
        p_logger->printf(Log::Debug, " %s filePath: %s", __func__, file_path.c_str());

        pk_name = file_path;
        cert_name = file_path;

        // Check if cert/key name is specified in the path ..else generate one.
        if (file_path.length())
        {
            size_t len = file_path.length();
            size_t pos = file_path.find_last_of("/");

            if (pos == std::string::npos)
            {
                pos = file_path.find_last_of("\\");
            }
            if (pos == (len - 1))
            {
                pk_name.append("deviceKey.pem");
                cert_name.append("deviceCert.cert");
                return;
            }
        }
        // Private Key
        if (pk_name.find(".pem") == std::string::npos)
        {
            pk_name.append(".pem");
        }

        // Certificate
        if (cert_name.find(".cert") == std::string::npos)
        {
            cert_name.append(".cert");
        }
    }

    /*
     * For a given filePath/string calculate sha256 and base64Encode
     * @param input  [in] string value or fileName to calculate hash value of.
     * @param isFile [in] bool value indicating type of first parameter (string or fileName)
     * @param encode [in] bool value if true base64 encode the hashed output
     * @param hashedVal [out] string value contains hashed output
     */
    bool sha256AndEncode(const std::string &input, bool isFile, bool encode, std::string &hashedVal)
    {
        std::string data = input;
        hashedVal.clear();

        if (isFile)
        {
            std::ifstream ifs(input.c_str());
            std::stringstream buffer;
            buffer << ifs.rdbuf();
            data = buffer.str();
            if (data.empty())
            {
                Log::getInstance()->printf(Log::Error, "%s Unable to read data from %s", __func__, input.c_str());
                return false;
            }
        }

        if (DeviceAuthorityBase *da = DeviceAuthority::getInstance())
        {
            hashedVal = da->doDigestSHA256(data);
            if (hashedVal.empty())
            {
                return false;
            }
        }
        else
        {
            Log::getInstance()->printf(Log::Error, "%s Unable to obtain DeviceAuthority instance", __func__);
            return false;
        }

        if (encode)
        {
            unsigned int encodedBlockLength = ((unsigned int)hashedVal.size()) * 2u;
            std::vector<char> encodedBlock(encodedBlockLength);
            int len = base64Encode((const unsigned char *)hashedVal.c_str(), (unsigned int)hashedVal.length(), &encodedBlock[0], encodedBlockLength);
            hashedVal.assign(&encodedBlock[0], len);
        }

        return true;
    }

    const std::string generateHMAC(const std::string &data, const std::string &key, bool base64_encode)
    {
        if (key.empty())
        {
            return "";
        }

        unsigned int len;
        unsigned char out[EVP_MAX_MD_SIZE];

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OpenSSL 1.0.x
        HMAC_CTX hmac;
        HMAC_CTX_init(&hmac);
        HMAC_Init_ex(&hmac, reinterpret_cast<const unsigned char*>(key.c_str()), key.length(), EVP_sha256(), nullptr);
        HMAC_Update(&hmac, reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
        HMAC_Final(&hmac, out, &len);
        HMAC_CTX_cleanup(&hmac);

#elif OPENSSL_VERSION_NUMBER < 0x30000000L
// OpenSSL 1.1.x
        HMAC_CTX *p_ctx = HMAC_CTX_new();
        HMAC_Init_ex(p_ctx, reinterpret_cast<const unsigned char*>(key.c_str()), key.length(), EVP_sha256(), nullptr);
        HMAC_Update(p_ctx, reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
        HMAC_Final(p_ctx, out, &len);
        HMAC_CTX_free(p_ctx);
#else
// OpenSSL 3.0.x
        HMAC(EVP_sha256(), reinterpret_cast<const unsigned char*>(key.c_str()), key.length(), reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), out, &len);
#endif
        const auto signature = std::string(reinterpret_cast<char*>(out), len);

        return base64_encode ? toBase64(signature) : signature;
    }

    unsigned char randomChar()
    {
#if __cplusplus > 199711L
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        return static_cast<unsigned char>(dis(gen));
#else
        srand(time(NULL));
        return rand() % (UCHAR_MAX + 1);
#endif // #if __cplusplus > 199711L
    }

    std::string generateHex(const unsigned int len)
    {
        std::stringstream ss;
#if __cplusplus > 199711L
        for (auto i = 0; i < len; i++)
        {
            auto rc = randomChar();
            std::stringstream hexstream;
            hexstream << std::hex << int(rc);
            auto hex = hexstream.str();
            ss << (hex.length() < 2 ? '0' + hex : hex);
        }
#else
        for (unsigned int i = 0; i < len; i++)
        {
            unsigned char rc = randomChar();
            std::stringstream hexstream;
            hexstream << std::hex << int(rc);
            std::string hex = hexstream.str();
            ss << (hex.length() < 2 ? '0' + hex : hex);
        }
#endif // #if __cplusplus > 199711L
        return ss.str();
    }

    std::string generateUUID()
    {
        std::stringstream ss;
        ss << generateHex(4) << "-"
           << generateHex(2) << "-"
           << generateHex(2) << "-"
           << generateHex(2) << "-"
           << generateHex(6);
        return ss.str();
    }

    uint64_t getTimeStamp()
    {
#if __cplusplus > 199711L
        using namespace std::chrono;
        system_clock::time_point tp = system_clock::now();
        system_clock::duration dtn = tp.time_since_epoch();
        return dtn.count();
#else
        std::time_t result = std::time(nullptr);
        return result;
#endif // #if __cplusplus > 199711L
    }

#if defined(ALLOW_COMPRESSION)
    #include "zlib.h"
    const std::string deflate(const std::string &data)
    {
        uLong sz = compressBound((uLong)data.size());
        std::vector<Bytef> buf(data.size() + 1, 0);

        if (Z_OK != compress(&buf[0], &sz, (const unsigned char *)data.c_str(), (uLong)data.size()))
        {
            throw std::runtime_error("Zlib compression failed");
        }

        return std::string(buf.begin(), buf.begin() + sz);
    }
#else
    const std::string deflate(const std::string &data)
    {
        return data;
    }
#endif

    const std::string getFileNameFromPath(const std::string& path)
    {
        size_t pos = path.find_last_of("/\\");
        if (pos == std::string::npos)
        {
            return "";
        }
        return path.substr(pos + 1);
    }
}
