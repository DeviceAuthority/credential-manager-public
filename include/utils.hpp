/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 *  Helper functions used by all agents.
 */
#ifndef UTILS_HPP
#define UTILS_HPP

#include <sstream>
#include <fstream>
#include <cstring>
#include <sys/types.h>
#include <string>
#if defined(WIN32)
#else
#include <unistd.h>
#include "tpm_wrapper.hpp"
#endif // #if defined(WIN32)
#include <sys/stat.h>
#include <errno.h>
#include "base64.h"
#include "dacryptor.hpp"
#include "byte.h"
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include "rapidjson/prettywriter.h" // for stringify JSON
#include "rapidjson/stringbuffer.h" // for stringify JSON

namespace utils
{

bool stringEndsWith(std::string const &src, std::string const &ending);
std::string toLower(const std::string& src);
std::string toUpper(const std::string& src);
bool isEmpty(const char *str);
bool isNull(const char *str);
int caseInsensitiveCompare(const char *str1, const char *str2);
char* toUpperCase(char *data, size_t cbData);
void toUpperCase(std::string& data);
char* toLowerCase(char *data, size_t cbData);
void toLowerCase(std::string& data);
void createJsonEncryptionBlock(const std::string& key_id, const std::string &asset_id, const std::string &encrypted_string, std::string &encrypted_json_block, bool use_base64 = false, bool sign_apphash = false);
std::string createJsonEncryptionBlockForTpm(const std::string &ciphertext, const std::vector<char> &iv);
bool getTextFromJsonEncryptionBlock(std::string &key_id, std::string &asset_id, std::string &ciphertext, bool &sign_apphash, const std::string &data, bool use_base64);
bool getTextFromJsonEncryptionBlockWithTpm(const std::string &json, std::string &ciphertext, std::vector<char> &iv);
bool encryptDataUsingTPM(const std::string &data, const std::string &key_path, std::vector<char> &key, std::vector<char> &iv, std::string &ciphertext);
bool encryptAndStorePK(const std::string &data, const std::string &key, const std::string &iv, const std::string &key_id, const std::string &asset_id, const std::string &file_path, bool key_iv_base64_encoded, bool sign_apphash);
bool encryptAndStoreUsingTPM(const std::string &plaintext, const std::string &file_path);
bool writeToFileSystem(const std::string& pk_path, const std::string& pk, std::string& message, const std::string& cert_path = "", const std::string& cert = "");
bool decryptJsonBlockFile(std::string &out_data, bool &sign_apphash, const std::string &key, const std::string &iv, const std::string &file_path, bool key_iv_base64_encoded);
bool decryptJsonBlockFile(std::string &out_data, const std::string &file_path);
bool generateKeyPath(const std::string &filePath,const std::string &name,std::string &PKfileName);
bool createFolder(std::string folderName);
bool keyPathExists(const std::string &filePath);
bool base64DecodeKeyIV(std::string &key, std::string &iv);
bool base64EncodeKeyIV(std::string &key, std::string &iv);
const std::string toBase64(const std::string &data);
const std::string fromBase64(const std::string &data);
bool getProcessInfoFromPid(const int pid, std::string &exePath);
bool sha256AndEncode(const std::string& input, bool isFile, bool encode,std::string &hashedVal);
/**
 * @brief Generate a HMAC signature on a string
 * @param data The data to sign
 * @param key The key to use when generating the HMAC
 * @param base64_encode If true, will base64 encode the HMAC
 * @return The HMAC signature
 */
const std::string generateHMAC(const std::string &data, const std::string &key, bool base64_encode = true);
uint64_t getTimeStamp();
std::string generateUUID();
const std::string deflate(const std::string &data);

/**
 * Pass the filePath and private key name and certificate name.
 */
void getPKAndCertName(std::string &pkName,std::string &certName,const std::string& filePath);

/**
 * Return the file name from a path
 */
const std::string getFileNameFromPath(const std::string& path);

};

#endif // #ifndef UTILS_HPP
