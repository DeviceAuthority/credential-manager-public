/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a string of bytes.
 */

#include <vector>
#include <sstream>
#include <fstream>
#include <cstring>
#include <sys/types.h>
#if defined(WIN32)
#else
#include <unistd.h>
#include <dlfcn.h>
#endif // #if defined(WIN32)
#include <sys/stat.h>
#include <errno.h>
#include "base64.h"
#include "dahttpclient.hpp"
#include "deviceauthority.hpp"
#include "configuration.hpp"
#include "dacryptor.hpp"
#include "da.hpp"
#include "utils.hpp"
#include "constants.hpp"
#include "tpm_wrapper.hpp"

#ifndef MAX_PATH
#define MAX_PATH 256
#endif // #ifndef MAX_PATH


void da_Lib_init()
{
    /*
     * libcurl has a global constant environment that you must set up and maintain while using libcurl.
     * This essentially means you call curl_global_init(3) at the start of your program and curl_global_cleanup(3) at the end.
     * It is required that the functions be called when no other thread in the program is running.
     */
    //DAHttpClient::init();
}

//https://linux.die.net/man/3/libcurl
void da_Lib_cleanup()
{
    /*
     * libcurl has a global constant environment that you must set up and maintain while using libcurl.
     * This essentially means you call curl_global_init(3) at the start of your program and curl_global_cleanup(3) at the end.
     * It is required that the functions be called when no other thread in the program is running.
     */
    //DAHttpClient::terminate();
}




// TODO: Move to utils once ipworks dependency is resolved
/* Gets path of the binary from the pid*/
bool getProcessInfoFromPid(const int pid, std::string &exePath)
{
    char dest[MAX_PATH];
    std::ostringstream command;
    bool result = false;

    memset(dest, 0, sizeof(dest));
#if defined(WIN32)
#else
    command << "/proc/" << pid << "/exe";

    std::string path = command.str();

    if (readlink(path.c_str(), dest, MAX_PATH) == -1)
    {
        Log::getInstance()->printf(Log::Error, "%s Could not get path of the executable for pid::%d ", __func__, pid);
    }
    else
    {
        exePath.assign(dest);
        result = true;
    }
#endif // #if defined(WIN32)

    return result;
}


bool getAppHash(std::string &hash)
{
    std::string execPath;
    bool result = false;
#if defined(WIN32)
#else
    //printf("\n %s Process identifier is %d", __func__, getpid());
    unsigned int pid = ::getpid();

    if (!getProcessInfoFromPid(pid, execPath))
    {
        // Unable to get process information by pid
        return false;
    }
#endif // #if defined(WIN32)
    if ( utils::sha256AndEncode(execPath, true, true, hash) )
    {
        result = true;
        Log::getInstance()->printf(Log::Debug, " %s hash value is (between :: markers) ::%s::", __func__, hash.c_str());
    }
    else
    {
        Log::getInstance()->printf(Log::Error, " %s sha256AndEncode failed", __func__);
    }
    /*
    std::string  hash2;
    std::string str= "TestHashStr";

    hashed = sha256AndEncode(str,false,true,hash2);
    logger.printf(Log::Error, "%s Test hash is %s", __func__, hash2.c_str());
    */

    return result;
}

/*
 * Prerequisite : export "DACONFIG" environment variable to point to the config file containing "DAUserID" & "DAAPIURL".
 * Gets key&iv pair from the DAE based on the "keyID" and "assetId" values from the encrypted data o decrypt the corresponding cipher_text.
 * @param keyId input value containing KeyId of the encrypted Data
 * @param assetId input value containing assetId of the encrypted Data
 * @param sign_apphash If true, the request for key and iv must contain a HMAC signature of the apphash
 * @param keyout return value containing key info
 * @param ivout return value containing iv info
 */
bool getInfoFromDAE(std::string& key_id, const std::string& asset_id, bool sign_apphash, std::string& keyout, std::string& ivout)
{
#if __STDC_WANT_SECURE_LIB__
    size_t requiredSize = 0;
    char *env_p = NULL;

    getenv_s(&requiredSize, NULL, 0, "DACONFIG");
    if (requiredSize > 0)
    {
        env_p = new char[(requiredSize * sizeof(char)) + 1];
        if (!env_p)
        {
            Log::getInstance()->printf(Log::Error, " Unable to allocate memory", __func__);

            return false;
        }
        // Get the value of the DACONFIG environment variable.
        getenv_s(&requiredSize, env_p, requiredSize, "DACONFIG");
    }
    else
    {
        Log::getInstance()->printf(Log::Debug, " environment variable 'DACONFIG' not defined", __func__);

        return false;
    }
#else
    const char *env_p = getenv("DACONFIG");
#endif // #if __STDC_WANT_SECURE_LIB__

    if (key_id.empty() || asset_id.empty())
    {
        Log::getInstance()->printf(Log::Error, " %s KeyID or assetId is empty, nothing to fetch", __func__);

        return false;
    }
    // Calculate application hash.(Wira indicated that this could be pushed in the DDKG by the agent as Key:Value pair instead of exposing in JSON)
    std::string app_hash("");

    if (!getAppHash(app_hash))
    {
        Log::getInstance()->printf(Log::Error, " %s Could not calculate appHash", __func__);

        return false;
    }
    if (!env_p)
    {
        Log::getInstance()->printf(Log::Error, " %s No config file specified for DA configs", __func__);

        return false;
    }
    //printf("\n %s Your configuration file path is %s", __func__, env_p);
    if (!config.parse(env_p))
    {
        Log::getInstance()->printf(Log::Error, " %s Failed parsing of config file: %s", __func__, env_p);
#if defined(WIN32)
        // Only on Windows platform we need to destroy env_p buffer
        delete [] env_p;
        env_p = NULL;
#endif // #if defined(WIN32)

        return false;
    }
#if defined(WIN32)
    // Only on Windows platform we need to destroy env_p buffer
    delete [] env_p;
    env_p = NULL;
#endif // #if defined(WIN32)

    const std::string DAUser = config.lookup(CFG_DAUSERID);
    const std::string DAAPIURL = config.lookup(CFG_DAAPIURL);
    std::string CRYPTOPROVIDER = config.lookup(CFG_KEYSTORE_PROVIDER);

    if (DAUser.empty() || DAAPIURL.empty())
    {
        Log::getInstance()->printf(Log::Error, " %s Did you remember to set DACONFIG for the config file path? .\"DAUserID\" or \"DAAPIURL\" is not set.", __func__);

        return false;
    }
    if (CRYPTOPROVIDER.empty())
    {
        CRYPTOPROVIDER = "SunPKCS11-NSS";
    }
    //printf("\n %s DAUserID %s", __func__, DAUser.c_str());
    //printf("\n %s DAAPIURL %s", __func__, DAAPIURL.c_str());

    std::string authkey("");
    std::string authiv("");
    std::string message("");
    const std::string device_name("");
    DeviceAuthorityBase *p_da_instance = DeviceAuthority::getInstanceForApp(DAUser, DAAPIURL, device_name, CRYPTOPROVIDER);
    DAHttpClient *p_http_client_obj = new DAHttpClient(p_da_instance->userAgentString());
    // Authorize the application making request using appHash
    std::string daJSON = p_da_instance->authoriseTheApp(key_id, authkey, authiv, message, app_hash, sign_apphash, asset_id, p_http_client_obj);

    // p_da_instance->destroyInstance();
    // Parse and decrypt Key&IV
    if (daJSON.empty())
    {
        Log::getInstance()->printf(Log::Error, " %s identifyAndAuthorise failed with error: %s ", __func__, message.c_str());
        delete p_http_client_obj;
        p_http_client_obj = NULL;

        return false;
    }

    rapidjson::Document json;
    DAErrorCode rc = ERR_OK;
    std::string jsonResponse("");
    std::string apiurl = DAAPIURL;

    apiurl.append("/key/app");

    rc = p_http_client_obj->sendRequest(DAHttp::ReqType::ePOST, apiurl, jsonResponse, daJSON);

    //printf("\n%s:%d jsonResponse: %s", __func__, __LINE__, jsonResponse.c_str());
    delete p_http_client_obj;
    p_http_client_obj = NULL;
    if ((rc == ERR_OK) && jsonResponse.length())
    {
        json.Parse<0>(jsonResponse.c_str());
        if (json.HasParseError())
        {
            Log::getInstance()->printf(Log::Error, " %s:%d Bad responseData %s \n", __func__, __LINE__, jsonResponse.c_str());
            rc =  ERR_BAD_DATA;

            return false;
        }
    }
    if (rc != ERR_OK)
    {
        std::ostringstream oss;

        oss << "Connect to API '" << DAAPIURL << "' has failed with HTTP client error code: " << rc;
        Log::getInstance()->printf(Log::Error," %s  %s ", __func__, oss.str().c_str());

        return false;
    }
    if (!json.IsNull())
    {
        bool decode = utils::base64DecodeKeyIV(authkey, authiv);

        if (decode)
        {
            // Get key
            if (json.HasMember("message"))
            {
                const rapidjson::Value& msgVal = json["message"];

                if (!msgVal.IsNull())
                {
                    if (msgVal.HasMember("errorMessage"))
                    {
                        const rapidjson::Value& errMsgVal = msgVal["errorMessage"];

                        if (!errMsgVal.IsNull())
                        {
                            std::string error = errMsgVal.GetString();

                            Log::getInstance()->printf(Log::Error, " %s:%d Failed to obtain encrypted Key & IV from DAE. Reason: %s", __func__, __LINE__ , error.c_str());
                        }

                        return false;
                    }
                    if (msgVal.HasMember("key"))
                    {
                        const rapidjson::Value& keyVal = msgVal["key"];

                        if (!keyVal.IsNull())
                        {
                            std::string keyFromJson = keyVal.GetString();

                            if (keyFromJson.length())
                            {
                                dacryptor keyCryptor;

                                keyCryptor.setCryptionKey(authkey);
                                keyCryptor.setInitVector(authiv);
                                keyCryptor.setInputData(keyFromJson);
                                if (keyCryptor.decrypt())
                                {
                                    const unsigned char *output;
                                    unsigned int length = 0;

                                    keyCryptor.getCryptedData(output, length);
                                    keyout.assign((const char *)output, length);
                                    //printf("\n %s:%d Obtained Key Length::%d::", __func__, __LINE__, length);
                                }
                                else
                                {
                                    Log::getInstance()->printf(Log::Error, " %s:%d Unable to decrypted key.", __func__, __LINE__);

                                    return false;
                                }
                            }
                        }
                    }
                    if (keyout.empty())
                    {
                        Log::getInstance()->printf(Log::Error," %s Unable to obtain decrypted key for further use.",__func__ );

                        return false;
                    }
                    if (msgVal.HasMember("iv"))
                    {
                        const rapidjson::Value& ivVal = msgVal["iv"];

                        if (!ivVal.IsNull())
                        {
                            std::string ivFromJson = ivVal.GetString();

                            if (ivFromJson.length() > 0)
                            {
                                dacryptor ivCryptor;

                                ivCryptor.setCryptionKey(authkey);  // Use the key generated above
                                ivCryptor.setInitVector(authiv);    // Use the iv generated above
                                ivCryptor.setInputData(ivFromJson);
                                if (ivCryptor.decrypt())
                                {
                                    const unsigned char * output;
                                    unsigned int length = 0;
                                    ivCryptor.getCryptedData( output, length);
                                    ivout.assign((const char*) output, length);

                                    return true;
                                }
                                Log::getInstance()->printf(Log::Error, " %s:%d Unable to decrypted iv.", __func__ , __LINE__);
                            }
                        }
                    }
                    if (ivout.empty())
                    {
                        Log::getInstance()->printf(Log::Error, " %s Unable to obtain decrypted iv for further use.", __func__);
                    }
                }
            } // end of if message
        } // end of decode
    } // if (!json.IsNull())

    return false;
}

bool getRawData(std::string file_name, std::string &raw_data)
{
    auto tpm_wrapper = TpmWrapper::getInstance();
    if (tpm_wrapper->initialised() && tpm_wrapper->isTpmAvailable())
    {
        if (!utils::decryptJsonBlockFile(raw_data, file_name))
        {
            const std::string error_message = "Failed to decrypt with key and iv from DAE.";
            Log::getInstance()->printf(Log::Error, " %s %s", __func__, error_message.c_str());

            return false;
        }

        return true;
    }

    //printf("\n%s file_name: %s", __func__, file_name.c_str());
#if __STDC_WANT_SECURE_LIB__
    FILE *fp;
    errno_t err = fopen_s(&fp, file_name.c_str(), "r");

    UNREFERENCED_PARAMETER(err);
#else
    FILE *fp = fopen(file_name.c_str(), "r");
#endif // #if __STDC_WANT_SECURE_LIB__

    if (fp == NULL)
    {
        Log::getInstance()->printf(Log::Error, " %s Unable to obtain decrypted iv for further use.", __func__);

        return false;
    }
    // Get the file size
    fseek(fp, 0, SEEK_END);

    long file_size = ftell(fp);

    if (file_size == 0)
    {
        rewind(fp);
        fclose(fp);

        return false;
    }

    char *file_data = new char[file_size + 1];

    if (file_data == NULL)
    {
        Log::getInstance()->printf(Log::Error, " %s Unable to allocate memory %ld byte(s).", __func__, (file_size + 1));
        rewind(fp);
        fclose(fp);

        return false;
    }
    rewind(fp);

    auto r = fread(file_data, sizeof(char), file_size, fp);
    std::string buffer(file_data, r);

    delete [] file_data;
    // Close file after reading data
    rewind(fp);
    fclose(fp);
    // Check for DA encryption
    if (r && (buffer.find("ciphertext") != std::string::npos))
    {
        std::string extracted_key_id;
        std::string extracted_asset_id;
        std::string cipher_text;
        bool sign_apphash;

        if (utils::getTextFromJsonEncryptionBlock(extracted_key_id, extracted_asset_id, cipher_text, sign_apphash, buffer, false))
        {
            std::string key;
            std::string iv;

            //printf("\nExtractedkeyId: %s, extracted_asset_id: %s", extracted_key_id.c_str(), extracted_asset_id.c_str());
            /*
             * libcurl has a global constant environment that you must set up and maintain while using libcurl.
             * This essentially means you call curl_global_init(3) at the start of your program and curl_global_cleanup(3) at the end.
             * It is required that the functions be called when no other thread in the program is running.
             */
            //DAHttpClient::init();
            bool result = getInfoFromDAE(extracted_key_id, extracted_asset_id, sign_apphash, key, iv);

            //printf("\n key:%s,iv:%s\n", key.c_str(), iv.c_str());
            if (result && key.size() && iv.size())
            {
                // key & iv is not empty
                //printf("extracted_key_id: %s, keyForDecrypt: %s, iv: %s, cipher_text: %s\n", extracted_key_id.c_str(), key.c_str(), iv.c_str(), cipher_text.c_str());
                dacryptor component;

                component.setInitVector(iv);
                component.setCryptionKey(key);
                component.setInputData(cipher_text);
                if (component.decrypt())
                {
                    unsigned int length = 0;
                    const unsigned char *decryptedBuff = NULL;

                    component.getCryptedData(decryptedBuff, length);
                    if (length > 0)
                    {
                        raw_data.assign((const char *)decryptedBuff, length);
                        //printf("\n%s:%d rawData: %s", __func__, __LINE__, raw_data.c_str());

                        return true;
                    }
                }
                else
                {
                    Log::getInstance()->printf(Log::Error, " %s:%d DA Decryption failed.", __func__, __LINE__);
                }
            }
            else
            {
                Log::getInstance()->printf(Log::Error, " %s:%d Unable to get Key & IV.", __func__, __LINE__);
            }
            //DAHttpClient::terminate();
        }
        else
        {
            Log::getInstance()->printf(Log::Error, " %s:%d getTextFromJsonEncryptionBlock failed.", __func__, __LINE__);
        }
    }
    else
    {
        // TODO: comment this
        Log::getInstance()->printf(Log::Error," %s:%d This is a normal file, not DA encrypted.", __func__, __LINE__);
    }

    return false;
}

#if 0
int LoadCertificateAndPrivateKey(SSL_CTX **ctx,char * certPath, int certType, char *filePath, int fileType)
{
   int  retVal = 0;
   return retVal;
   Log::getInstance()->printf(Log::Debug," %s:%d LoadCertificateAndPrivateKey certPath:%s filePath:%s*****************\n .",__func__,__LINE__,certPath,filePath);
   Log::getInstance()->printf(Log::Debug," %s:%d Original context::%p *****************\n .",__func__,__LINE__,(*ctx));
   int j;
   BIO *in=NULL;
   X509 *x=NULL;

   std::string rawBuff;
   if(getRawData(certPath,rawBuff)) //IN DA format..parsed and decrypted
   {
    if (rawBuff.size() > 0)
    {
      Log::getInstance()->printf(Log::Debug,"%s:%d !!!! Decryption SUCCESS !!!!  plaintext::%s", __func__,__LINE__,rawBuff.c_str());
      in = BIO_new_mem_buf((void *)rawBuff.c_str(),rawBuff.size());
      if (in == NULL)
      {
        Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,ERR_R_BUF_LIB);
        if (x != NULL) X509_free(x);
        if (in != NULL) BIO_free(in);
        return retVal;
      }
    }//if(file_size)
    else
    {
      Log::getInstance()->printf(Log::Error,"%s \n !!!! Decryption failed!!!!", __func__);
      if (x != NULL) X509_free(x);
      if (in != NULL) BIO_free(in);
      return retVal;
    }
  }
  else
  {
    Log::getInstance()->printf(Log::Error," %s:%d This could be a normal file..not DA encrypted  OR  DA Decryption failed\n",__func__,__LINE__);
  }
  //Original implementation with FILE BIO pointer.
  if(in == NULL) //gotta be a normal non-da encrypted cert file
  {
    Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
    in = BIO_new(BIO_s_file_internal());
    if (in == NULL)
    {
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE,ERR_R_BUF_LIB);
      if (x != NULL) X509_free(x);
      if (in != NULL) BIO_free(in);
      return retVal;
    }
    if (BIO_read_filename(in,certPath) <= 0)
    {
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE,ERR_R_SYS_LIB);
      if (x != NULL) X509_free(x);
      if (in != NULL) BIO_free(in);
      return retVal;
    }
  }
  //common for both
  if (certType == SSL_FILETYPE_ASN1)
  {
    Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
    j=ERR_R_ASN1_LIB;
    x=d2i_X509_bio(in,NULL);
  }
  else if (certType == SSL_FILETYPE_PEM)
  {
    Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
    j=ERR_R_PEM_LIB;
    x=PEM_read_bio_X509(in,NULL,(*ctx)->default_passwd_callback,(*ctx)->default_passwd_callback_userdata);
  }
  else
  {
    Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
    SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE,SSL_R_BAD_SSL_FILETYPE);
    if (x != NULL) X509_free(x);
    if (in != NULL) BIO_free(in);
    return retVal;
  }
  if (x == NULL)
  {
    Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
    SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE,j);
    if (x != NULL) X509_free(x);
    if (in != NULL) BIO_free(in);
    return retVal;
  }

  Log::getInstance()->printf(Log::Debug," %s:%d  Key file:%s Overridden API *****************\n .",__func__,__LINE__,certPath);
  BIO *in2=NULL;
  EVP_PKEY *pkey2=NULL;
  std::string rawBuff2;
  //char *fileNew = "/home/mohini/Downloads/AWS_SDK/certs/device_decrypted.pem";
  if(getRawData(filePath,rawBuff2)) //IN DA format..parsed and decrypted
  {
    if(rawBuff2.size() > 0)
    {
      Log::getInstance()->printf(Log::Debug," !!!! Decryption SUCCESS !!!! %s plaintext::%s", __func__,rawBuff2.c_str());
      in2 = BIO_new_mem_buf((void *)rawBuff2.c_str(),rawBuff2.size());
      if (in2 == NULL)
      {
        Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,ERR_R_BUF_LIB);
        if (in2 != NULL) BIO_free(in2);
        return retVal;
      }
    }
    else
    {
      Log::getInstance()->printf(Log::Error," %s !!!! Decryption failed!!!!", __func__);
      if (in2 != NULL) BIO_free(in2);
      return retVal;
    }
  }
  else
  {
   Log::getInstance()->printf(Log::Debug," %s This is a normal file..not DA encrypted in: %p\n",__func__,in2);
  }

  if(in2 == NULL)//gotta be a normal non-da encrypted cert file
  {
    Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
    in2=BIO_new(BIO_s_file_internal());
    if (in2 == NULL)
    {
      SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,ERR_R_BUF_LIB);
       if (in2 != NULL) BIO_free(in2);
       return retVal;
    }
    Log::getInstance()->printf(Log::Debug,"%s:%d Reading file:%s\n .",__func__,__LINE__,filePath);
    if (BIO_read_filename(in2,filePath) <= 0)
    {
      SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,ERR_R_SYS_LIB);
       if (in2 != NULL) BIO_free(in2);
       return retVal;
    }
  }
  if (fileType == SSL_FILETYPE_PEM)
  {
   Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
    j=ERR_R_PEM_LIB;
    pkey2=PEM_read_bio_PrivateKey(in2,NULL,(*ctx)->default_passwd_callback,(*ctx)->default_passwd_callback_userdata);
  }
  else if (fileType == SSL_FILETYPE_ASN1)
  {
    Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
    j = ERR_R_ASN1_LIB;
    pkey2 = d2i_PrivateKey_bio(in2,NULL);
  }
  else
  {
    Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
    SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,SSL_R_BAD_SSL_FILETYPE);
     if (in2 != NULL) BIO_free(in2);
     return retVal;
  }
  if (pkey2 == NULL)
  {
    Log::getInstance()->printf(Log::Debug," %s:%d Overridden API *****************\n .",__func__,__LINE__);
    SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,j);
     if (in2 != NULL) BIO_free(in2);
     return retVal;
  }

  //Creating new context and returning
   //Attach cert to context
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  if (SSL_library_init() < 0) {
    Log::getInstance()->printf(Log::Error,"****SSL_library_init  Failed - Unable to create SSL Context");
        return retVal;
  }
  const SSL_METHOD *method = TLSv1_2_method();
  if ((*ctx = SSL_CTX_new(method)) == NULL) {

    Log::getInstance()->printf(Log::Error," ****SSL_CTX_new Failed - Unable to create SSL Context");
        return retVal;
  }

  retVal =SSL_CTX_use_certificate(*ctx,x);
  Log::getInstance()->printf(Log::Error," %s:%d New context::%p *****************\n .",__func__,__LINE__,(*ctx));

  if (x != NULL) X509_free(x);
  if (in != NULL) BIO_free(in);

  if(!retVal)
  {
   Log::getInstance()->printf(Log::Error," %s:%d SSL_CTX_use_certificate failed ......\n .",__func__,__LINE__);

   EVP_PKEY_free(pkey2);
   return retVal;
  }

  retVal =SSL_CTX_use_PrivateKey(*ctx,pkey2);
  EVP_PKEY_free(pkey2);


  if(!retVal)
  {
   Log::getInstance()->printf(Log::Error," %s:%d SSL_CTX_use_PrivateKey failed ......\n .",__func__,__LINE__);
   if (in2 != NULL) BIO_free(in2);
  }

  Log::getInstance()->destroyInstance();
  return retVal;
}
#endif

/*
 *  1. Remove hardcoded key&iv. Get this info from the keyscaler with "KeyId".
 *
 *  SSL_CTX_use_certificate_file() loads the first certificate stored in file into ctx. The formatting type of the certificate must be specified from the known types SSL_FILETYPE_PEM, SSL_FILETYPE_ASN1.
 */
/* SSL_CTX_use_certificate_chain_file() loads a certificate chain from file into ctx.
The certificates must be in PEM format and must be sorted starting with the subject's certificate (actual client or server certificate),
followed by intermediate CA certificates if applicable, and ending at the highest level (root) CA. There is no corresponding function working on a single SSL object. */
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *newfile, int type)
{
    // const char *newfile = "/home/mohini/Downloads/AWS_SDK/certs/certFromDecodedPem.cert";
    Log::getInstance()->printf(Log::Debug, " %s:%d Overridden API newfile: %s.", __func__, __LINE__, newfile);

    std::string rawBuff;
    int j = 0;
    int ret = 0;
    BIO *in = NULL;
    X509 *x = NULL;

    if (getRawData(newfile, rawBuff)) // IN DA format, parsed and decrypted
    {
        if (rawBuff.length() > 0)
        {
            Log::getInstance()->printf(Log::Debug, " %s:%d Decryption SUCCESS! plaintext: %s\n- END OF PLAIN TEXT -", __func__, __LINE__, rawBuff.c_str());

            in = BIO_new_mem_buf((void *)rawBuff.c_str(),rawBuff.size());
            if (in == NULL)
            {
                SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
                goto end;
            }
        }
        else
        {
            Log::getInstance()->printf(Log::Error, " %s Decryption failed!", __func__);
            goto end;
        }
    }
    else
    {
        Log::getInstance()->printf(Log::Error, " %s:%d This could be a normal file, not DA encrypted OR DA Decryption failed", __func__, __LINE__);
    }
    // Original implementation with FILE BIO pointer.
    if (in == NULL)
    {
        // Gotta be a normal non-da encrypted cert file
        //printf( "\n %s:%d Overridden API *****************\n .",__func__,__LINE__);
        in = BIO_new(BIO_s_file_internal());
        if (in == NULL)
        {
            SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
            goto end;
        }
        if (BIO_read_filename(in, newfile) <= 0)
        {
            SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
            goto end;
        }
    }
    // Common for both
    if (type == SSL_FILETYPE_ASN1)
    {
        //printf("\n %s:%d Overridden API *****************\n", __func__, __LINE__);
        j = ERR_R_ASN1_LIB;
        x = d2i_X509_bio(in, NULL);
    }
    else if (type == SSL_FILETYPE_PEM)
    {
        //printf("\n %s:%d Overridden API *****************\n", __func__, __LINE__);
        j = ERR_R_PEM_LIB;
        x = PEM_read_bio_X509(in, NULL, SSL_CTX_default_passwd_callback(ctx), SSL_CTX_default_passwd_callback_userdata(ctx));
    }
    else
    {
        //printf("\n %s:%d Overridden API *****************\n", __func__, __LINE__);
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }
    if (x == NULL)
    {
        //printf( "\n %s:%d Overridden API *****************\n", __func__, __LINE__);
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE,j);
        goto end;
    }
    //printf( "\n %s:%d Overridden API *****************\n", __func__, __LINE__);
    ret = SSL_CTX_use_certificate(ctx, x);
    //printf( "\n %s:%d Overridden API *****************\n .",__func__,__LINE__);
end:
    if (x != NULL)
    {
        X509_free(x);
    }
    if (in != NULL)
    {
        BIO_free(in);
    }
    //printf("\n %s:%d Overridden API ***************** ret:%d\n", __func__, __LINE__, ret);
    // Fix for issue where call to da function clobbers ssl context
    OpenSSL_add_all_algorithms();
    Log::getInstance()->destroyInstance();

    return(ret);
}

/*
 * SSL_CTX_use_PrivateKey() adds pkey as private key to ctx
 */
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *newfile, int type)
{
    //const char* newfile = "/home/mohini/Downloads/AWS_SDK/certs/pkFromDecoded.pem";
    Log::getInstance()->printf(Log::Debug, " %s:%d Key file: %s, Overridden API *****************\n", __func__, __LINE__, newfile);

    std::string rawBuff;
    int j = 0;
    int ret = 0;
    BIO *in = NULL;
    EVP_PKEY *pkey = NULL;

    if (getRawData(newfile, rawBuff))
    {
        // IN DA format, parsed and decrypted
        if (rawBuff.size() > 0)
        {
            Log::getInstance()->printf(Log::Debug, " %s:%d Decryption SUCCESS! plaintext: %s\n- END OF PLAIN TEXT -", __func__, __LINE__, rawBuff.c_str());
            in = BIO_new_mem_buf((void *)rawBuff.c_str(), rawBuff.size());
            if (in == NULL)
            {
                //printf("\n %s:%d Overridden API *****************\n", __func__, __LINE__);
                SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
                goto end;
            }
        }
        else
        {
            Log::getInstance()->printf(Log::Error," %s Decryption failed!", __func__);
            goto end;
        }
    }
    else
    {
        Log::getInstance()->printf(Log::Debug, " %s This is a normal file, not DA encrypted in: %p\n", __func__, in);
    }
    if (in == NULL)
    {
        // Gotta be a normal non-da encrypted cert file
        //printf("\n %s:%d Overridden API *****************\n", __func__, __LINE__);
        in = BIO_new(BIO_s_file_internal());
        if (in == NULL)
        {
            SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,ERR_R_BUF_LIB);
            goto end;
        }
        //printf("\n %s:%d Reading file: %s\n", __func__, __LINE__, newfile);
        if (BIO_read_filename(in, newfile) <= 0)
        {
            SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
            goto end;
        }
    }
    if (type == SSL_FILETYPE_PEM)
    {
        //printf("\n %s:%d Overridden API *****************\n", __func__, __LINE__);
        j = ERR_R_PEM_LIB;
        pkey = PEM_read_bio_PrivateKey(in, NULL, SSL_CTX_default_passwd_callback(ctx), SSL_CTX_default_passwd_callback_userdata(ctx));
    }
    else if (type == SSL_FILETYPE_ASN1)
    {
        // printf( "\n %s:%d Overridden API *****************\n", __func__, __LINE__);
        j = ERR_R_ASN1_LIB;
        pkey = d2i_PrivateKey_bio(in, NULL);
    }
    else
    {
        //printf("\n %s:%d Overridden API *****************\n", __func__, __LINE__);
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }
    if (pkey == NULL)
    {
        // printf( "\n %s:%d Overridden API *****************\n",__func__,__LINE__);
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, j);
        goto end;
    }
    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
    //printf("\n %s:%d Overridden API ret:%d*****************\n", __func__, __LINE__, ret);

end:
    if (in != NULL)
    {
        BIO_free(in);
    }
    // Fix for issue where call to da function clobbers ssl context
    OpenSSL_add_all_algorithms();
    Log::getInstance()->destroyInstance();

    return ret;
}
