/**
 * \file /mavericks/lib/include/DeviceKeyAPI.h
 *
 * \brief Definition of dynamic device key generator C-style APIs
 *
 * \author Copyright (c) 2005-2006 by Uniloc USA Inc. ALL RIGHTS RESERVED.
 * \author Copyright (c) 2014-2016 by DeviceAuthority Inc. ALL RIGHTS RESERVED.
 * \author Copyright (c) 2016 by Device Authority Ltd. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to Device Authority Ltd. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from Device Authority Ltd.
 *
 * \version 1.0
 *
 * \date October 5, 2011
 * \date January 1, 2014
 *
 */

#if _MSC_VER > 1000
#pragma once
#endif // #if _MSC_VER > 1000

#ifndef __DEVICEKEYAPI_H__
#define __DEVICEKEYAPI_H__

#include "DeviceKeyDef.h"

//#define UDADDKDLL_EXPORTS

#if defined(_WINDOW)
#define OSCALL WINAPI
#else
#if defined(__OS2__)
#define OSCALL _System
#else
#define OSCALL
#endif // #if defined(__OS2__)
#endif // #if defined(_WINDOW)

#if defined(UDADDKDLL_EXPORTS)
#define UDADDKDLL_API __declspec(dllexport)
#elif defined(UDADDKDLL_IMPORTS)
#define UDADDKDLL_API __declspec(dllimport)
#else
#define UDADDKDLL_API
#endif // #ifdef UDADDKDLL_EXPORTS

#ifdef __cplusplus
extern "C" {
#endif // #ifdef __cplusplus

/**
 * Global initialization and cleanup
 *
 * \param none
 *
 * \return none
 */
UDADDKDLL_API void OSCALL naudaddk_globalinit();

UDADDKDLL_API void OSCALL naudaddk_globalcleanup();

UDADDKDLL_API void OSCALL naudaddk_initopenssl();

UDADDKDLL_API void OSCALL naudaddk_deinitopenssl();

/**
 * \fn int naudaddk_getdevicetid(char **deviceTid)
 * \brief Gets the device TId (Tenant Id) and returns it in out parameter deviceTid
 *
 * \param deviceTid a pointer to a char * - null-terminated string device TId value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicetid(char **deviceTid);

/**
 * \fn int naudaddk_getdevicetidex(const char *json, char **deviceTid)
 * \brief Gets the device TId (Tenant Id) and returns it in out parameter deviceTid
 *
 * \param json a pointer to a char * - contains a null-terminated JSON string
 * \param deviceTid a pointer to a char * - contains a null-terminated string device TId value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicetidex(const char *json, char **deviceTid);

/**
 * \fn int naudaddk_getdevicekey(char **deviceKey, const char *acceptMimeType)
 * \brief Generates a generic device Id key and returns it in out parameter deviceKey
 *
 * \param deviceKey a pointer to a char * - null-terminated string encoded generic device Id key value
 * \param acceptMimeType a pointer to a char * - null-terminated string MIME type string such as text/xml
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekey(char **deviceKey, const char *acceptMimeType);

/**
 * \fn int naudaddk_getdevicekeyoaep(const char *cryptoProvider, char **deviceKey, const char *acceptMimeType)
 * \brief Generates a generic device Id key and returns it in out parameter deviceKey
 *
 * \param cryptoProvider a pointer to a char * - null-terminated string crypto provider name
 * \param deviceKey a pointer to a char * - null-terminated string encoded generic device Id key value
 * \param acceptMimeType a pointer to a char * - null-terminated string MIME type string such as text/xml
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekeyoaep(const char *cryptoProvider, char **deviceKey, const char *acceptMimeType);

/**
 * \fn int naudaddk_getdevicekeyex(const char *json, char **deviceKey)
 * \brief Generates a dynamic device key and returns it in out parameter deviceKey
 *
 * \param json a pointer to a char * - null-terminated JSON string
 * \param deviceKey a pointer to a char * - null-terminated string encoded dynamic device key value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekeyex(const char *json, char **deviceKey);

/**
 * \fn int naudaddk_getdevicekeyex_hv(const char *json, char **deviceKey, BOOL withHostValidation)
 * \brief Generates a dynamic device key and returns it in out parameter deviceKey
 *
 * \param json a pointer to a char * - null-terminated JSON string
 * \param deviceKey a pointer to a char * - null-terminated string encoded dynamic device key value
 * \param withHostValidation a boolean - TRUE means with host verification, FALSE means without host verification
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekeyex_hv(const char *json, char **deviceKey, BOOL withHostValidation);

/**
 * \fn int naudaddk_getdevicekeywithchallenge(const char *challenge, char **deviceKey)
 * \brief Generates a dynamic device key and returns it in out parameter deviceKey
 *
 * \param challenge a pointer to a string - null-terminated string challenge
 * \param deviceKey a pointer to a char * - null-terminated string encoded dynamic device key value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekeywithchallenge(const char *challenge, char **deviceKey);

/**
 * \fn int naudaddk_getdevicekeywithchallenge_withdevicerole(const char *challenge, const char *deviceRole, char **deviceKey)
 * \brief Generates a dynamic device key and returns it in out parameter deviceKey
 *
 * \param challenge a pointer to a string - null-terminated string challenge
 * \param deviceRole a pointer to a string - null-terminated string device role
 * \param deviceKey a pointer to a char * - null-terminated string encoded dynamic device key value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekeywithchallenge_withdevicerole(const char *challenge, const char *deviceRole, char **deviceKey);

/**
 * \fn int naudaddk_getdevicekeywithchallenge_withdevicemeta(const char *challenge, const char *deviceMetaJson, char  **deviceKey)
 * \brief Generates a dynamic device key and returns it in out parameter deviceKey
 *
 * \param challenge a pointer to a string - null-terminated string challenge
 * \param deviceMetaJson a pointer to a string - null-terminated string device metadata JSON. For example:
 *        {"device_meta" : [{"name":"device-id","value":"device01"}]}
 * \param deviceKey a pointer to a char * - null-terminated string encoded dynamic device key value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekeywithchallenge_withdevicemeta(const char *challenge, const char *deviceMetaJson, char  **deviceKey);

/**
 * \fn int naudaddk_getdevicekeywithchallenge_withdevicerole_forsigplus(const char *challenge, const char *deviceRole, char **deviceKey)
 * \brief Generates a dynamic device key and returns it in out parameter deviceKey
 *
 * \param challenge a pointer to a string - null-terminated string challenge
 * \param deviceRole a pointer to a string - null-terminated string device role
 * \param deviceKey a pointer to a char * - null-terminated string encoded dynamic device key value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekeywithchallenge_withdevicerole_forsigplus(const char *challenge, const char *deviceRole, char **deviceKey);

/**
 * \fn int naudaddk_getdevicekeywithchallengewithtransaction(const char *challenge, const char *transactionValue, char **deviceKey)
 * \brief Generates a dynamic device key and returns it in out parameter deviceKey
 *
 * \param challenge a pointer to a string - null-terminated string challenge
 * \param transactionValue a pointer to a string - null-terminated string current page transaction value
 * \param deviceKey a pointer to a char * - null-terminated string encoded dynamic device key value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekeywithchallengewithtransaction(const char *challenge, const char *transactionValue, char **deviceKey);

/**
 * \fn int naudaddk_getdevicekeywithchallengeobjectwithtransaction(const void *challenge, const char *transactionValue, char **deviceKey)
 * \brief Generates a dynamic device key and returns it in out parameter deviceKey
 *
 * \param challenge a pointer to a void * - challenge reference object
 * \param transactionValue a pointer to a string - null-terminated string current page transaction value
 * \param deviceKey a pointer to a char * - null-terminated string encoded dynamic device key value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekeywithchallengeobjectwithtransaction(const void *challenge, const char *transactionValue, char **deviceKey);

/**
 * \fn int naudaddk_getdevicekeyversion(char **deviceKeyVersion)
 * \brief Gets the DDKG version string and returns it in out parameter deviceKeyVersion
 *
 * \param deviceKeyVersion a pointer to a char * - null-terminated string DDKG version value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekeyversion(char **deviceKeyVersion);

/**
 * \fn int naudaddk_getuseragentstring(char **userAgent)
 * \brief Gets the User-Agent string and returns it in out parameter userAgent
 *
 * \param userAgent a pointer to a char * - null-terminated string User-Agent value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getuseragentstring(char **userAgent);

/**
 * \fn int naudaddk_getplatformstring(char **platform)
 * \brief Gets the platform string and returns it in out parameter platform
 *
 * \param platform a pointer to a char * - null-terminated string platform value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getplatformstring(char **platform);

/**
 * \fn int naudaddk_getsecurekeyid_forsigplus(char **secureKeyId)
 * \brief Gets the secure key-id for PKI SigPlus from secure storage
 *
 * \param secureKeyId a pointer to a char * - null-terminated string secure key-id value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getsecurekeyid_forsigplus(char **secureKeyId);

/**
 * \fn int naudaddk_getsignature_forsigplus(const char *keyId, const char *key, const char *iv, char **signatureJSON)
 * \brief Gets signature for PKI SigPlus given the key-id, key, and iv.
 *
 * \param keyId a pointer to a char * - null-terminated string (crypto) key ID
 * \param key a pointer to a char * - null-terminated string AES key
 * \param iv a pointer to a char * - null-terminated string AES initialization vector
 * \param signatureJSON a pointer to a char * - null-terminated string signature JSON value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getsignature_forsigplus(const char *keyId, const char *key, const char *iv, char **signatureJSON);

/**
 * \fn int naudaddk_freedevicekey(char **deviceKey)
 * \brief Dispose dynamic device key memory acquired from calling getdevicekey()
 *
 * \param deviceKey a pointer to a char * - null-terminated string encoded dynamic device key value
 *        obtained from calling @See getdevicekey()
 */
UDADDKDLL_API int OSCALL naudaddk_freedevicekey(char **deviceKey);

/**
 * \fn void naudaddk_freebuffer(char **buffer)
 * \brief Dispose memory acquired from calling getdevicekeyversion()
 *
 * \param buffer a pointer to a char * - null-terminated string buffer to be freed
 */
UDADDKDLL_API void OSCALL naudaddk_freebuffer(char **buffer);

/**
 * \fn int naudaddk_installkeyboarddog()
 * \brief Install KEYBOARD_LL and MOUSE_LL Hook
 *
 */
UDADDKDLL_API int OSCALL naudaddk_installkeyboarddog();

/**
 * \fn int naudaddk_uninstallkeyboarddog()
 * \brief Uninstall KEYBOARD_LL and MOUSE_LL Hook
 *
 */
UDADDKDLL_API int OSCALL naudaddk_uninstallkeyboarddog();

/**
 * \fn int naudaddk_docipher_aes_cfb128()
 * \brief AES-256 CFB-128 cipher operation
 *
 * \param key a pointer to a char * - null-terminated string AES key
 * \param cbKey length of AES key
 * \param iv a pointer to a char * - null-terminated string AES initialization vector
 * \param cbIv length of AES initialization vector
 * \param input a pointer to a char * - null-terminated string of input to encrypt/decrypt
 * \parem cbInput length of input
 * \param output a pointer to a pointer to a char * - allocated output
 * \param mode cipher operation - encrypt or decrypt
 *
 * \return Integer value indicating the result of the cipher operation
 */
UDADDKDLL_API int OSCALL naudaddk_docipher_aes_cfb128(const char *key, const size_t cbKey, const char *iv, const size_t cbIv, const unsigned char *input, unsigned long cbInput, unsigned char **output, int mode);

/**
 * \fn int naudaddk_dodigest_sha256()
 *
 * \param input a pointer to a char * - null-terminated string of input to compute the digest
 * \parem cbInput length of input
 * \param output a pointer to a pointer to a char * - allocated output for digest
 *
 * \return Integer value indicating the result of the digest operation
 */
UDADDKDLL_API int OSCALL naudaddk_dodigest_sha256(const char *input, const size_t cbInput, unsigned char **output);

/**
 * \fn int naudaddk_getkscpublickey(unsigned char **outPublicKey)
 *
 * \param output a pointer to a pointer to a unsigned char * - allocated output for digest
 *
 * \return Integer value indicating the result of the digest operation
 */
UDADDKDLL_API int OSCALL naudaddk_getkscpublickey(unsigned char **outPublicKey);

/**
 * \fn int naudaddk_getdevicekey_foredge(const char *cryptoProvider, char **deviceKey, const char *acceptMimeType)
 * \brief Generates a generic device Id key and returns it in out parameter deviceKey
 *
 * \param edgeDataJSON a pointer to a char * - null-terminated string keyscaler edge data JSON
 * \param deviceKey a pointer to a char * - null-terminated string encoded generic device Id key value
 *
 * \return eDeviceKeyStatus value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getdevicekey_foredge(const char *metaDataJSON, char **deviceKey);

/**
 * \fn int naudaddk_setudi(const char *udi, size_t len)
 * \brief Stores a unique value which is delivered as the machine UUID if not empty
 *
 * \param udi The unique device identifier - null-terminated string
 * \param len The length of the UDI value
 *
 * \return int Integer value indicating the result of the set operation
 */
UDADDKDLL_API int OSCALL naudaddk_setudi(const char *udi, size_t len);

/**
 * \fn int naudaddk_getudi(char **udi)
 * \brief Gets the UDI and returns it in out parameter udi
 *
 * \param udi a pointer to a char * - null-terminated string udi value
 *
 * \return int Integer value indicating the result of the operation
 */
UDADDKDLL_API int OSCALL naudaddk_getudi(char **udi);

/**
 * \fn int naudaddk_setextddkgudipropertyname(const char *property_name, size_t len)
 * \brief Stores the external DDKG property identifier whose value should be read and used as the UDI of the device
 *
 * \param property_name The external DDKG property UDI identifier - null-terminated string
 * \param len The length of the UDI identifier
 */
UDADDKDLL_API int OSCALL naudaddk_extddkg_setudipropertyname(const char *property_name, size_t len);

/**
 * \fn int naudaddk_setrootfs(const char *root_fs, size_t len)
 * \brief Stores the root filepath for DDKG to use when generating and reading its metadata files
 *
 * \param root_fs The root filesystem path - null-terminated string
 * \param len The length of the root filesystem path
 */
UDADDKDLL_API int OSCALL naudaddk_setrootfs(const char *root_fs, size_t len);

#ifdef __cplusplus
}
#endif // #ifdef __cplusplus

#endif // #ifndef __DEVICEKEYAPI_H__
