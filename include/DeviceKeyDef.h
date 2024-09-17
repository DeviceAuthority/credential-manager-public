/**
 * \file /mavericks/lib/include/DeviceKeyDef.h
 *
 * \brief Definition of dynamic device key generator error codes and constants
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

#ifndef __DEVICEKEYDEF_H__
#define __DEVICEKEYDEF_H__

#ifndef _STDDEF_H
#include <stddef.h>
#endif // #ifndef _STDDEF_H

#define DEVICEKEY_MAGIC_MARKER          "NADDKv"

// JSON key(s) found in DDKG (since version 4.0.13.116) response
#define JSON_DDK_TEXT                   "ddk"
#define JSON_IOT_TEXT                   "iot"
#define JSON_DKD_TEXT                   "dkd"
#define JSON_KEY_ID_TEXT                "key_id"
#define JSON_KEY_TEXT                   "key"
#define JSON_IV_TEXT                    "iv"
#define JSON_TID_TEXT                   "tid"

// JSON key(s) found in input parameter
#define JSON_ACCEPT_TEXT                "accept"
#define JSON_ALGO_TEXT                  "algo"
#define JSON_BIT_TEXT                   "bit"
#define JSON_CH_TEXT                    "ch"
#define JSON_CT_TEXT                    "ct"
#define JSON_COMPRESS_TEXT              "compress"
#define JSON_DEVICE_META_TEXT           "device_meta"
#define JSON_DEVICE_ROLE_TEXT           "device_role"
#define JSON_ENCODING_TEXT              "encoding"
#define JSON_KEYGEN_TEXT                "keygen"
#define JSON_HV_TEXT                    "hv"
#define JSON_SIZE_TEXT                  "size"
#define JSON_TVK_TEXT                   "tvk"
#define JSON_TYPE_TEXT                  "type"
#define JSON_NAME_TEXT                  "name"
#define JSON_VALUE_TEXT                 "value"
#define JSON_DOMAIN_TEXT                "domain"
#define JSON_PROTO_TEXT                 "proto"
#define JSON_PORT_TEXT                  "port"
#define JSON_CRYPTO_PROVIDER_TEXT       "crypto_provider"
#define JSON_MIMETYPE_TEXT              "mimetype"
#define JSON_NODE_TEXT                  "node"
#define JSON_KEY_AND_EXPIRY_TEXT        "keyAndExpiry"
#define JSON_EXPIRY_TEXT                "expiry"
#define JSON_SIGNATURE_TEXT             "signature"
#define JSON_DATA_TEXT                  "data"
#define JSON_SIG_ALGO_TEXT              "sig_algo"

#define EDGE_NODE                       "edge"
#define CENTRAL_NODE                    "central"
#define NCIPHERKM_PROVIDER              "nCipherKM"
#define SAFENET_PROVIDER                "LunaProvider"
#define PKCS11_NSS_PROVIDER             "SunPKCS11-NSS"

/**
 * \enum eDeviceKeyStatus
 *
 * \brief Status codes return from Dynamic Device Key API call
 */
typedef enum
{
    kDDKStatusUdiUnknownError = -799,
    kDDKStatusUdiInvalidValue = -701,
    kDDKStatusKSEPublicKeyNotFoundError = -609,
    kDDKStatusKSCPublicKeyExpiredError = -608,
    kDDKStatusKSCDataSignatureError = -607,
    kDDKStatusKSCDigestError = -606,
    kDDKStatusKSCDigestInitError = -605,
    kDDKStatusKSCMemoryAllocError = -604,
    kDDKStatusKSCValidateSignatureError = -603,
    kDDKStatusKSCCipherInitializationError = -602,
    kDDKStatusKSCPublicKeyNotFoundError = -601,
    kDDKStatusSigPlusEncodeDecodeError = -505,
    kDDKStatusSigPlusMemoryAllocError = -504,
    kDDKStatusSigPlusCipherError = -503,
    kDDKStatusSigPlusCipherInitializationError = -502,
    kDDKStatusSigPlusPublicKeyNotFoundError = -501,
    kDDKStatusSigPlusInvalidSignatureError = -501,
    kDDKStatusSecureStorageError = -400,
    kDDKStatusSecureKeyPairEncodeDecodeError = -356,
    kDDKStatusSecureKeyPairSignatureError = -356,
    kDDKStatusSecureKeyPairCipherError = -355,
    kDDKStatusSecureKeyPairMemoryAllocError = -354,
    kDDKStatusSecureKeyPairImportError = -353,
    kDDKStatusSecureKeyPairNotFoundError = -352,
    kDDKStatusSecureKeyPairFactoryNotInitializedError = -351,
    kDDKStatusSecureKeyPairGenerationError = -350,
    kDDKStatusKeyPairGenerationError = -300,
    kDDKStatusBadVersion = -200,
    kDDKStatusBadExtDDKGPropertyJSON = -174,
    kDDKStatusDeprecatedDeviceKeyVersion = -173,
    kDDKStatusDeprecatedChallengeVersion = -172,
    kDDKStatusBadMetadataJSON = -171,
    kDDKStatusBadJSON = -170,
    kDDKStatusDeviceKeyMarshallException = -152,
    kDDKStatusBadDeviceKeyMarshall = -151,
    kDDKStatusBadDeviceKey = -150,
    kDDKStatusBadChallengeMissingSignature = -136,
    kDDKStatusBadChallengeMissingRotatedKeySignature = -135,
    kDDKStatusBadRotatedKeySignature = -134,
    kDDKStatusBadErrorSerializerBase64EncodingLogBuffer = -133,
    kDDKStatusBadErrorSerializerCipherAsymmetricEncryption = -132,
    kDDKStatusBadErrorSerializerInitCipherAsymmetric = -131,
    kDDKStatusBadErrorSerializerBasePublicKey = -130,
    kDDKStatusBadDDKEnvelopeBase64EncodingNonce = -129,
    kDDKStatusBadDDKEnvelopeCipherAsymmetricNonceEncryption = -128,
    kDDKStatusBadDDKEnvelopeDigest = -127,
    kDDKStatusBadDDKEnvelopeInitDigest = -126,
    kDDKStatusBadDDKEnvelopeCipherAsymmetricEncryption = -125,
    kDDKStatusBadDDKEnvelopeCipherSymmetricEncryption = -124,
    kDDKStatusBadDDKEnvelopeBasePublicKey = -123,
    kDDKStatusBadDDKEnvelopeInitCipherAsymmetric = -122,
    kDDKStatusBadDDKEnvelopeInitCipherSymmetric = -121,
    kDDKStatusBadChallengeKeyRecipe = -120,
    kDDKStatusBadSyntheticKey = -119,
    kDDKStatusBadTVKHMACKey = -118,
    kDDKStatusBadTVKDigestInstance = -117,
    kDDKStatusBadTVKAlgo = -116,
    kDDKStatusBadBase64EncodingTVK = -115,
    kDDKStatusBadTVKValue = -114,
    kDDKStatusBadDeviceKeyEnvelope = -113,
    kDDKStatusBadChallengeNoComponentFound = -112,
    kDDKStatusBadDeprecatedChallengeBody = -111,
    kDDKStatusBadChallengeUnmarshall = -110,
    kDDKStatusBadChallengeBody = -109,
    kDDKStatusBadChallengeBodyCipherKeyAndIV = -108,
    kDDKStatusBadRotatedKey = -107,
    kDDKStatusBadRotatedKeyCipherKeyAndIV = -106,
    kDDKStatusBadDeviceKeyInstance = -105,
    kDDKStatusBadChallengeVersion = -104,
    kDDKStatusBadChallengeSignature = -103,
    kDDKStatusBadChallengeFormat = -102,
    kDDKStatusBadChallengeKey = -101,
    kDDKStatusBadChallenge = -100,
    kDDKStatusRunningOnJailBroken = -51,
    kDDKStatusRunningOnVM = -50,            ///< function detected a virtualize machine
    kDDKStatusImportDeviceKeyXMLError = -14,///< function is unable to import device key from XML
    kDDKStatusDeviceIdReadFailure = -13,    ///< function detected a problem when storing device IDs
    kDDKStatusDeviceIdWriteFailure = -12,   ///< function detected a problem when storing device IDs
    kDDKStatusBadHostResolution = -11,      ///< function detected a host name cannot be resolved
    kDDKStatusBadDependencyLibrary = -10,   ///< function detected either dependency library signature not verified or API list not validated
    kDDKStatusBadAppSignature = -9,         ///< function detected bad app signature format, ie. asterisk found not at end
    kDDKStatusInvalidHost = -8,             ///< function detected the plugin is invoked not from a valid host
    kDDKStatusInvalidInvocation = -7,       ///< function detected the DLL is invoked by unknown process
    kDDKStatusSessionNotInitialized = -6,   ///< function detected DDKG Session has not been initialized
    kDDKStatusDeprecated = -5,              ///< function has been deprecated
    kDDKStatusNotImplemented = -4,          ///< function is not supported or implemented
    kDDKStatusInvalidSession = -3,          ///< function is unable to instantiate DDKG session
    kDDKStatusOutOfMemory = -2,             ///< function is unable to allocate required memory
    kDDKStatusError = -1,                   ///< function encountered an error during execution
    kDDKStatusSuccess = 0,                  ///< function returned successfully
    kDDKStatusFuzzy,                        ///< function generated suspicious data
    kDDKStatusFuzzyCrack,                   ///< function generated data that looks like a hacking attempt
    kDDKStatusCrack,                        ///< function generated data that is certainly the result of a hack attempt
    kDDKStatusUnsupported,                  ///< function is not supported on this hardware/software platform
    kDDKStatusUnavailable,                  ///< function queries hardware that is supported but not available on this system
    kDDKStatusFailedToRetrieveFPData

} eDeviceKeyStatus;

typedef void (*NAUDADDK_GLOBALINIT_PROC)();
typedef void (*NAUDADDK_GLOBALCLEANUP_PROC)();
typedef int (*NAUDADDK_GETDEVICETID_PROC)(char **deviceTid);
typedef int (*NAUDADDK_GETDEVICEKEY_PROC)(char **deviceKey, const char *acceptMimeType);
typedef int (*NAUDADDK_GETDEVICEKEYOAEP_PROC)(const char *cryptoProvider, char **deviceKey, const char *acceptMimeType);
typedef int (*NAUDADDK_GETDEVICEKEYEX_PROC)(const char *json, char **deviceKey);
typedef int (*NAUDADDK_GETDEVICEKEYWITHCHALLENGE_PROC)(const char *challenge, char **deviceKey);
typedef int (*NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEROLE_PROC)(const char *challenge, const char *deviceRole, char **deviceKey);
typedef int (*NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEMETA_PROC)(const char *challenge, const char *deviceMetaJson, char **deviceKey);
typedef int (*NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEROLE_FORSIGPLUS_PROC)(const char *challenge, const char *deviceRole, char **deviceKey);
typedef int (*NAUDADDK_GETDEVICEKEYWITHCHALLENGE_FOREDGE_PROC)(const char *metaDataJSON, char **deviceKey);
typedef int (*NAUDADDK_GETSIGNATURE_FORSIGPLUS_PROC)(const char *keyId, const char *key, const char *iv, char **signatureJSON);
typedef int (*NAUDADDK_FREEDEVICEKEY_PROC)(char **deviceKey);
typedef int (*NAUDADDK_GETDEVICEKEYVERSION_PROC)(char **deviceKeyVersion);
typedef int (*NAUDADDK_GETUSERAGENTSTRING_PROC)(char **userAgent);
typedef int (*NAUDADDK_GETPLATFORMSTRING_PROC)(char **platform);
typedef void (*NAUDADDK_FREEBUFFER_PROC)(char **buffer);
typedef int (*NAUDADDK_INSTALLKBDWATCHDOG_PROC)();
typedef int (*NAUDADDK_UNINSTALLKBDWATCHDOG_PROC)();
typedef int (*NAUDADDK_DOCIPHER_AES_CFB128_PROC)(const char *key, const size_t cbKey, const char *iv, const size_t cbIv, const unsigned char *input, unsigned long cbInput, unsigned char **output, int mode);
typedef int (*NAUDADDK_DODIGEST_SHA256_PROC)(const char *input, const size_t cbInput, unsigned char **output);
typedef int (*NAUDADDK_GETDEVICEKEY_FOREDGE_PROC)(const char *metadataJSON, char **deviceKey);
typedef int (*NAUDADDK_SETUDI_PROC)(const char *udi, size_t len);
typedef int (*NAUDADDK_GETUDI_PROC)(char **udi);
typedef int (*NAUDADDK_EXTDDKG_SETUDIPROPERTYNAME)(const char *property_name, size_t len);
typedef int (*NAUDADDK_SETROOTFS_PROC)(const char *root_fs, size_t len);

#endif // #ifndef __DEVICEKEYDEF_H__
