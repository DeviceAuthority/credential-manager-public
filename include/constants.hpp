#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

#define PROTO_ALWAYSON                      "alwayson"
#define PROTO_HTTP                          "http"
#define PROTO_MQTT                          "mqtt"

#define CRYPTO_OP_ENCRYPT                   "ENCRYPT"
#define CRYPTO_OP_DECRYPT                   "DECRYPT"

#define DATADIR_C2S                         "C2S"
#define DATADIR_S2C                         "S2C"

#define METHOD_GET                          "GET"
#define METHOD_POST                         "POST"

#define OP_CI                               "ci"
#define OP_DA                               "da"
#define OP_DR                               "dr"
#define OP_CPD                              "cpd"

#define TYPE_DDKG                           "ddkg"

#define JSON_ACCOUNT_ID                     "account-id"
#define JSON_ACTIVE                         "active"
#define JSON_AUTHENTICATED                  "authenticated"
#define JSON_CHALLENGE                      "challenge"
#define JSON_CRYPTIONPATH                   "cryptionPath"
#define JSON_CRYPTOKEYROTATIONPOLICY        "cryptoKeyRotationPolicy"
#define JSON_DOMAIN                         "domain"
#define JSON_ENCRYPTIONPOLICYID             "encryptionPolicyId"
#define JSON_ERRORMESSAGE                   "errorMessage"
#define JSON_ID                             "id"
#define JSON_IV                             "iv"
#define JSON_GATEWAYCRYPTOOPERATION         "gatewayCryptoOperation"
#define JSON_GATEWAYDATADIRECTION           "gatewayDataDirection"
#define JSON_GATEWAYMETHODTYPE              "gatewayMethodType"
#define JSON_KEY                            "key"
#define JSON_MESSAGE                        "message"
#define JSON_NAME                           "name"
#define JSON_OP                             "op"
#define JSON_OPS                            "ops"
#define JSON_PAYLOADTYPE                    "payLoadType"
#define JSON_POLICIES                       "policies"
#define JSON_POLICYCRYPTOOPERATION          "policyCryptoOperation"
#define JSON_POLICYDATADIRECTION            "policyDataDirection"
#define JSON_POLICYMETHODTYPE               "policyMethodType"
#define JSON_POLICYPAYLOADTYPE              "policyPayLoadType"
#define JSON_POLS                           "pols"
#define JSON_PRIORITY                       "priority"
#define JSON_PROPERTYNAMES                  "propertyNames"
#define JSON_RES                            "res"
#define JSON_RESP                           "resp"
#define JSON_RESULT                         "result"
#define JSON_STATUS_CODE                    "status_code"
#define JSON_TS                             "ts"
#define JSON_TYPE                           "type"
#define JSON_UDI                            "udi"
#define JSON_UDI_TYPE                       "udi-type"
#define JSON_URLPATTERN                     "urlPattern"
#define JSON_USER_AGENT                     "user-agent"
#define JSON_ROTATIONPOLICY_T               "t"
#define JSON_ROTATIONPOLICY_SCHEDULE        "schd"
#define JSON_ROTATIONPOLICY_UPDATE          "upd"
#define JSON_ROTATIONPOLICY_RETRY           "rtry"

// Keyscale Edge/Central JSON specific
/*
metaDataJSON
# node: Valid values are edge and central
# crypto_provider: Valid values are SunPKCS11-NSS, nCipherKM, LunaProvider (default SunPKCS11-NSS)
# mimetype: Valid values are text/xml, application/json
{
    "node": "edge",
    "crypto_provider": "SunPKCS11-NSS",
    "mimetype": "text/xml",
    "device_role": "DA Agent",
    "device_meta": [
        {
            "name": "deviceId",
            "value": "deviceIdValue"
        }
    ],
    "ch": "",
    "keyAndExpiry": {
		"key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAopT6xCVGP4KPCOXXwUD8\n3aM1lWREhMaNP783mZ2ob3EN9P2cSACKSTtGid++qDgb3l1mbX3sru4eWWOXTw/w\nkJSdhTZoON0UVABTvgX/31JS1QXYO0cog0UYn5QGOwgxTi5WsbqDPGoOumFw5gC8\n2wjEoiF2BMMb6IgHZ7224q0cE/x6BAY7K56PxzsjtpLbtJJaFk7wxhvRe3v6EE1E\no8SVPCeSXEXKZa/clFNs9lMggqD8b6V7ilO91ooVsstxAsc/lF1qt403n0mluD9y\nb67EFHZXL1anR4V8GvAH4yQZlzgDowO+2G6J8SngREAv+LBDloCKiDE/bvkPpMEH\nmwIDAQAB\n-----END PUBLIC KEY-----\n",
		"expiry": "2021-05-15T20:18:29.807+00:00"
	},
	"signature": {
		"algo": "RSA",
		"data": "zOwdjUEKkzE41ISdQ98CyRj64fxeToatMiLGa61g6AAhk9H64zL0ZEKAfG/U7BSp0qxavZP9Hkbu8JoUhyhkUqxwYEuW/O6i2NiDa6nqDyN6QSmcplGv/CwPwozQW/KP9bQJ9QW2rkcTHDTOtnjaUvnt67jV+EaWmzYE2ngHWWn2tOBGq+tnElIqA3lNCModsuZBrA8BoKpPRw96om4sPbsmNsrdxrHPWxgh1qxTCpAI+bafdb7ytgBWwZLNybbBu0/QJ9sWeTzisr+osWtiW6iv3MvnUzt0Xrf4X1pDfzrvdbUYFEv0bf0JMis6zyXfJ/XgmkSizkOWWzddtoWN7Q==",
		"encoding": "Base64",
		"sig_algo": "SHA1withRSA"
	}
}
*/
#define JSON_NODE                           "node"
#define JSON_CRYPTO_PROVIDER                "crypto_provider"
#define JSON_MIMETYPE                       "mimetype"
#define JSON_DEVICE_ROLE                    "device_role"
#define JSON_DEVICE_META                    "device_meta"
#define JSON_DEVICE_META_NAME               JSON_NAME
#define JSON_DEVICE_META_VALUE              "value"
#define JSON_CH                             "ch"
#define JSON_KEY_AND_EXPIRY                 "keyAndExpiry"
#define JSON_EXPIRY                         "expiry"
#define JSON_SIGNATURE                      "signature"
#define JSON_SIGNATURE_ALGO                 "algo"
#define JSON_SIGNATURE_DATA                 "data"
#define JSON_SIGNATURE_ENCODING             "encoding"
#define JSON_SIGNATURE_SIGN_ALGO            "sig_algo"

// NOTE: Any new configuration keys added, you must add them as well in configuration.cpp
//       inside the class constructor when building validationMap_ hashmap table
#define CFG_KEYCACHETIMEOUT                 "KEYCACHETIMEOUT"
#define CFG_POLICYCACHETIMEOUT              "POLICYCACHETIMEOUT"
#define CFG_POLICYCACHESIZEITEMS            "POLICYCACHESIZEITEMS"
#define CFG_MAXIMUMCLIENTS                  "MAXIMUMCLIENTS"
#define CFG_LOCALPORTNUMBER                 "LOCALPORTNUMBER"
#define CFG_REMOTEHOSTADDRESS               "REMOTEHOSTADDRESS"
#define CFG_REMOTEPORTNUMBER                "REMOTEPORTNUMBER"
#define CFG_LOGFILENAME                     "LOGFILENAME"
#define CFG_SYSLOGHOST                      "SYSLOGHOST"
#define CFG_SYSLOGPORT                      "SYSLOGPORT"
#define CFG_AVERAGEPROCESSINGTIMEEVERY      "AVERAGEPROCESSINGTIMEEVERY"
#define CFG_MEMORYBLOCKSIZE                 "MEMORYBLOCKSIZE"
#define CFG_KEEPCONNECTIONBUFFERS           "KEEPCONNECTIONBUFFERS"
#define CFG_INBOUNDSOCKETQUEUELENGTH        "INBOUNDSOCKETQUEUELENGTH"
#define CFG_ACCEPTUPTOCONNECTIONSPERLOOP    "ACCEPTUPTOCONNECTIONSPERLOOP"
#define CFG_SLEEPPERIOD                     "SLEEPPERIOD"
#define CFG_PROXYCONNLOOPWAIT               "PROXYCONNLOOPWAIT"
#define CFG_ENABLEALWAYSONPROXY             "ENABLEALWAYSONPROXY"
#define CFG_TCPINPUTBUFFERSIZE              "TCPINPUTBUFFERSIZE"
#define CFG_TCPOUTPUTBUFFERSIZE             "TCPOUTPUTBUFFERSIZE"
#define CFG_WORKERTHREADS                   "WORKERTHREADS"
#define CFG_APIURL                          "APIURL"
#define CFG_CERTIFICATEPATH                 "CERTIFICATEPATH"
#define CFG_CERTIFICATEPASSWORD             "CERTIFICATEPASSWORD"
#define CFG_APIKEY                          "APIKEY"
#define CFG_APISECRET                       "APISECRET"
#define CFG_DBHOST                          "DBHOST"
#define CFG_DBNAME                          "DBNAME"
#define CFG_DBUSER                          "DBUSER"
#define CFG_DBPASSWORD                      "DBPASSWORD"
#define CFG_DAUSERID                        "DAUSERID"
#define CFG_DAAPIURL                        "DAAPIURL"
#define CFG_DEVICENAME                      "DEVICENAME"
#define CFG_LOCATION                        "LOCATION"
#define CFG_MODE                            "MODE"
#define CFG_USEBASE64                       "USEBASE64"
#define CFG_ROTATELOGAFTER                  "ROTATELOGAFTER"
#define CFG_ENDDACONFIG                     "ENDDACONFIG"
#define CFG_REMOTECONNECTIONSSL             "REMOTECONNECTIONSSL"
#define CFG_UDI                             "UDI"
#define CFG_UDITYPE                         "UDITYPE"
#define CFG_KEYSCALER_PROTOCOL              "KEYSCALER_PROTOCOL"
#define CFG_KEYSCALER_HOST                  "KEYSCALER_HOST"
#define CFG_KEYSCALER_PORT                  "KEYSCALER_PORT"
#define CFG_SCHEDULEINTERVAL                "SCHEDULEINTERVAL"
#define CFG_UPDATEINTERVAL                  "UPDATEINTERVAL"
#define CFG_RETRYINTERVAL                   "RETRYINTERVAL"
#define CFG_CAPATH                          "CAPATH"
#define CFG_CAFILE                          "CAFILE"
#define CFG_IDCTOKENTTL                     "IDCTOKENTTL"
#define CFG_USEIDCTOKEN                     "USEIDCTOKEN"
#define CFG_KEYSTORE_PROVIDER               "KEYSTORE_PROVIDER"
#define CFG_PROTOCOL                        "PROTOCOL"
#define CFG_MQTT_TOPIC_IN                   "MQTT_TOPIC_IN"
#define CFG_MQTT_TOPIC_OUT                  "MQTT_TOPIC_OUT"
#define CFG_DEVICE_ROLE                     "DEVICEROLE"
#define CFG_BROKER_HOST                     "BROKERHOST"
#define CFG_BROKER_PORT                     "BROKERPORT"
#define CFG_DAPLATFORM                      "DAPLATFORM"
#define CFG_USERAGENT                       "USERAGENT"
#if defined(WIN32)
#define CFG_DDKGLIB                         "DDKGLIB"
#define CFG_LIBDIR                          "LIBDIR"
#define CFG_FORCE_MS_ENHANCED_PROVIDER      "FORCE_MS_ENHANCED_PROVIDER"
#define CFG_STORE_FULL_CERTIFICATE_CHAIN    "STORE_FULL_CERTIFICATE_CHAIN"
#endif // #if defined(WIN32)
#define CFG_METADATAFILE                    "METADATAFILE"
#define CFG_PROXY							"PROXY"
#define CFG_PROXY_CREDENTIALS				"PROXY_CREDENTIALS"
#define CFG_POLL_TIME_FOR_REQUESTED_DATA	"POLL_TIME_FOR_REQUESTED_DATA"
#define CFG_HEARTBEAT_INTERVAL_S            "HEARTBEAT_INTERVAL_S"
#define CFG_EVENT_NOTIFICATION_LIBRARIES    "EVENT_NOTIFICATION_LIBRARIES"
#define CFG_RETRY_AUTHORIZATION_INTERVAL_S  "RETRY_AUTHORIZATION_INTERVAL_S"
#define CFG_USE_UDI_AS_DEVICE_IDENTITY      "USE_UDI_AS_DEVICE_IDENTITY"
#define CFG_EXT_DDKG_UDI_PROPERTY           "EXT_DDKG_UDI_PROPERTY"
#define CFG_DDKG_ROOT_FS                    "DDKG_ROOT_FS"
#define CFG_OSSL_PROVIDER                   "OSSL_PROVIDER"

// Keyscaler Edge/Central Specific Config
#define CFG_NODE                            "NODE"

#define DEVICE_ROLE                         "DA Agent"
#define EDGE_NODE                           "edge"
#define CENTRAL_NODE                        "central"

#define IDC_PATH                            "/idc"
#define REGISTER_PATH                       "/register"
#define CHALLENGE_PATH                      "/challenge"

#endif // #ifndef CONSTANTS_HPP
