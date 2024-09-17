#ifndef DA_HPP
#define DA_HPP

#include "openssl/evp.h"
#include <openssl/pem.h>
#include "openssl/ssl.h"
#include <openssl/err.h>
#include <openssl/buffer.h>
#include "dasslcompat.h"

/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 *  Helper functions used by all agents.
 */
 #ifdef __cplusplus
 extern "C"
 {
 #endif 
   int LoadCertificateAndPrivateKey(SSL_CTX **ctx,char * certPath,int certType, char *filePath, int fileType);
 #ifdef __cplusplus
 }
 #endif
 
#endif
