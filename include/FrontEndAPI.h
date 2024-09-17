/**
 * \file /mavericks/lib/include/FrontEndAPI.h
 *
 * \brief Definition of front-end app API to support NCST ZeroClient
 *
 * \author Copyright (c) 2005-2006 by Uniloc USA Inc. ALL RIGHTS RESERVED.
 * \author Copyright (c) 2014 by DeviceAuthority Inc. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to DeviceAuthority Inc. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from DeviceAuthority Inc.
 * 
 * \version 1.0
 * 
 * \date October 5, 2011
 * \date May 27, 2015
 *
 */

#if _MSC_VER > 1000
#pragma once
#endif // #if _MSC_VER > 1000

#ifndef __FRONTENDAPI_H__
#define __FRONTENDAPI_H__

typedef enum
{
    eAuthApiCtx,
    eChallengeApiCtx,
    eProvisionApiCtx,
    eRegisterApiCtx,
    eValidateApiCtx,
    eMaxApiCtx
} ApiContext;

#define FEAPP_JSON_RESPONSE_CODE            "code"
#define FEAPP_JSON_RESPONSE_STATUS          "status"
#define FEAPP_JSON_RESPONSE_MESSAGE         "message"
#define FEAPP_JSON_RESPONSE_DATA            "data"
#define FEAPP_JSON_RESPONSE_PROVID          "provision_id"
#define FEAPP_JSON_RESPONSE_CHALLENGE       "challenge"
#define FEAPP_JSON_RESPONSE_ISREGISTERED    "is_registered"

#ifdef __cplusplus
extern "C" {
#endif // #ifdef __cplusplus

const char *frontend_apicontext(int apiCtx);
size_t frontend_getnonce(char **nonce);
size_t frontend_getctxsignature(int apiCtx, const char *requestParams, size_t cbRequestParams, char **signature);
void frontend_freebuffer(char **buffer);

#ifdef __cplusplus
}
#endif // #ifdef __cplusplus

#endif // #ifndef __FRONTENDAPI_H__
