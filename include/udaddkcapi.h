/**
 * \file /mavericks/shared/include/udaddkcapi.h
 *
 * \brief Definition of dynamic device key C-style APIs function pointer structure
 *
 * \author Copyright (c) 2005-2006 by Uniloc USA Inc. ALL RIGHTS RESERVED.
 * \author Copyright (c) 2014 - 2015 DeviceAuthority, Inc. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to DeviceAuthority Inc. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from DeviceAuthority Inc.
 *
 * \version 1.0
 *
 * \date October 5, 2011
 * \date May 1, 2015
 *
 */

#if _MSC_VER > 1000
#pragma once
#endif // #if _MSC_VER > 1000

#ifndef __UDADDKCAPI_H__
#define __UDADDKCAPI_H__

#include "DeviceKeyDef.h"

#ifndef WIN32
typedef void* HMODULE;
#endif // #ifndef WIN32

// Functions exposed by API
typedef struct NAUDADDKFunctions
{
    HMODULE hMod;
    NAUDADDK_GLOBALINIT_PROC naudaddk_globalinit;
    NAUDADDK_GLOBALCLEANUP_PROC naudaddk_globalcleanup;
    NAUDADDK_GETDEVICETID_PROC naudaddk_getdevicetid;
    NAUDADDK_GETDEVICEKEY_PROC naudaddk_getdevicekey;
    NAUDADDK_GETDEVICEKEYOAEP_PROC naudaddk_getdevicekeyoaep;
    NAUDADDK_GETDEVICEKEYVERSION_PROC naudaddk_getdevicekeyversion;
    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_PROC naudaddk_getdevicekeywithchallenge;
    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEROLE_PROC naudaddk_getdevicekeywithchallenge_withdevicerole;
    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEMETA_PROC naudaddk_getdevicekeywithchallenge_withdevicemeta;
    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEROLE_FORSIGPLUS_PROC naudaddk_getdevicekeywithchallenge_withdevicerole_forsigplus;
    NAUDADDK_GETSIGNATURE_FORSIGPLUS_PROC naudaddk_getsignature_forsigplus;
    NAUDADDK_GETUSERAGENTSTRING_PROC naudaddk_getuseragentstring;
    NAUDADDK_GETPLATFORMSTRING_PROC naudaddk_getplatformstring;
    NAUDADDK_FREEDEVICEKEY_PROC naudaddk_freedevicekey;
    NAUDADDK_FREEBUFFER_PROC naudaddk_freebuffer;
    NAUDADDK_DOCIPHER_AES_CFB128_PROC naudaddk_docipher_aes_cfb128;
    NAUDADDK_DODIGEST_SHA256_PROC naudaddk_dodigest_sha256;
    NAUDADDK_GETDEVICEKEY_FOREDGE_PROC naudaddk_getdevicekey_foredge;
    NAUDADDK_SETUDI_PROC naudaddk_setudi;
    NAUDADDK_GETUDI_PROC naudaddk_getudi;
    NAUDADDK_EXTDDKG_SETUDIPROPERTYNAME naudaddk_extddkg_setudipropertyname;
    NAUDADDK_SETROOTFS_PROC naudaddk_setrootfs;
} NAUDADDK_FUNCS, *PNAUDADDK_FUNCS, *LPNAUDADDK_FUNCS;

#ifndef WIN32
// Non-Windows platform
typedef union
{
    NAUDADDK_GLOBALINIT_PROC pfnaudaddk_globalinit;
    NAUDADDK_GLOBALCLEANUP_PROC pfnaudaddk_globalcleanup;
    NAUDADDK_GETDEVICETID_PROC pfnaudaddk_getdevicetid;
    NAUDADDK_GETDEVICEKEY_PROC pfnaudaddk_getdevicekey;
    NAUDADDK_GETDEVICEKEYOAEP_PROC pfnaudaddk_getdevicekeyoaep;
    NAUDADDK_GETDEVICEKEYVERSION_PROC pfnaudaddk_getdevicekeyversion;
    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_PROC pfnaudaddk_getdevicekeywithchallenge;
    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEROLE_PROC pfnaudaddk_getdevicekeywithchallenge_withdevicerole;
    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEMETA_PROC pfnaudaddk_getdevicekeywithchallenge_withdevicemeta;
    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEROLE_FORSIGPLUS_PROC pfnaudaddk_getdevicekeywithchallenge_withdevicerole_forsigplus;
    NAUDADDK_GETSIGNATURE_FORSIGPLUS_PROC pfnaudaddk_getsignature_forsigplus;
    NAUDADDK_GETUSERAGENTSTRING_PROC pfnaudaddk_getuseragentstring;
    NAUDADDK_GETPLATFORMSTRING_PROC pfnaudaddk_getplatformstring;
    NAUDADDK_FREEDEVICEKEY_PROC pfnaudaddk_freedevicekey;
    NAUDADDK_FREEBUFFER_PROC pfnaudaddk_freebuffer;
    NAUDADDK_DOCIPHER_AES_CFB128_PROC pfnaudaddk_docipher_aes_cfb128;
    NAUDADDK_DODIGEST_SHA256_PROC pfnaudaddk_dodigest_sha256;
    NAUDADDK_GETDEVICEKEY_FOREDGE_PROC pfnaudaddk_getdevicekey_foredge;
    NAUDADDK_SETUDI_PROC pfnaudaddk_setudi;
    NAUDADDK_GETUDI_PROC pfnaudaddk_getudi;
    NAUDADDK_EXTDDKG_SETUDIPROPERTYNAME naudaddk_extddkg_setudipropertyname;
    NAUDADDK_SETROOTFS_PROC naudaddk_setrootfs;
    void *obj;
} uNAUDADDKFuncPtrAlias;
#endif // #ifndef WIN32

#endif // #ifndef __UDADDKCAPI_H__
