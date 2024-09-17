/**
 * \file /mavericks/shared/include/platform_osx.h
 *
 * \brief Implementation of platform specific definition and function declarations
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
 * \date January 1, 2014
 *
 */

#pragma once

#ifndef __PLATFORM_IOS_H__
#define __PLATFORM_IOS_H__

void Platform_SetAppDatabase(LPCSTR);
LPCSTR Platform_GetAppDatabase();
void Platform_SetSyntheticKey(LPVOID);
LPVOID Platform_GetSyntheticKey(LPVOID);

#endif // #ifndef __PLATFORM_IOS_H__
