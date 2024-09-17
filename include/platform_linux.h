/**
 * \file /mavericks/shared/include/platform_linux.h
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

#ifndef __PLATFORM_LINUX_H__
#define __PLATFORM_LINUX_H__

#ifndef UINT_T
#if __WORDSIZE == 64
typedef uint64_t UINT_T;
#else
typedef uint32_t UINT_T;
#endif // #if __WORDSIZE == 64
#endif // #ifndef UINT_T

#ifndef BOOL
typedef int BOOL;
#endif // #ifndef BOOL

#ifndef DWORD
typedef unsigned long DWORD;
#endif // #ifndef DWORD

#ifndef LPSTR
typedef char* LPSTR;
#endif // #ifndef LPSTR

#ifndef LPCSTR
typedef const char* LPCSTR;
#endif // #ifndef LPCSTR

#ifndef BYTE
typedef uint8_t BYTE;
#endif // #ifndef BYTE

#ifndef LPBYTE
typedef BYTE* LPBYTE;
#endif // #ifndef LPBYTE

#ifndef LPCBYTE
typedef const BYTE* LPCBYTE;
#endif // #ifndef LPCBYTE

#ifdef  UNICODE

#else

#ifndef LPCTSTR
typedef LPCSTR LPCTSTR;
#endif // #ifndef LPCTSTR

#endif // #ifdef  UNICODE

#ifndef LPVOID
typedef void* LPVOID;
#endif // #ifndef LPVOID

#ifndef DWORDLONG
typedef uint64_t DWORDLONG;
#endif // #ifndef DWORDLONG

#ifndef LPDWORD
typedef DWORD* LPDWORD;
#endif // #ifndef LPDWORD

#ifndef TRUE
#define TRUE 1
#endif // #ifndef TRUE

#ifndef FALSE
#define FALSE 0
#endif // #ifndef FALSE

#endif // #ifndef __PLATFORM_LINUX_H__
