/****************************** Module Header ******************************\
 * Module Name:  ServiceInstaller.cpp
 * Project:      Credential-Manager
 * Copyright (c) Device Authority Ltd.
 *
 * The file implements functions that install and uninstall the service.
 *
 * This source is subject to the Microsoft Public License.
 * See http://www.microsoft.com/en-us/openness/resources/licenses.aspx#MPL.
 * All other rights reserved.
 *
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/
#pragma region "Includes"
#include <stdio.h>
#include <windows.h>
#include <iostream>
#include "ServiceInstaller.h"
#include "log.hpp"
#pragma endregion


//
//   FUNCTION: InstallService
//
//   PURPOSE: Install the current application as a service to the local
//   service control manager database.
//
//   PARAMETERS:
//   * pszServiceName - the name of the service to be installed
//   * pszDisplayName - the display name of the service
//   * pszServiceDescription - the description of the service
//   * dwStartType - the service start option. This parameter can be one of
//     the following values: SERVICE_AUTO_START, SERVICE_BOOT_START,
//     SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_SYSTEM_START.
//   * pszDependencies - a pointer to a double null-terminated array of null-
//     separated names of services or load ordering groups that the system
//     must start before this service.
//   * pszAccount - the name of the account under which the service runs.
//   * pszPassword - the password to the account name.
//
//   NOTE: If the function fails to install the service, it prints the error
//   in the standard output stream for users to diagnose the problem.
//
void InstallService(PWSTR pszServiceName,
                    PWSTR pszDisplayName,
                    PWSTR pszServiceDescription,
                    DWORD dwDesiredAccess,
                    DWORD dwStartType,
                    PWSTR pszDependencies,
                    PWSTR pszAccount,
                    PWSTR pszPassword)
{
    wchar_t szPath[MAX_PATH];
    SERVICE_DESCRIPTION description;
    char errMsg[256] = { 0 };
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;

    if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)) == 0)
    {
        sprintf_s(errMsg, sizeof(errMsg), "GetModuleFileName failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    // Open the local default service control manager database
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (schSCManager == NULL)
    {
        sprintf_s(errMsg, sizeof(errMsg), "OpenSCManager failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    // Install the service into SCM by calling CreateService
    schService = CreateService(
        schSCManager,                   // SCManager database
        pszServiceName,                 // Name of service
        pszDisplayName,                 // Name to display
        dwDesiredAccess,                // Desired access
        SERVICE_WIN32_OWN_PROCESS,      // Service type
        dwStartType,                    // Service start type
        SERVICE_ERROR_NORMAL,           // Error control type
        szPath,                         // Service's binary
        NULL,                           // No load ordering group
        NULL,                           // No tag identifier
        pszDependencies,                // Dependencies
        NULL,                           // Service running account
        NULL                            // Password of the account
    );
    if (schService == NULL)
    {
        sprintf_s(errMsg, sizeof(errMsg), "CreateService failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    description.lpDescription = pszServiceDescription;
    ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &description);
    sprintf_s(errMsg, sizeof(errMsg), "%S is installed", pszDisplayName);
    std::cout << errMsg << std::endl;

Cleanup:
    // Centralized cleanup for all allocated resources
    if (schSCManager)
    {
        CloseServiceHandle(schSCManager);
        schSCManager = NULL;
    }
    if (schService)
    {
        CloseServiceHandle(schService);
        schService = NULL;
    }
}

//
//   FUNCTION: UninstallService
//
//   PURPOSE: Stop and remove the service from the local service control
//   manager database.
//
//   PARAMETERS:
//   * pszServiceName - the name of the service to be removed.
//
//   NOTE: If the function fails to uninstall the service, it prints the
//   error in the standard output stream for users to diagnose the problem.
//
void UninstallService(PWSTR pszServiceName, PWSTR pszDisplayName)
{
    char errMsg[256] = { 0 };
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;
    SERVICE_STATUS ssSvcStatus = {};

    // Open the local default service control manager database
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (schSCManager == NULL)
    {
        sprintf_s(errMsg, sizeof(errMsg), "OpenSCManager failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    // Open the service with delete, stop, and query status permissions
    schService = OpenService(schSCManager, pszServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (schService == NULL)
    {
        sprintf_s(errMsg, sizeof(errMsg), "OpenService failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    // Try to stop the service
    if (ControlService(schService, SERVICE_CONTROL_STOP, &ssSvcStatus))
    {
        sprintf_s(errMsg, sizeof(errMsg), "Stopping %S service", pszDisplayName);
        std::cout << errMsg << std::endl;
        ::Sleep(1000);
        while (QueryServiceStatus(schService, &ssSvcStatus))
        {
            if (ssSvcStatus.dwCurrentState == SERVICE_STOP_PENDING)
            {
                ::Sleep(1000);
            }
            else
            {
                break;
            }
        }
        if (ssSvcStatus.dwCurrentState == SERVICE_STOPPED)
        {
            sprintf_s(errMsg, sizeof(errMsg), "%S service is stopped", pszDisplayName);
            std::cout << errMsg << std::endl;
        }
        else
        {
            sprintf_s(errMsg, sizeof(errMsg), "%S service failed to stop", pszDisplayName);
            std::cerr << errMsg << std::endl;
        }
    }
    // Now remove the service by calling DeleteService
    if (!DeleteService(schService))
    {
        sprintf_s(errMsg, sizeof(errMsg), "DeleteService failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    sprintf_s(errMsg, sizeof(errMsg), "%S service is removed", pszDisplayName);
    std::cout << errMsg << std::endl;

Cleanup:
    // Centralized cleanup for all allocated resources
    if (schSCManager)
    {
        CloseServiceHandle(schSCManager);
        schSCManager = NULL;
    }
    if (schService)
    {
        CloseServiceHandle(schService);
        schService = NULL;
    }
}

//
// Purpose: 
//   Starts the service if possible.
//
// Parameters:
//   None
// 
// Return value:
//   None
//
void StartService(PWSTR pszServiceName, PWSTR pszDisplayName)
{
    SERVICE_STATUS_PROCESS ssStatus;
    char errMsg[256] = { 0 };
    const DWORD dwTimeout = 30000;
    DWORD dwBytesNeeded = 0;
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;

    // Get a handle to the SCM database
    schSCManager = OpenSCManager(
        NULL,                    // local computer
        NULL,                    // servicesActive database
        SC_MANAGER_ALL_ACCESS);  // full access rights
    if (schSCManager == NULL)
    {
        sprintf_s(errMsg, sizeof(errMsg), "OpenSCManager failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    // Get a handle to the service
    schService = OpenService(
        schSCManager,         // SCM database
        pszServiceName,       // name of service
        SERVICE_ALL_ACCESS);  // full access
    if (schService == NULL)
    { 
        sprintf_s(errMsg, sizeof(errMsg), "OpenService failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }    
    // Check the status in case the service is not stopped
    if (!QueryServiceStatusEx(
            schService,                     // handle to service
            SC_STATUS_PROCESS_INFO,         // information level
            (LPBYTE)&ssStatus,              // address of structure
            sizeof(SERVICE_STATUS_PROCESS), // size of structure
            &dwBytesNeeded))                // size needed if buffer is too small
    {
        sprintf_s(errMsg, sizeof(errMsg), "QueryServiceStatusEx failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    // Check if the service is already running. It would be possible
    // to stop the service here, but for simplicity this example just returns. 
    if ((ssStatus.dwCurrentState != SERVICE_STOPPED) && (ssStatus.dwCurrentState != SERVICE_STOP_PENDING))
    {
        std::cout << "Cannot start the service because it is already running" << std::endl;
        goto Cleanup;
    }

    DWORD dwWaitTime = 0;
    // Save the tick count and initial checkpoint
    DWORD dwStartTickCount = GetTickCount();
    DWORD dwOldCheckPoint = ssStatus.dwCheckPoint;

    // Wait for the service to stop before attempting to start it
    while (ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
    {
        // Do not wait longer than the wait hint. A good interval is
        // one-tenth of the wait hint but not less than 1 second
        // and not more than 10 seconds
        dwWaitTime = ssStatus.dwWaitHint / 10;
        if (dwWaitTime < 1000)
        {
            dwWaitTime = 1000;
        }
        else if (dwWaitTime > 10000)
        {
            dwWaitTime = 10000;
        }
        ::Sleep(dwWaitTime);
        // Check the status until the service is no longer stop pending
        if (!QueryServiceStatusEx(
                schService,                     // handle to service
                SC_STATUS_PROCESS_INFO,         // information level
                (LPBYTE)&ssStatus,              // address of structure
                sizeof(SERVICE_STATUS_PROCESS), // size of structure
                &dwBytesNeeded))                // size needed if buffer is too small
        {
            sprintf_s(errMsg, sizeof(errMsg), "QueryServiceStatusEx failed, error: 0x%08lx", GetLastError());
            std::cerr << errMsg << std::endl;
            goto Cleanup;
        }
        if (ssStatus.dwCheckPoint > dwOldCheckPoint)
        {
            // Continue to wait and check
            dwStartTickCount = GetTickCount();
            dwOldCheckPoint = ssStatus.dwCheckPoint;
        }
        else if ((GetTickCount() - dwStartTickCount) > ssStatus.dwWaitHint)
        {
            std::cout << "Timeout waiting for service to stop" << std::endl;
            goto Cleanup;
        }
    }
    // Attempt to start the service
    if (!StartService(
            schService,  // handle to service 
            0,           // number of arguments 
            NULL))       // no arguments 
    {
        sprintf_s(errMsg, sizeof(errMsg), "StartService failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    std::cout << "Service start pending..." << std::endl;
    // Check the status until the service is no longer start pending
    if (!QueryServiceStatusEx(
            schService,                     // handle to service 
            SC_STATUS_PROCESS_INFO,         // info level
            (LPBYTE)&ssStatus,              // address of structure
            sizeof(SERVICE_STATUS_PROCESS), // size of structure
            &dwBytesNeeded))                // if buffer too small
    {
        sprintf_s(errMsg, sizeof(errMsg), "QueryServiceStatusEx failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    } 
    // Save the tick count and initial checkpoint
    dwStartTickCount = GetTickCount();
    dwOldCheckPoint = ssStatus.dwCheckPoint;
    while (ssStatus.dwCurrentState == SERVICE_START_PENDING) 
    { 
        // Do not wait longer than the wait hint. A good interval is
        // one-tenth the wait hint, but no less than 1 second and no
        // more than 10 seconds
        dwWaitTime = ssStatus.dwWaitHint / 10;
        if (dwWaitTime < 1000)
        {
            dwWaitTime = 1000;
        }
        else if (dwWaitTime > 10000)
        {
            dwWaitTime = 10000;
        }
        ::Sleep(dwWaitTime);
        // Check the status again
        if (!QueryServiceStatusEx(
            schService,                     // handle to service 
            SC_STATUS_PROCESS_INFO,         // info level
            (LPBYTE)&ssStatus,              // address of structure
            sizeof(SERVICE_STATUS_PROCESS), // size of structure
            &dwBytesNeeded))                // if buffer too small
        {
            sprintf_s(errMsg, sizeof(errMsg), "QueryServiceStatusEx failed, error: 0x%08lx", GetLastError());
            std::cerr << errMsg << std::endl;
            break; 
        }
        if (ssStatus.dwCheckPoint > dwOldCheckPoint)
        {
            // Continue to wait and check
            dwStartTickCount = GetTickCount();
            dwOldCheckPoint = ssStatus.dwCheckPoint;
        }
        else if ((GetTickCount() - dwStartTickCount) > dwTimeout/*ssStatus.dwWaitHint*/)
        {
            // No progress made within the wait hint
            break;
        }
    } 
    // Determine whether the service is running
    if (ssStatus.dwCurrentState == SERVICE_RUNNING) 
    {
        sprintf_s(errMsg, sizeof(errMsg), "%S service started successfully", pszDisplayName);
        std::cout << errMsg << std::endl;
    }
    else 
    { 
        std::cout << "Service not started" << std::endl;
        std::cout << "  Current State: " << ssStatus.dwCurrentState << std::endl;
        std::cout << "  Exit Code: " << ssStatus.dwWin32ExitCode << std::endl;
        std::cout << "  Check Point: " << ssStatus.dwCheckPoint << std::endl;
        std::cout << "  Wait Hint: " << ssStatus.dwWaitHint << std::endl;
    }

Cleanup:
    // Centralized cleanup for all allocated resources
    if (schSCManager)
    {
        CloseServiceHandle(schSCManager);
        schSCManager = NULL;
    }
    if (schService)
    {
        CloseServiceHandle(schService);
        schService = NULL;
    }
}

static BOOL StopDependentServices(SC_HANDLE schSCManager, SC_HANDLE schService)
{
    DWORD i = 0;
    DWORD dwBytesNeeded = 0;
    DWORD dwCount = 0;
    ENUM_SERVICE_STATUS ess;
    SC_HANDLE hDepService;
    SERVICE_STATUS_PROCESS ssp;
    LPENUM_SERVICE_STATUS lpDependencies = NULL;
    DWORD dwStartTime = GetTickCount();
    // 30-second time-out
    const DWORD dwTimeout = 30000;

    // Pass a zero-length buffer to get the required buffer size
    if (EnumDependentServices(schService, SERVICE_ACTIVE,
         lpDependencies, 0, &dwBytesNeeded, &dwCount)) 
    {
         // If the Enum call succeeds, then there are no dependent
         // services, so do nothing.
         return TRUE;
    }
    if (GetLastError() != ERROR_MORE_DATA)
    {
        // Unexpected error
        return FALSE;
    }
    // Allocate a buffer for the dependencies
    lpDependencies = (LPENUM_SERVICE_STATUS)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);
    if (!lpDependencies)
    {
        return FALSE;
    }
    __try
    {
        // Enumerate the dependencies
        if (!EnumDependentServices(schService, SERVICE_ACTIVE,
            lpDependencies, dwBytesNeeded, &dwBytesNeeded, &dwCount))
        {
            return FALSE;
        }
        for (i = 0; i < dwCount; i++)
        {
            ess = *(lpDependencies + i);
            // Open the service
            hDepService = OpenService(schSCManager,
                ess.lpServiceName,
                SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (!hDepService)
            {
                return FALSE;
            }
            __try
            {
                // Send a stop code
                if (!ControlService(hDepService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
                {
                    return FALSE;
                }
                // Wait for the service to stop
                while (ssp.dwCurrentState != SERVICE_STOPPED)
                {
                    ::Sleep(ssp.dwWaitHint);
                    if (!QueryServiceStatusEx(
                            hDepService,
                            SC_STATUS_PROCESS_INFO,
                            (LPBYTE)&ssp,
                            sizeof(SERVICE_STATUS_PROCESS),
                            &dwBytesNeeded))
                    {
                        return FALSE;
                    }
                    if (ssp.dwCurrentState == SERVICE_STOPPED)
                    {
                        break;
                    }
                    if ((GetTickCount() - dwStartTime) > dwTimeout)
                    {
                        return FALSE;
                    }
                }
            }
            __finally 
            {
                // Always release the service handle.
                CloseServiceHandle(hDepService);
            }
        }
    } 
    __finally 
    {
        if (lpDependencies)
        {
            // Always free the enumeration buffer.
            HeapFree(GetProcessHeap(), 0, lpDependencies);
        }
    }

    return TRUE;
}

//
// Purpose: 
//   Stops the service.
//
// Parameters:
//   None
// 
// Return value:
//   None
//
VOID StopService(PWSTR pszServiceName, PWSTR pszDisplayName)
{
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwStartTime = GetTickCount();
    DWORD dwWaitTime = 0;
    // 30-second time-out
    const DWORD dwTimeout = 30000;
    char errMsg[256] = { 0 };
    DWORD dwBytesNeeded = 0;
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;

    // Get a handle to the SCM database. 
    schSCManager = OpenSCManager(
        NULL,                    // local computer
        NULL,                    // ServicesActive database
        SC_MANAGER_ALL_ACCESS);  // full access rights
    if (schSCManager == NULL)
    {
        sprintf_s(errMsg, sizeof(errMsg), "OpenSCManager failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    // Get a handle to the service
    schService = OpenService( 
        schSCManager,         // SCM database 
        pszServiceName,       // name of service 
        SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
    if (schService == NULL)
    { 
        sprintf_s(errMsg, sizeof(errMsg), "OpenService failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }    
    // Make sure the service is not already stopped
    if (!QueryServiceStatusEx(
            schService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded))
    {
        sprintf_s(errMsg, sizeof(errMsg), "QueryServiceStatusEx failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    if (ssp.dwCurrentState == SERVICE_STOPPED)
    {
        std::cout << "Service is already stopped" << std::endl;
        goto Cleanup;
    }
    // If a stop is pending, wait for it
    while (ssp.dwCurrentState == SERVICE_STOP_PENDING)
    {
        std::cout << "Service stop pending..." << std::endl;
        // Do not wait longer than the wait hint. A good interval is
        // one-tenth of the wait hint but not less than 1 second
        // and not more than 10 seconds
        dwWaitTime = ssp.dwWaitHint / 10;
        if (dwWaitTime < 1000)
        {
            dwWaitTime = 1000;
        }
        else if (dwWaitTime > 10000)
        {
            dwWaitTime = 10000;
        }
        ::Sleep(dwWaitTime);
        if (!QueryServiceStatusEx(
                 schService,
                 SC_STATUS_PROCESS_INFO,
                 (LPBYTE)&ssp,
                 sizeof(SERVICE_STATUS_PROCESS),
                 &dwBytesNeeded))
        {
            sprintf_s(errMsg, sizeof(errMsg), "QueryServiceStatusEx failed, error: 0x%08lx", GetLastError());
            std::cerr << errMsg << std::endl;
            goto Cleanup;
        }
        if (ssp.dwCurrentState == SERVICE_STOPPED)
        {
            sprintf_s(errMsg, sizeof(errMsg), "%S service stopped successfully", pszDisplayName);
            std::cout << errMsg << std::endl;
            goto Cleanup;
        }
        if ((GetTickCount() - dwStartTime) > dwTimeout)
        {
            std::cout << "Timeout waiting for service to stop" << std::endl;
            goto Cleanup;
        }
    }
    // If the service is running, dependencies must be stopped first.
    StopDependentServices(schSCManager, schService);
    // Send a stop code to the service
    if (!ControlService(schService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
    {
        sprintf_s(errMsg, sizeof(errMsg), "ControlService failed, error: 0x%08lx", GetLastError());
        std::cerr << errMsg << std::endl;
        goto Cleanup;
    }
    // Wait for the service to stop
    while (ssp.dwCurrentState != SERVICE_STOPPED) 
    {
        ::Sleep(ssp.dwWaitHint);
        if (!QueryServiceStatusEx(
                schService,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE)&ssp,
                sizeof(SERVICE_STATUS_PROCESS),
                &dwBytesNeeded))
        {
            sprintf_s(errMsg, sizeof(errMsg), "QueryServiceStatusEx failed, error: 0x%08lx", GetLastError());
            std::cerr << errMsg << std::endl;
            goto Cleanup;
        }
        if (ssp.dwCurrentState == SERVICE_STOPPED)
        {
            break;
        }
        if ((GetTickCount() - dwStartTime) > dwTimeout)
        {
            std::cout << "Timeout waiting for service to stop" << std::endl;
            goto Cleanup;
        }
    }
    sprintf_s(errMsg, sizeof(errMsg), "%S service stopped successfully", pszDisplayName);
    std::cout << errMsg << std::endl;

Cleanup:
    // Centralized cleanup for all allocated resources
    if (schSCManager)
    {
        CloseServiceHandle(schSCManager);
        schSCManager = NULL;
    }
    if (schService)
    {
        CloseServiceHandle(schService);
        schService = NULL;
    }
}
