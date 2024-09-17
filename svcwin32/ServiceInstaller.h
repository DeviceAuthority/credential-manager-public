/****************************** Module Header ******************************\
 * Module Name:  ServiceInstaller.h
 * Project:      Credential-Manager
 * Copyright (c) Device Authority Ltd.
 *
 * The file declares functions that install and uninstall the service.
 *
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/
#pragma once

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
//   * dwStartType - the service desired access. Before granting the requested
//     access, the system checks the access token of the calling process.
//     For a list of values, see https://docs.microsoft.com/en-us/windows/desktop/Services/service-security-and-access-rights
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
                    PWSTR pszPassword);

//
//   FUNCTION: UninstallService
//
//   PURPOSE: Stop and remove the service from the local service control
//   manager database.
//
//   PARAMETERS:
//   * pszServiceName - the name of the service to be removed.
//   * pszDisplayName - the display name of the service
//
//   NOTE: If the function fails to uninstall the service, it prints the
//   error in the standard output stream for users to diagnose the problem.
//
void UninstallService(PWSTR pszServiceName, PWSTR pszDisplayName);

void StartService(PWSTR pszServiceName, PWSTR pszDisplayName);

void StopService(PWSTR pszServiceName, PWSTR pszDisplayName);
