/****************************** Module Header ******************************\
 * Module Name:  DAServiceImpl.h
 * Project:      Credential-Manager
 * Copyright (c) Device Authority Ltd.
 *
 * Provides a DA service class that derives from the service base class -
 * CServiceBase. The DA service logs the service start and stop
 * information to the Application event log, and shows how to run the main
 * function of the service in a thread pool worker thread.
 *
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/
#pragma once

#include "daagentsvc.h"
#include "ServiceBase.h"
#include "base_worker_loop.hpp"

class CDACredentialManagerService : public CServiceBase
{
public:
    CDACredentialManagerService(PWSTR pszServiceName,
        BOOL fCanStop = TRUE,
        BOOL fCanShutdown = TRUE,
        BOOL fCanPauseContinue = FALSE);
    CDACredentialManagerService(PWSTR pszServiceName,
        LPCSTR pszModuleFullPath,
        LPCSTR pszConfigFilename,
        BOOL fCanStop = TRUE,
        BOOL fCanShutdown = TRUE,
        BOOL fCanPauseContinue = FALSE);
    virtual ~CDACredentialManagerService(void);

protected:
    virtual void OnStart(DWORD dwArgc, PWSTR *pszArgv);
    virtual void OnStop();
    void ServiceWorkerThread(void);

private:
    std::unique_ptr<BaseWorkerLoop> mp_worker_loop;
    HANDLE m_hStoppedEvent;
    std::string m_sModuleFullPath;
    std::string m_sConfigFilename;
};
