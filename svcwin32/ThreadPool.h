/****************************** Module Header ******************************\
 * Module Name:  ThreadPool.h
 * Project:      Credential-Manager
 * Copyright (c) Device Authority Ltd.
 *
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/
#pragma once

#include <memory>

class CThreadPool
{
public:
    template <typename T>
    static void QueueUserWorkItem(void (T::*function)(void),
        T *object, ULONG flags = WT_EXECUTELONGFUNCTION)
    {
        typedef std::pair<void (T::*)(), T *> CallbackType;
        std::auto_ptr<CallbackType> p(new CallbackType(function, object));

        if (::QueueUserWorkItem(ThreadProc<T>, p.get(), flags))
        {
            // The ThreadProc now has the responsibility of deleting the pair.
            p.release();
        }
        else
        {
            throw GetLastError();
        }
    }

private:
    template <typename T>
    static DWORD WINAPI ThreadProc(PVOID context)
    {
        typedef std::pair<void (T::*)(), T *> CallbackType;

        std::auto_ptr<CallbackType> p(static_cast<CallbackType *>(context));

        (p->second->*p->first)();
        return 0;
    }
};
