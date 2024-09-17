#include <Windows.h>
#include <string.h>
#include <fstream>
#include "StringHelper.h"


BOOL fileExists(LPCSTR pszFilename)
{
    std::ifstream ifs(pszFilename, std::ifstream::in);

    if (ifs.is_open())
    {
        ifs.close();

        return TRUE;
    }

    return FALSE;
}

BOOL createDirectoryRecursively(std::wstring path)
{
    unsigned int pos = 0;

    if (path.length() > 0)
    {
        do
        {
            pos = path.find_first_of(L"\\/", pos + 1);
            if (pos != std::string::npos)
            {
                if (!CreateDirectory(path.substr(0, pos).c_str(), NULL))
                {
                    if (GetLastError() != ERROR_ALREADY_EXISTS)
                    {
                        return FALSE;
                    }
                }
            }
        } while (pos != std::string::npos);
    }

    return TRUE;
}

BOOL createDirectoryRecursively(LPCSTR pszPath)
{
    if ((pszPath == NULL) || (strlen(pszPath) == 0))
    {
        // Nothing to be created
        return TRUE;
    }

    std::string sPath(pszPath);

    return createDirectoryRecursively(utf8ToUtf16(pszPath));
}

