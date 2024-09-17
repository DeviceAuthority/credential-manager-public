#pragma once

#include <string>

BOOL fileExists(LPCSTR pszFilename);
BOOL createDirectoryRecursively(std::wstring path);
BOOL createDirectoryRecursively(LPCSTR pszPath);
