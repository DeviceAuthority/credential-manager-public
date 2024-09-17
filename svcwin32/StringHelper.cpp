#include <codecvt>
#include "StringHelper.h"


std::wstring utf8ToUtf16(const std::string& utf8Str)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;

    return conv.from_bytes(utf8Str);
}

std::string utf16ToUtf8(const std::wstring& utf16Str)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;

    return conv.to_bytes(utf16Str);
}

bool endsWith(std::string const &fullString, std::string const &ending)
{
    if (fullString.length() >= ending.length())
    {
        return (fullString.compare(fullString.length() - ending.length(), ending.length(), ending) == 0);
    }

    return false;
}