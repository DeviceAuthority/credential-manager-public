#ifndef DA_HTTP_CLIENT_HPP
#define DA_HTTP_CLIENT_HPP

#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <string>
#include <vector>
#include "dahttpclient_base.hpp"

using namespace std;

class DAHttpClient : public DAHttpClientBase
{
public:
    static void init();
    static void terminate();

    DAHttpClient(const std::string& userAgent);
    virtual ~DAHttpClient();

    DAErrorCode sendRequest(int reqType, const std::string &url, std::string &response, const std::string &post) override;
    DAErrorCode sendRequest(int reqType, const std::string &url, std::ostream *outStream, std::istream *inStream=0) override;

private:
    CURL *m_handle;
    char m_error_buffer[CURL_ERROR_SIZE + 1];
    curl_slist *m_headers;
	std::string m_userAgent;
};

#endif // #ifndef DA_HTTP_CLIENT_HPP
