/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * A wrapper for the Device Authority SAC calls.
 */
#include "dahttpclient.hpp"
#include "configuration.hpp"
#include <memory>
#include <string.h>
#include <sstream>
#include "log.hpp"
#include "constants.hpp"

namespace
{
    /** @brief  This is the callback registered with libCurl for libCurl to read pending data to send out
     *
     * This callback function gets called by libcurl when it requires data to send out
     *
     *  @param  ptr  char pointer to the pending data
     *  @param  size  buffer size indicator.(size*nmemb) gives size of the buffer.
     *  @param  nmemb  buffer size indicator.(size*nmemb) gives size of the buffer.
     *  @param  userData  userData passed when the callback is called by libCurl
     *
     *  @return  size_t  returns the number of bytes actually taken care of by the callback
     *
     */
    size_t httpReadCallback(void *ptr, size_t size, size_t nmemb, void *userData)
    {
        std::istream *is = (std::istream *)userData;
        return is ? is->readsome((char *)ptr, size * nmemb) : 0;
    }

    /** @brief  This is the callback registered with libCurl for writing received data
     *
     * This callback function gets called by libcurl as soon as there is data received that needs to be saved.
     *
     *  @param  ptr  char pointer to the delivered data
     *  @param  size  buffer size indicator.(size*nmemb) gives size of the buffer.
     *  @param  nmemb  buffer size indicator.(size*nmemb) gives size of the buffer.
     *  @param  userData  userData passed when the callback is called by libCurl
     *
     *  @return  size_t  returns the number of bytes actually taken care of by the callback
     *
     * @note This function may be called with zero bytes data if the transferred file is empty.
     *
     */
    size_t httpWriteCallback(char *ptr, size_t size, size_t nmemb, void *userData)
    {
        if (std::ostream *streamObj = (std::ostream *)userData)
        {
            const size_t maxBytes = size * nmemb;
            streamObj->write(ptr, maxBytes);
            if (streamObj->good())
            {
                return maxBytes;
            }
        }
        return 0;
    }

    /**
     * This is a callback registered with libcurl that allows it to seek to a given point in
     * the data stream. This is required if the connection fails and it is requested that the
     * client re-send its data (in a POST or PUT request)
     *
     * @param data The data stream
     * @param offset How far to seek in the stream
     * @param origin The origin of the seek operation
    */
    int httpSeekCallback(void *data, curl_off_t offset, int origin)
    {
        std::istream* p_streamObj = (std::istream *)data;

        std::ios_base::seekdir dir;
        switch (origin)
        {
            case SEEK_SET:
                dir = std::ios_base::beg;
                break;
            case SEEK_CUR:
                dir = std::ios_base::cur;
                break;
            case SEEK_END:
                dir = std::ios_base::end;
                break;
            default:
                Log::getInstance()->printf(Log::Severity::Error, "Unknown origin in HTTP seek");
                break;
        }

        p_streamObj->clear();
        p_streamObj->seekg(offset, dir);

        if (!p_streamObj->good())
        {
            Log::getInstance()->printf(Log::Severity::Error, "Failed to rewind");
            return CURL_SEEKFUNC_FAIL;
        }

        return CURL_SEEKFUNC_OK;
    }
}

DAHttpClient::DAHttpClient(const std::string &userAgent) : m_handle(NULL), m_userAgent(userAgent)
{
    m_headers = NULL;
    m_handle = curl_easy_init();
}

DAHttpClient::~DAHttpClient()
{
    if (m_handle)
    {
        curl_easy_cleanup(m_handle);
        if (m_headers)
        {
            curl_slist_free_all(m_headers);
            m_headers = NULL;
        }
    }
}

void DAHttpClient::init()
{
    Log::getInstance()->printf(Log::Information, "Curl version %s", curl_version());
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

void DAHttpClient::terminate()
{
    Log::getInstance()->printf(Log::Debug, " %s: Calling curl_global_cleanup()", __FUNCTION__);
    curl_global_cleanup();
}

DAErrorCode DAHttpClient::sendRequest(const int reqType, const std::string &url, std::string &response, const std::string &post)
{
    std::ostringstream oss;
    std::istringstream iss(post);
    DAErrorCode rc = sendRequest(reqType, url, &oss, post.empty() ? (std::istringstream *)0 : &iss);
    response = oss.str();
    return rc;
}

DAErrorCode DAHttpClient::sendRequest(const int reqType, const std::string &url, std::ostream *outStream, std::istream *inStream)
{
    CURLcode curlCode = CURLE_FAILED_INIT;
    DAErrorCode rc = ERR_OK;
    std::string Proxy_Loc = config.lookup(CFG_PROXY);
    std::string Proxy_Cred = config.lookup(CFG_PROXY_CREDENTIALS);

    if (m_handle != NULL)
    {
        // original which did not work with none authenticated proxy's
        // if (proxy_flag == 1)
        // {

        // std::string PROXY_LOCATION = config.lookup(CFG_PROXY);
        // std::string PROXY_CREDENTIALS = config.lookup(CFG_PROXY_CREDENTIALS);

        // curl_easy_setopt(m_handle, CURLOPT_PROXY, PROXY_LOCATION.c_str());
        // curl_easy_setopt(m_handle, CURLOPT_PROXYUSERPWD, PROXY_CREDENTIALS.c_str());

        // }

        // New works with non and authenticate proxy's.
        if (strlen(Proxy_Loc.c_str()) != 0)
        {
            Log::getInstance()->printf(Log::Debug, "Set Curl Proxy Location");

            curl_easy_setopt(m_handle, CURLOPT_PROXY, Proxy_Loc.c_str());

            if (strlen(Proxy_Cred.c_str()) != 0)
            {
                Log::getInstance()->printf(Log::Debug, "Set Curl Proxy Password");

                curl_easy_setopt(m_handle, CURLOPT_PROXYUSERPWD, Proxy_Cred.c_str());
            }
            else
            {
                Log::getInstance()->printf(Log::Debug, "No Proxy Password");
            }
        }
        curl_easy_setopt(m_handle, CURLOPT_POSTFIELDS, inStream ? NULL : "");
        curl_easy_setopt(m_handle, CURLOPT_POSTFIELDSIZE, inStream ? -1 : 0);
        curl_easy_setopt(m_handle, CURLOPT_READFUNCTION, httpReadCallback);
        curl_easy_setopt(m_handle, CURLOPT_READDATA, (void *)inStream);
        curl_easy_setopt(m_handle, CURLOPT_SEEKFUNCTION, httpSeekCallback);
        curl_easy_setopt(m_handle, CURLOPT_SEEKDATA, (void *)inStream);
        curl_easy_setopt(m_handle, CURLOPT_URL, url.c_str());
#if defined(ENABLE_VERBOSE_LOG)
        curl_easy_setopt(m_handle, CURLOPT_VERBOSE, 1L);
#endif // ENABLE_VERBOSE_LOG

        std::string CApath = config.lookup(CFG_CAPATH);
        std::string CAfile = config.lookup(CFG_CAFILE);

        if (CApath.length())
        {
            Log::getInstance()->printf(Log::Debug, "%s CURLOPT_CAPATH: %s", __func__, CApath.c_str());
            curl_easy_setopt(m_handle, CURLOPT_CAPATH, CApath.c_str());
        }
        if (CAfile.length())
        {
            Log::getInstance()->printf(Log::Debug, " %s CURLOPT_CAINFO: %s", __func__, CAfile.c_str());
            curl_easy_setopt(m_handle, CURLOPT_CAINFO, CAfile.c_str());
        }
        curl_easy_setopt(m_handle, CURLOPT_WRITEFUNCTION, httpWriteCallback);
        curl_easy_setopt(m_handle, CURLOPT_WRITEDATA, (void *)outStream);
        if (reqType == DAHttp::ReqType::eGET)
        {
            curl_easy_setopt(m_handle, CURLOPT_HTTPGET, 1);
        }
        else if (reqType == DAHttp::ReqType::ePOST)
        {
            curl_easy_setopt(m_handle, CURLOPT_POST, 1);
        }
        else if (reqType == DAHttp::ReqType::ePUT)
        {
            curl_easy_setopt(m_handle, CURLOPT_PUT, 1);
        }
        else if (reqType == DAHttp::ReqType::eDELETE)
        {
            curl_easy_setopt(m_handle, CURLOPT_CUSTOMREQUEST, "DELETE");
        }
        if (m_headers == NULL)
        {
            m_headers = curl_slist_append(m_headers, "Connection: keep-alive");
            m_headers = curl_slist_append(m_headers, "Accept-Language: en-us;en,q=0.4");
            m_headers = curl_slist_append(m_headers, "Content-Type: application/json");
            m_headers = curl_slist_append(m_headers, "Transfer-Encoding: chunked");

            std::string agentStr = "User-Agent: ";

            agentStr.append(m_userAgent);
            m_headers = curl_slist_append(m_headers, agentStr.c_str());
            curl_easy_setopt(m_handle, CURLOPT_HTTPHEADER, m_headers);
        }
        curl_easy_setopt(m_handle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(m_handle, CURLOPT_SSL_VERIFYHOST, 1L);
        memset(m_error_buffer, 0, sizeof(m_error_buffer));
        curl_easy_setopt(m_handle, CURLOPT_ERRORBUFFER, m_error_buffer);
        curlCode = curl_easy_perform(m_handle);
        // Everything was fine
        if (curlCode == CURLE_OK)
        {
            long httpRespCode = 0;

            curl_easy_getinfo(m_handle, CURLINFO_RESPONSE_CODE, &httpRespCode);
            if (httpRespCode != 200)
            {
                Log::getInstance()->printf(Log::Debug, " %s:%d httpRespCode: %ld", __func__, __LINE__, httpRespCode);
                rc = ERR_CURL;
            }
        }
        else
        {
            Log::getInstance()->printf(Log::Error, " %s:%d error buffer: %s, curlCode: %d", __func__, __LINE__, m_error_buffer, curlCode);
            if (CApath.length())
            {
                Log::getInstance()->printf(Log::Information, "%s CURLOPT_CAPATH(CApath): %s", __func__, CApath.c_str());
            }
            if (CAfile.length())
            {
                Log::getInstance()->printf(Log::Information, "%s CURLOPT_CAINFO(CAfile) :%s ", __func__, CAfile.c_str());
            }
            rc = ERR_CURL;
        }
    }

    return rc;
}
