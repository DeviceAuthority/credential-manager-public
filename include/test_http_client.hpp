#ifndef TEST_HTTP_CLIENT_HPP
#define TEST_HTTP_CLIENT_HPP

#include <istream>
#include <string>
#include "dahttpenums.hpp"
#include "dahttpclient_base.hpp"

class TestHttpClient : public DAHttpClientBase
{
public:
    virtual ~TestHttpClient() {};

    DAErrorCode sendRequest(const int req_type, const std::string &url, std::string &response, const std::string &post) override
    {
        std::ostringstream oss;
        std::istringstream iss(post);
        DAErrorCode rc = sendRequest(req_type, url, &oss, post.empty() ? (std::istringstream *)0 : &iss);
        response = oss.str();
        return rc;
    }

    DAErrorCode sendRequest(const int req_type, const std::string &url, std::ostream *p_out_stream, std::istream *p_in_stream = nullptr) override
    {
        m_send_req_json.clear();

        m_req_url = url;

        if (p_in_stream)
        {
            m_send_req_json = std::string(std::istreambuf_iterator<char>(*p_in_stream), std::istreambuf_iterator<char>());
        }

        if (p_out_stream)
        {
            p_out_stream->write(m_response_json.c_str(), m_response_json.size());
        }

        return DAErrorCode::ERR_OK;
    }

    const std::string &getLastRequestUrl() const
    {
        return m_req_url;
    }

    const std::string &getLastRequestJson() const
    {
        return m_send_req_json;
    }

    void setResponseJson(const std::string &resp_json)
    {
        m_response_json = resp_json;
    }

private:
    std::string m_req_url;
    std::string m_send_req_json;
    std::string m_response_json;
};

#endif // #ifndef TEST_HTTP_CLIENT_HPP
