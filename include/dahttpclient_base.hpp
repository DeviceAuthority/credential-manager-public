#ifndef DA_HTTP_CLIENT_BASE_HPP
#define DA_HTTP_CLIENT_BASE_HPP

#include <string>
#include <iostream>
#include "dahttpenums.hpp"

class DAHttpClientBase
{
public:
    virtual ~DAHttpClientBase() {};

    virtual DAErrorCode sendRequest(int req_type, const std::string &url, std::string &response, const std::string &post) = 0;
    virtual DAErrorCode sendRequest(int req_type, const std::string &url, std::ostream *p_out_stream, std::istream *p_in_stream = 0) = 0;
};

#endif // #ifndef DA_HTTP_CLIENT_BASE_HPP
