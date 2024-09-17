#ifndef DA_HTTP_ENUM_H
#define DA_HTTP_ENUM_H

typedef enum DAReturnCode_
{
    ERR_OK              = 0,
    ERR_UNKNOWN         = 1,
    ERR_BAD_PARAM       = 2,
    ERR_BAD_DATA        = 3,
    ERR_INTERNAL        = 4,
    ERR_CURL            = 5
} DAErrorCode;

namespace DAHttp
{
	namespace ReqType
	{
		enum ReqType
		{
			eGET,
			ePOST,
			ePUT,
			eDELETE,
			eHEAD
		};
	}
}

#endif // #ifndef DA_HTTP_ENUM_H
