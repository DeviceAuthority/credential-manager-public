/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Types to represent the various functional options.
 */
#ifndef OPTYPE_H
#define OPTYPE_H

#ifdef __cplusplus
//namespace cryptosoft
//{

#include <string>

enum OpType
{
    NOTHING = 0,
    ENCRYPT = 1,
    DECRYPT = 2
};

inline std::string toString( OpType op )
{
	return op == ENCRYPT ? "ENCRYPT":
           op == DECRYPT ? "DECRYPT":
        		           "NOTHING";
}


enum DirectionType
{
    C2S = 0,
    S2C = 1,
    BOTH = 2
};

inline std::string toString( DirectionType dir )
{
	return dir == C2S ? "C->S":
           dir == S2C ? "S->C":
        		        "s<->C";
}

enum MethodType
{
    NA = 0,
    POST = 1,
    GET = 2
};

//}
#else

typedef enum { NOTHING = 0, ENCRYPT = 1, DECRYPT = 2 } OpType;
typedef enum { C2S = 0, S2C = 1, BOTH = 2 } DirectionType ;
typedef enum { NA = 0, POST = 1, GET = 2 } MethodType ;

#endif // #ifdef __cplusplus

#endif // #ifndef OPTYPE_H
