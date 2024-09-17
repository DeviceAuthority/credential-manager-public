/*
 * Copyright (c) 2019 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * This class provides RapidJSON "XPath" functionality with wildcards
 */
#pragma once

#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include <vector>
#include <string>

namespace rapidjson
{
    /**
     * Obtain all JSON values matching the given JSON "XPath"
     *
     * <path>: '/' <fieldname> <path> | "/[" <index> ']' <path> | '/'
     * <fieldname>: [0-9a-zA-Z_]+ | '*'
     * <index>: [0-9]+ | '*'
     *
     * @param[in]  value  Pointer to rapidjson::Value from which to start search
     * @param[in]  path   JSON XPath string with above format
     * @param[out] result JSON values matching given path string
     */
	void allAtXPath( Value* value, const std::string& path, std::vector< Value* >& result );
} //end rapidjson
