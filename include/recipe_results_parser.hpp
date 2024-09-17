/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * PArser of receipe results
 */
#ifndef RECIPE_RESULTS_PARSER_HPP
#define RECIPE_RESULTS_PARSER_HPP

#include <string>
#include <sstream>

/**
 * @brief Parses the recipe result for flags that indicate how the result should be further processed, e.g.,
 * if a compression string is found, indicates that the result should be compressed.
 *
 */
struct RecipeResultsParser
{
public:
#if defined(ALLOW_COMPRESSION)
    const char *const USE_COMPRESSION_TAG = "(USE COMPRESSION)";

    RecipeResultsParser() : m_compress(false) {}

    std::string operator()(const std::string &recipeResults)
    {
        std::stringstream in(recipeResults, std::ios_base::in);
        std::stringstream out;

        for (std::string line; std::getline(in, line);)
        {
            if (!m_compress && line.find(USE_COMPRESSION_TAG) != std::string::npos)
            {
                m_compress = true;
            }
            else
            {
                out << line;
            }
        }
        return out.str();
    }

    bool isCompressRequested() const
    {
        return m_compress;
    }

private:
    bool m_compress;

#else

    std::string operator()(std::string recipeResults)
    {
        return std::move(recipeResults);
    }

    bool isCompressRequested() const { return false; }

#endif // ALLOW_COMPRESSION
};

#endif // RECIPE_RESULTS_PARSER_HPP
