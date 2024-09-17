/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An function to process any password assets
 */
#ifndef ACCOUNTS_HPP
#define ACCOUNTS_HPP

#include <string>
#include <vector>

class account
{
public:
    account(const std::string& name, const std::string& salt, const std::string& hash, const std::string& result, const std::string& reason);
    ~account();

    inline std::string getResult() const
    {
        return m_result;
    }

    inline std::string getReason() const
    {
        return m_reason;
    }

    inline std::string getName() const
    {
        return m_name;
    }

    inline std::string getSalt() const
    {
        return m_salt;
    }

    inline void setResult(const std::string& result, const std::string& reason = "")
    {
        m_result = result;
        if (m_result != account::success)
        {
            m_reason = reason;
        }
    }

    const std::string sha256AndEncode(const std::string& input) const;
    bool validateHash(const std::string& password) const;
    const std::string generatePassword(const std::string& key) const;
    /*
    void display()
    */

public:
    static const std::string success;
    static const std::string failure;

private:
    std::string m_name;
    std::string m_salt;
    std::string m_validation_hash;
    std::string m_result;
    std::string m_reason;
};

#endif // #ifndef ACCOUNTS_HPP
