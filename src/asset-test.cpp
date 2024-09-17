#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <memory>

#include "base64.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "configuration.hpp"
#include "constants.hpp"
#include "asset_manager.hpp"
#include "asset_constants.hpp"
#include "deviceauthority.hpp"
#include "rapidjson/pointer.h"
#include "zlib.h"

namespace
{
    enum OSEnum
    {
        WINDOWS,
        LINUX
    };

#if defined(WIN32)
    const OSEnum OS_ENUM = WINDOWS;
#else
    const OSEnum OS_ENUM = LINUX;
#endif

    const std::string privateKey =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpQIBAAKCAQEAowBa409fWPTqZsN+8G/U2riw95Gxj3AXUGq+IpXfFUphljZf\n"
        "feQs0Mm5OI97QX2IM20xqHYZW32qNETdpBQtmWjQlKxSbAon6LTSr1D8kdH8Koic\n"
        "hRc/ciZdso9HEzykPhyHEJGkh+61g66JMDKVmL/Z+y8sZCyeIJwXG57q2cuVUh9g\n"
        "B+B12gvRibMsY/dVJFeYL3+7G5y8Erngg+YZsGCpjLmKiyCiWdGOWRrFj1nE18Xh\n"
        "mjQY99MHiuX1AfYn8m9PF4gq2zXhZmQp8BXhtkGSjLJG4FL5g/Ce33sIbMa5IudH\n"
        "BXksXJ0SRGdx1ToQYN+JNM/E/CMNiEIW+nsGOwIDAQABAoIBAQCZxYH4oy5t+08O\n"
        "dytPpBCH7mh0hWuex74WzTxl4EE+EpeRX+YiG5nztfoYU7ORit1stnx8Uj2FxD1H\n"
        "Zhg57BdAfFMZjp+K8OHJdJy1a495+UEM1yfhnpbqFyuZgfUpPrIrLjp09RDkc9ul\n"
        "SIh/gZkDKyp2/n/AWR8r4FUkZ31izFy7QvU0TuP7wk84xaGa72j6j0RgY1T2gvc8\n"
        "7KOJ09vGuJExMlXZHTPa1xqzCY3+9v8OQiKCYHby7S/JB3dxxGv/hN1DoVi7A5CW\n"
        "RBsrNftqYYnSYeZFqyTPEBQyuFvE0vTfo5Rwi0os9ZlXrIWrzbOUawhc1dLsBFay\n"
        "GCh/qxixAoGBAMzcKaCBlLiWLBGE5UNiREM72S6rWoMEmr0RzwKOjfYS2oNN9zqg\n"
        "OTp5I9Eo5OPmlYQEkErZ2uHRuHiuYpH4fYGkVpLfCOdNBA4xHhqnyGlJ/Fg6/u+M\n"
        "+4R920RXuhhAqVPis59g+Rv6NFjhWaDndJj4hroUAtbb4OVS17WSkPgvAoGBAMux\n"
        "Kg8pIXqF/aIcSV3Ha3QdxlK6O1dV/Meo+pEDzDQI5ePSYBEU0c3afRJaSWeOueBs\n"
        "6ek/Y1JH6m60ROklyz10qLoysHyJoWJXx2yftQAtR2NtiQEec4ubJKs4U0qqYHvO\n"
        "fUI+6iLiQb4o8/CUHtt+tlGAUxi75n0EBbXiXQO1AoGBAIhyf9tjU65af8GvdZCb\n"
        "LAJoI3D9Os0XTQVvjiUS1CU5S4e3b1sCCvwSYbPXfBT7qUyESaNBVZOhPzBKXmcB\n"
        "Tn8B+ZPbsC93UaMuPfHdHRRb7hLKQLFHguMtfNUZZV7v+phf3+nhCisDTMiCWFNe\n"
        "tn+I0RuxZm67hyDXO8u5couLAoGASBm4B5HJlfMj6mQU3CsgsANyFgpxwuJfDdWU\n"
        "jAxKFgkoRtJKywERmspCB2MKJKvyw6wJyFR1tcRbCUCqO9Ty8hf/OZmDuzGEfKkR\n"
        "oDOQADYG1P0Kx+idgccy3aCcawuQB4L5958JhbuNBeC9KGVl3tAlfQftYg3w8kOg\n"
        "OdeckRkCgYEAlBnMXgOfzYUi4RaRYe3/yWjWDQzaWlZMk6Eif/InxTNBKBbNb2FX\n"
        "gxG2XPI4vReY/P6ZY31wOLnrm1tMuCPm4LLWtWq1p8mmTfWyiTAvkIwkY3wfLgNc\n"
        "/OiVkltk090cklFjydsJ/KMfzpySQHEqrEnxSyx/qzCR0mWqKJl6MLQ=\n"
        "-----END RSA PRIVATE KEY-----";

    const std::string publicKey =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAowBa409fWPTqZsN+8G/U\n"
        "2riw95Gxj3AXUGq+IpXfFUphljZffeQs0Mm5OI97QX2IM20xqHYZW32qNETdpBQt\n"
        "mWjQlKxSbAon6LTSr1D8kdH8KoichRc/ciZdso9HEzykPhyHEJGkh+61g66JMDKV\n"
        "mL/Z+y8sZCyeIJwXG57q2cuVUh9gB+B12gvRibMsY/dVJFeYL3+7G5y8Erngg+YZ\n"
        "sGCpjLmKiyCiWdGOWRrFj1nE18XhmjQY99MHiuX1AfYn8m9PF4gq2zXhZmQp8BXh\n"
        "tkGSjLJG4FL5g/Ce33sIbMa5IudHBXksXJ0SRGdx1ToQYN+JNM/E/CMNiEIW+nsG\n"
        "OwIDAQAB\n"
        "-----END PUBLIC KEY-----";

    const std::string aesKey = "E8B6C00C9ADC5E75BB656ECD429CB1643A25B111FCD22C6622D53E0722439993";
    const std::string aesIV = "E486BB61EB213ED88CC3CFB938CD58D7";

    void storePublicKey()
    {
        std::string publicKeyPath;
        if (config.exists(CFG_CERTIFICATEPATH))
        {
            publicKeyPath = config.lookup(CFG_CERTIFICATEPATH);
        }
        if (publicKeyPath.empty())
        {
            throw std::runtime_error("Public key path not defined");
        }

        std::ofstream os(publicKeyPath);
        os << publicKey;
    }

    /////////////////////////////////////////////////////////////
    // Recipe Test
    /////////////////////////////////////////////////////////////
    struct RecipeTest
    {
        virtual std::string script() = 0;
        virtual std::string expectedResults() = 0;
        virtual std::string dataUrl() = 0;
        virtual void run() = 0;
        virtual std::string name() = 0;
        virtual ~RecipeTest() {}
    }

    typedef std::shared_ptr<RecipeTest>
        RecipeTestPtr;
    typedef std::vector<RecipeTestPtr> RecipeTests;

    struct RecipeTestBase
    {
        virtual std::string dataUrl() { return ""; };

        std::string inflate(const std::string &data)
        {
            uLong sz = 1024 * 1024;
            std::vector<Bytef> buf(sz + 1, 0);

            if (Z_OK != uncompress(&buf[0], &sz, (const Bytef *)data.c_str(), (uLong)data.size()))
            {
                throw std::runtime_error("Zlib decompression failed");
            }

            return std::string(buf.begin(), buf.begin() + sz);
        }

        std::string toBase64(const std::string &data) const
        {
            std::vector<char> buf(data.size() * 2, 0);
            unsigned int sz = base64Encode((unsigned char *)data.c_str(), (unsigned int)data.size(), &buf[0], (unsigned int)buf.size());
            return std::string(buf.begin(), buf.begin() + sz);
        }

        std::string fromBase64(const std::string &data) const
        {
            std::vector<unsigned char> buf(data.size());
            unsigned int sz = base64Decode(data.c_str(), &buf[0], buf.size());
            return std::string(buf.begin(), buf.begin() + sz);
        }

        std::string digest(const std::string &data) const
        {
            return DeviceAuthority::getInstance()->doDigestSHA256(data);
        }

        std::string encrypt(const std::string &value, const std::string &key, const std::string &iv) const
        {
            const std::string res = DeviceAuthority::getInstance()->doCipherAES(key, iv, value, CipherModeEncrypt);
            if (res.empty())
            {
                throw std::runtime_error("Unable to encrypt:" + value);
            }
            return res;
        }

        // Create a BIO object from the given string holding an RSA key or Certificate
        BIOPtr createBIO(const std::string &key)
        {
            BIOPtr bio(BIO_new(BIO_s_mem()), BIO_free);
            if (!bio)
            {
                throw std::runtime_error("Failed to create buffer for Public Key");
            }
            else if ((unsigned)key.size() != (unsigned)BIO_write(bio.get(), key.c_str(), (int)key.size()))
            {
                throw std::runtime_error("Failed to write RSA Key into internal buffer");
            }
            return bio;
        }

        std::string sign(const std::string &data, const std::string &key)
        {
            RSAPtr rsaKey(PEM_read_bio_RSAPrivateKey(createBIO(key).get(), 0, 0, 0), RSA_free);
            if (!rsaKey)
            {
                throw std::runtime_error("Failed to create private key!");
            }

            unsigned int sigLen = RSA_size(rsaKey.get());
            std::vector<unsigned char> sig(sigLen, 0);

            if (0 == RSA_sign(NID_sha256, (const unsigned char *)data.c_str(), data.size(), &sig[0], &sigLen, rsaKey.get()))
            {
                throw std::runtime_error("Failed to sign data:" + data);
            }

            return std::string(sig.begin(), sig.begin() + sigLen);
        }

        std::string makeRecipeAsset(const std::string &script, const std::string &dataurl)
        {
            const std::string scriptB64 = toBase64(script);
            const std::string sig = toBase64(sign(digest(scriptB64), privateKey));
            const std::string data = "{ \"recipe\":\"" + scriptB64 + "\",\n" + "  \"sig\":\"" + sig + "\" }";
            std::stringstream ss;
            ss << "{\n"
               << "  \"assetType\": \"SCRIPT\",\n"
               << "  \"assetId\": \"57a4f09d-8db2-4d1e-833c-9c12749bc199\",\n"
               << "  \"autoRotate\": false,\n"
               << "  \"pollingRate\": -1,\n"
               << "  \"data\":\"" << toBase64(encrypt(data, aesKey, aesIV)) << "\"\n"
               << "  \"fileLink\":\"" << dataurl << "\"\n"
               << "}";
            return ss.str();
        }

        std::string handleRecipe(const std::string &recipe)
        {
            std::string results;
            std::string err;

            rapidjson::Document recipeJson;
            recipeJson.Parse(recipe.c_str());

            if (recipeJson.HasParseError())
            {
                throw std::runtime_error("Bad recipe JSON:" + recipe);
            }

            AssetManager proc;
            if (!proc.handleRecipe(recipeJson, aesKey, aesIV, "", results, err, 0))
            {
                throw std::runtime_error("Failed to handle recipe:" + err);
            }

            return results;
        }

        std::string extractData(const std::string &results)
        {
            rapidjson::Document resultsJson;
            resultsJson.Parse(results.c_str());
            if (resultsJson.HasParseError())
            {
                throw std::runtime_error("Bad JSON results:" + results);
            }

            std::string data;
            if (rapidjson::Value *v = rapidjson::Pointer("/data").Get(resultsJson))
            {
                data = fromBase64(v->GetString());
            }
            if (data.empty())
            {
                throw std::runtime_error("JSON missing 'data' field");
            }

            if (rapidjson::Value *v = rapidjson::Pointer("/compression").Get(resultsJson))
            {
                if (v->GetString() == std::string("zlib"))
                {
                    data = inflate(data);
                }
            }

            return data;
        }

        std::string extractLogs(const std::string &data)
        {
            rapidjson::Document dataJson;
            dataJson.Parse(data.c_str());
            if (dataJson.HasParseError())
            {
                throw std::runtime_error("Bad JSON data:" + data);
            }

            std::stringstream resultsStream;
            for (int i = 0; true; ++i)
            {
                std::stringstream pathStrm;
                pathStrm << "/logs/" << i << "/description";

                if (rapidjson::Value *v = rapidjson::Pointer(pathStrm.str().c_str()).Get(dataJson))
                {
                    resultsStream << v->GetString() << "\n";
                }
                else
                {
                    break;
                }
            }

            return resultsStream.str();
        }

        void run() override
        {
            const std::string recipe = makeRecipeAsset(script(), dataUrl());
            const std::string results = handleRecipe(recipe);
            const std::string data = extractData(results);
            const std::string logs = extractLogs(data);
            const std::string expectedLogs = expectedResults();

            if (logs != expectedLogs)
            {
                throw std::runtime_error("Recipe results mismatch - \nexpected:" + expectedLogs + "\nactual:" + logs);
            }
        }
    };

    //////////////////////////////////
    // Count Test
    //////////////////////////////////
    template <int N>
    struct CountRecipeTest : public RecipeTestBase
    {
        std::string name() override { return "CountRecipeTest<" + std::to_string(N) + ">"; }

        std::string expectedResults() override
        {
            std::stringstream ss;
            for (int i = 1; i <= N; ++i)
            {
                ss << i << "\n";
            }
            return ss.str();
        }
    };

    template <OSEnum E, int N>
    struct OSCountRecipeTest;
    template <int N>
    struct OSCountRecipeTest<WINDOWS> : CountRecipeTest<N>
    {
        std::string script() override
        {
            return (std::stringstream() << "for /L %%a in (1,1," << N << ") do echo %%a").str();
        }
    };

    template <int N>
    struct OSCountRecipeTest<LINUX> : CountRecipeTest<N>
    {
        std::string script() override
        {
            return (std::stringstream() << "for (( c=1; c<=" << N << "; c++ ))\ndo\n  echo \"$c\"\ndone").str();
        }
    };

    typedef OSCountRecipeTest<OS_ENUM, 10000> TenKCountTest;

    ///////////////////////////////////////////////
    // Compression decorator test
    ///////////////////////////////////////////////
    template <typename T>
    struct Zip : public T
    {
        std::string name() override { return "Zip<" + T::name() + ">"; }

        void run() override
        {
            struct ConfigManager
            {
                void setThreshold(long n) { config.override(CFG_RECIPE_LOG_SZ_COMPRESS_THRESHOLD, std::to_string(n)); }
                ConfigManager() { setThreshold(1); }                                 // Set low threshold to turn on compression
                ~ConfigManager() { setThreshold(std::numeric_limits<long>::max()); } // Set high threshold to turn off compression
            } cm;

            T::test();
        }
    };

    ///////////////////////////////////////////////
    // Blob Fetch Test
    ///////////////////////////////////////////////
    struct RecipeBlobFetchTestBase
    {
        std::string dataUrl()
        {
            return "https://fbnstorageaccount.blob.core.windows.net/myblobcontainer123/QuickStart_a871ee31-24a1-46f1-aed6-2ca5fbe1098b.txt";
        }

        std::string expectedResults() { return "Test Data!"; }
    };

    template <OSEnum E>
    struct RecipeBlobFetchTest;
    typedef RecipeBlobFetchTest<OS_ENUM> BlobFetchTest;

    template <>
    struct RecipeBlobFetchTest<LINUX> : public RecipeBlobFetchTestBase
    {
        std::string script() override { return "cat $DATAFILEPATH"; }
    };
    template <>
    struct RecipeBlobFetchTest<WINDOWS> : public RecipeBlobFetchTestBase
    {
        std::string script() override { return "type %DATAFILEPATH%"; }
    };

    ///////////////////////////////////////////////////
    // Recipe Test list
    ///////////////////////////////////////////////////
    RecipeTests recipeTests =
        {
            std::make_shared<TenKCountTest>(),
            std::make_shared<Zip<TenKCountTest>>(),
            std::make_shared<BlobFetchTest>()};
}

void doRecipeTests()
{
    std::cout << "Testing Recipe Assets..." << std::endl;
    for (auto test : recipeTests)
    {
        try
        {
            std::cout << "Running test " << test->name() << "..." << std::endl;
            test->run();
            std::cout << "Success!" << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Test failed: " << e.what() << std::endl;
        }
    }
    std::cout << "Asset Recipe Tests Complete" << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << argv[0] << " <config file>" << std::endl;
        exit(-1);
    }
    config.parse(argv[1]);
    storePublicKey();
    return doRecipeTests();
}
