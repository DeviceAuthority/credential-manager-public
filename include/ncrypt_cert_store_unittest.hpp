
/*
 * Copyright (c) 2024 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Unit tests of the windows cert store that writes to the Windows Certificate Store using the ncrypt API
 */
#ifndef NCRYPT_CERT_STORE_UNITTEST_HPP
#define NCRYPT_CERT_STORE_UNITTEST_HPP

#include <Windows.h>
#include <string>
#include "gtest/gtest.h"
#include "ncrypt_cert_store.hpp"


class NcryptCertStoreTest : public testing::Test
{
    public:
    NcryptCertStore m_cert_store;

    NcryptCertStoreTest()
        : m_cert_store{ NcryptCertStore(true, false) }
    {
        
    }

    void SetUp() override
    {
        ASSERT_TRUE(m_cert_store.initialize());
    }

    void TearDown() override
    {
        m_cert_store.shutdown();
    }
};

TEST_F(NcryptCertStoreTest, CreateKeyPair)
{
    BCRYPT_ALG_HANDLE alg_handle;
    NTSTATUS ret = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_RSA_ALGORITHM, NULL, 0); // MS_PLATFORM_CRYPTO_PROVIDER
    if (BCRYPT_SUCCESS(ret))
    {
        BCRYPT_KEY_HANDLE key_handle = NULL;
        ret = BCryptGenerateKeyPair(alg_handle, &key_handle, 2048, 0);
        if (BCRYPT_SUCCESS(ret))
        {
            ret = BCryptFinalizeKeyPair(key_handle, 0);
            ASSERT_TRUE(BCRYPT_SUCCESS(ret));

            ULONG cbKey = 0;
            PUCHAR pbKey = 0;
            ret = BCryptExportKey(key_handle, 0, BCRYPT_RSAFULLPRIVATE_BLOB, pbKey, cbKey, &cbKey, 0);
            ASSERT_TRUE(BCRYPT_SUCCESS(ret));
        }
    }
}

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

TEST_F(NcryptCertStoreTest, VerifyTpmAvailable)
{
    bool has_tpm_support = false;
    PCRYPT_PROVIDERS p_buffer = NULL;
    ULONG buffer_len = 0;
    NTSTATUS status = BCryptEnumRegisteredProviders(&buffer_len, &p_buffer);
    if (NT_SUCCESS(status))
    {
        if (p_buffer != NULL)
        {
            // Enumerate the providers.
            for (ULONG i = 0; i < p_buffer->cProviders; i++)
            {
                printf("%S\n", p_buffer->rgpszProviders[i]);
                if (wcscmp(p_buffer->rgpszProviders[i], MS_PLATFORM_CRYPTO_PROVIDER) == 0) {
                    has_tpm_support = true;
                }
            }
        }
    }

    if (NULL != p_buffer)
    {
        /*
        Free the memory allocated by the
        BCryptEnumRegisteredProviders function.
        */
        BCryptFreeBuffer(p_buffer);
    }

    ASSERT_TRUE(has_tpm_support);
}

void enumerateKeys(NCRYPT_PROV_HANDLE provider)
{
    NCryptKeyName* pKeyName = NULL;
    PVOID pEnumState = NULL;
    SECURITY_STATUS status;

    status = NCryptEnumKeys(provider, NULL, &pKeyName, &pEnumState, NCRYPT_MACHINE_KEY_FLAG);

    if (status == ERROR_SUCCESS) 
    {
        printf("Key Name: %S\n", pKeyName->pszName);
    }
    else 
    {
        printf("NCryptEnumKeys failed!\n");
    }

    if (pKeyName != NULL) 
    {
        NCryptFreeBuffer(pKeyName);
    }
}

TEST_F(NcryptCertStoreTest, PrintKeys)
{
    NCRYPT_PROV_HANDLE provider = NULL;
    SECURITY_STATUS sec_status = NCryptOpenStorageProvider(
        &provider,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0);

    enumerateKeys(provider);

    if (provider)
    {
        NCryptFreeObject(provider);
    }
}

TEST_F(NcryptCertStoreTest, createExportAndDeletePfxTest)
{
    const std::string certificate = "-----BEGIN CERTIFICATE-----\nMIIDFDCCAfwCAQMwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UEBhMCQVUxEzARBgNV\nBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\nZDEUMBIGA1UEAwwLaW50ZXIgaW50ZXIwHhcNMjQwNTEzMTE1ODUyWhcNMjUwNTEz\nMTE1ODUyWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8G\nA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAkkmEOhwgWEqIpju5lL22jYJCQ39ZPL8yXBJr5qznMyHF\npnZBn9iaHGpkPLdCuFT+ltfp2UtxGq/qEUo1TYlrYAClytpm2no2ykVk6JB0njrB\nF5mw4YPGblNSXZXyRVETWRN9sVvmijmLvvWk29Wrr5efNy2qwPgVVBlrfHf3VuSr\nBx0W7kjgeJ2NQB6WGDTBCNAY4fQVbKvdz4+mD2p7uuivPlo1muyb30voDHrxuNZM\n9wlY1hY5I0mUxOVCoGRh0ylPqDy5XlzNvUzDeCrGx0NCGSD8WLjNmpcrkIr5Dd8q\nG6Ptjj5wNHyI3PM3fam4wH4vUC5d0B6cfA9JoJMnJwIDAQABMA0GCSqGSIb3DQEB\nCwUAA4IBAQCWTsdnSYuLNHhMZUL3Cg2YCNd4N7sLsO3LFJNyVsGAyMhLxmPW1WYp\nrOx1b2DjgLjz1WxwLPq5QnfQ8YDfNHtnXTrRHe4PS7+bQk6AmFbpZR6z0iKb5q7D\nJzZtbmtLYPUshpGMU9t1XnSig2tPTbRcNzQbq6z2mKI07mpIMzpRCaJJL09a14OV\nlqBMdk2TTIdJJ0QgEsKbqfFCl9OvIOw+PvtWZXFkig2LyFYcyifdx+nkuQlm57LG\nxDZaftAXS6VaarzTBsBOm8pyjPsPxJUwxH4KpxJ6a2wN/Fn5KZhogJSUzZDGWhV8\nxy30rntRnNktRSKs5SbZveuOD8KjKxPF\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIDKDCCAhACAQIwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCQVUxEzARBgNV\nBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\nZDESMBAGA1UEAwwJdGVzdCB0ZXN0MB4XDTI0MDUxMzExNTgxNFoXDTI1MDUxMzEx\nNTgxNFowWzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNV\nBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLaW50ZXIgaW50\nZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8gXqynWXfgHSu8Vet\n1gn4Nxs5MxNYtgubbtYLR8d4UCsRR+GET9/eFiG2ksUvsQ1Iv/f1vYkbAj6vqsga\nyhYcOkIBo4x0TN8z3I79eoAjeZQkH/jXs0vlmtHIoRxgLM4M0n5R6jICxGfeXakh\n7BMWAjPuGSkTMJk0lRFufkkdAEDjXUkAt7CrRFrA6mWh77lmOi0Yx/rviDxiLPZ3\nlfDhhRkCdF7daazIvAjVdmn/BA6IwJkP8YhzlYJCWyzS9VmfW1zIsUAo/WVgAw7T\nJQpBsIOUDt59ExjMiXzqy2TzoE++r28sRl1K0znI170AeHCZijUlqDpmm9q20PRL\n4KgFAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJwX5hA5Nr0y3YEZIbbxhu80kHvO\nUKKKKBSNOQIEW3RAZk6svhZb6vj075pmZrdG60TrlrmZczV0KRVUUnhXh5iT5gEf\nTtfhU+mmK3z+MsQEhaJNWHYcOP0sJlyrKhlUJjzl8gaZ2sP9q4EKj1R98p1XWzmC\nJWXfwe5wg7HbUzt18x6ifSf6QKMmLqPLCDKXnE+O5Th3YO/yCnFoTT0IIIEfv0Bd\nmhYlxVxRycAaywBGX907/g8siAM4gx0ZnWS4z58mnG/FxcuhiTeYLWa3Hqh7Fpg/\nbyWt+K+diYjemeS3b0DwckW6tp4BiDGMsQJ0NHTafT4z+VJ230Fzn0QfOMU=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIDJjCCAg4CAQEwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCQVUxEzARBgNV\nBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\nZDESMBAGA1UEAwwJdGVzdCB0ZXN0MB4XDTI0MDUxMzExNTY1MFoXDTI1MDUxMzEx\nNTY1MFowWTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNV\nBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDESMBAGA1UEAwwJdGVzdCB0ZXN0\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsIMri9wZBQEyEXP82Sf0\nXCxVx529IPDsjz4AnEBppNDXBn8QK8o6BYjetPudiqNuXsyzTBXZR1/4p0GxYIzL\n+jHJqTfNEmH5hI4vA0UJEAEo9ERB3AiFABjC4q2zmmkFYW92S4oXZVO4jKSt+FO5\n/SSShLXHKSyUN8u4SPCJ/t0WfV6LTOUflYzWb0whWt8ezVPFjPO2Zy1Wc30/rSEz\n5GpG+vHPnCCMtBsPgt6NaN3gBWf47wYLBeI9dooCOY5OkbpWfPK6bl8Epti13EXb\nO1y1hqIHJRFdDuKvOPqWFGffqa6xjQ4u7FyGpuSAtOFaV5ntRcG13E6o8DhmMIHL\nVQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAR2M9fDe9x8ZNibWeYuD7WYAIedjI/\nNZsYdylD+5bII2Vj1qDOlTlvMgpfBqu1RvUXmHedTpmjcjGduATKsg9HE31HrGrP\n+y1CpRQ/ePXIF7HEveFv6oyJE8LzRetB5h9MqFosPImmJYWx3bvW3kHP8aixoq1o\nDDqyY6jijrIW2w8NhcyrjEje3GiiXpUOI66OpzH+U1a+33icv5enVbKDsxg7JISF\nGwz4SMpKKkg5OEmky0ZkFIupk09LhMq0DsnOuZCKvipCjvrhfP7UMsE0PdXWYgl2\nm8nmpVOinTTuIfmlxnpS9PD/s5CH4zwyD6BvHE0OCzYiVOS0fwpc90Ak\n-----END CERTIFICATE-----\n";
    const std::string private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA2tCLyLsIsmSr+OmPsjJGPtUBjS9PxIBJ7N+XKuIM7QO3EmCP\nHg76HWBRNrfAuYTiVnK/M5Z3jxOtgH4FYIvWXrmWmZ/0xl2NPAwIbCtDfG+1Mjcd\nvnj+3Wn7lOLHo88lV+I8yPlVtVX6DqKbNwZGwivk40qmiSvhDyxuE/WfG9GdT6Qh\nrqgLrgg3tinn4rz3gGRp9AFfnIb1Q3Mlecyg8J+O53M0b0DhGwTxC0pocd90aMRg\n/+Dktq9hNJxZfLcxyXejKL2ezrFH0ZcXwtTy26xzS4SIx19W0000g+WrJp43uKGP\n+/QM9w/8DPUzBmeA6/0KBxPDVKhvR+9CUULzhwIDAQABAoIBAFCp43X2mQCmgw0K\nENp4lROxk1ZYNBg00Mu9Ky14UpqHLZRdOzUyATsWGCpLOAVL+uIyf9DFLcL1VpcR\nHetW8YpO8Tkl0ebUcu3JY8t4cXLsfUgLMHBYi1/VI5ThuwXkpZgNwym1XMax8LI3\neG+i5S/MXZ76lITpw5hD4TqDaAmpIBr41dJVF64Kh+pJndKDxDxXpbSJpxl65ZZm\nuBqScp1w7wqmdSUkujDCIFMkuRQ3Yu6S9galJvWDpAt4QH7ayc7+ZIs406/yeMs2\nqDi62uLQbR4jVkzWAjyYwgaRLm0gNF0LdlXxp6OUtCfDe4h2im96H/ndAVcXfEXg\nbf/4aPUCgYEA+A5rgKYPHMAppRSCJvPdZDJEBPSai/drsDfRns7Li+L3ALmhnKX1\nh3WiaPR8VvaPUi80qDdP7mcTinlXrf5xKfqeSSxZ9r4rpN/3WNPmf4k/Fo/i4OdW\nU8udKhb0v5nsxbRDPkxopewITX1grTKp2VrUySaWSINtr+plxtJHiCMCgYEA4dJm\np/DIgqUMvxL0jzK/JJgt/S8tJQXQLb8V8msKGQBq+xS8x1zE2TbiRhULpAXq5qBu\nT4/GFzMwRTeniII1AYLGxUWMEPWMLrN45TgAmcIQ4QFUKSh5IUPqsegHuoXWA1z1\nz0CR9fEKAVgpDBUGBc9RyTFD+iFSs6cWtz0ci00CgYBBgL1OmYtAElZs6z97PcZm\noQdpL5ZoA4wCWpsWDpGdfO+w11Qf44s0nBGpGXaEGFO8Zg7HpOOMlteIJ4bJwXjs\nluuZcwbGq20m+qV8ZWhmoT1xnclRjoUzV39HEAzNU748bt+a4d54gh2nKMaQteI4\nLU4nV/MzbtFWNNVvbTPKdQKBgQChHWJMk8gbHfL4KGf/+u7RBxpYt134OiuLV/gq\nmx/7MochWGxPuOphJ31NDxrdDbPIk9HgRe3JA6Z+2/RVusBisZFrkfEa8HXxo+6v\na8NR8FnmjvIi41N43mIGSEurUm2cvKhME/+Pf0fqKaIvkphXcNEjQFkFjtzYfHAC\nkEFbSQKBgQC+U3bTarH6TwNCN6Vz29ayj1Am2Mw/fx4ZqLHIxhW8te7AYNDjCgT2\n2nqm7igbWhAYp+3x9U+oy5JRuGKrUQ/01YuZjyGknVEPBSCNiCou4OkkJIba1MNp\nA4f1py59eBcntU/EsHHdJK6ogpOHH9y82iCx9rboXB5rr5buxKVWPQ==\n-----END RSA PRIVATE KEY-----\n";
    const std::string subject_name = "Internet Widgits Pty Ltd";

    ASSERT_TRUE(m_cert_store.importPrivateKey(private_key, subject_name));

    std::vector<std::string> certs{};
    ASSERT_TRUE(m_cert_store.extractCertsFromCertificateChain(certificate, certs));
    ASSERT_TRUE(m_cert_store.importCertChain(certs));

    ASSERT_TRUE(m_cert_store.deleteCertFromCertStore(subject_name));
    ASSERT_FALSE(m_cert_store.deleteCertFromCertStore(subject_name)); // ensure it no longer exists
}

TEST_F(NcryptCertStoreTest, extractSubjectNameFromCertificate)
{
    const std::string certificate = "-----BEGIN CERTIFICATE-----\nMIIDETCCAfkCFBWeseQkSi3duBP6ieYfi5hx88kaMA0GCSqGSIb3DQEBCwUAMEUx\nCzAJBgNVBAYTAkdCMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\ncm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjQwMzA0MTcyNDI1WhcNMjUwMzA0MTcy\nNDI1WjBFMQswCQYDVQQGEwJHQjETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE\nCgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC\nAQ8AMIIBCgKCAQEAk90/qjsel7r2xxhdShWxb7WkAajrzK+2PTZZ5LKmx7WHHSHy\n+geU5qYPgk7Po1UUouOKnTAwxglLe3d0pAgNHoYzAHHCK9LXNntpgz4XrnL2LJhT\n7YCuwMN3TBzqXHmZy2BPa7tyDOoqljyewD5+ggT3slftnGvXKBhUZMQ4pxQBjAeY\n7d8LRBwZoK2DfuGFgicgpna+pjr6k+P7oWDLcUkjOGCHBx2JX52dpTz3jGWbYnEc\n+QY4NBgOVZ49Y6dbk6MONGsdlo5HYm1XnotpZKrdHXzqEGqKJV+L1xgJzd1vU6XL\n5xrNCWY0SdVkK3f3sPfRkUcXdLnNLztBun2AMwIDAQABMA0GCSqGSIb3DQEBCwUA\nA4IBAQAi8cSB2ko9gVikjc9s70Lr2gNzsLEEM7zWvNz+zFr0yczRkoxG/3xxMLan\nTvdKjHzGBUXXpwSmqBziVqkYyx6C0e3Z77ql0XGnWVIFLepsqVvYxyHezo2Lp4+M\nKwG3f1sYOrg3LAQPsrcwi1fFJTj82uNv6QrGnnjitzPs4RKiTTnF+tAkNP/d6Y8G\nCX0mZa68lsM9VQ939yTZ7qT+W7kfvWPc6eZ8gz+PtnEEViFBW7Sn6aub7y4VmRXT\n8QGsR7mduEEh3EIos61bmI8JkS7/asRcFd5o92eXRbs/R5+kTKqRSoq5lbhEXE0J\nVDSEnab86efNI852k/r3gWgzaw6n\n-----END CERTIFICATE-----\n";
    const std::string expected_subject_name = "Internet Widgits Pty Ltd";

    std::string subject_name;
    ASSERT_TRUE(m_cert_store.getSubjectNameFromCertificate(certificate, subject_name));
    ASSERT_STREQ(expected_subject_name.c_str(), subject_name.c_str());
}

TEST_F(NcryptCertStoreTest, deleteCertFailureNonExistentSubjectName)
{
    const std::string subject_name = "I don't exist";

    ASSERT_FALSE(m_cert_store.deleteCertFromCertStore(subject_name));
}

#endif // #ifndef NCRYPT_CERT_STORE_UNITTEST_HPP
