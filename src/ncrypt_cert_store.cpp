
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Implementation of the win cert store that writes to the Windows Certificate Store using the Ncrypt API
 */

#include <Windows.h>
#include <iostream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <tchar.h>
#include <stdio.h>
#include <wincrypt.h>
#include <ncrypt.h>

#include "log.hpp"
#include "ncrypt_cert_store.hpp"

#pragma comment(lib, "ncrypt.lib")

bool NcryptCertStore::initialize()
{
    // Verifies that we have access to the certificate store through the ncrypt API
	NCRYPT_PROV_HANDLE provider_handle = 0;
    SECURITY_STATUS sec_status = NCryptOpenStorageProvider(
        &provider_handle,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0);
	if (provider_handle)
	{
		Log::getInstance()->printf(Log::Debug, "Using Microsoft Platform Crypto Provider");
		NCryptFreeObject(provider_handle);
	}
	else
	{
		Log::getInstance()->printf(Log::Debug, "Failed to open storage provider Microsoft Platform Crypto Provider, falling back to legacy provider");
	}
	return sec_status == ERROR_SUCCESS;
}

bool NcryptCertStore::shutdown()
{
    return true;
}

bool NcryptCertStore::importPrivateKey(const std::string& private_key, const std::string& key_id)
{
	LPBYTE p_buffer = NULL;
	ULONG buffer_len = cryptPrivateKeyToBinary(private_key, p_buffer);

	if (buffer_len == 0 || p_buffer == NULL)
	{
		return false;
	}

	LPBYTE key_blob = NULL;
	DWORD key_blob_len = decodePrivateKey(p_buffer, buffer_len, CNG_RSA_PRIVATE_KEY_BLOB, key_blob);
	LocalFree(p_buffer);
	p_buffer = NULL;

	if (key_blob_len == 0 || key_blob == NULL)
	{
		return false;
	}

	bool success = false;
	NCRYPT_PROV_HANDLE provider_handle = NULL;
	NCRYPT_KEY_HANDLE key_handle = NULL;
	SECURITY_STATUS sec_status = NCryptOpenStorageProvider(
		&provider_handle,
		MS_PLATFORM_KEY_STORAGE_PROVIDER,
		0);
	if (sec_status == ERROR_SUCCESS)
	{
		// Some weird subject name conversion to wide string then string?
		const std::wstring wide_subject_name(key_id.begin(), key_id.end());
		const std::string subject_name(wide_subject_name.begin(), wide_subject_name.end());

		// Delete existing certificate, if it exists
		deleteCertFromCertStore(subject_name);

		SECURITY_STATUS sec_status = NCryptCreatePersistedKey(
			provider_handle,                   //IN: provider handle
			&key_handle,                       //OUT: Handle to key
			NCRYPT_RSA_ALGORITHM,              //IN: CNG Algorithm Identifiers. NCRYPT_RSA_ALGORITHM creates public key
			wide_subject_name.c_str(),         //IN: Key name. If NULL, the key does not persist
			0,                                 //IN: Key type
			NCRYPT_OVERWRITE_KEY_FLAG);
		if (sec_status == ERROR_SUCCESS)
		{
			sec_status = NCryptSetProperty(
				key_handle,
				BCRYPT_RSAFULLPRIVATE_BLOB,
				key_blob,
				key_blob_len,
				NCRYPT_PERSIST_FLAG | NCRYPT_SILENT_FLAG);

			if (sec_status == ERROR_SUCCESS)
			{
				success = NCryptFinalizeKey(key_handle, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS;
			}
		}
		NCryptFreeObject(provider_handle);
	}
	LocalFree(key_blob);
	key_blob = NULL;

	// Create temporary self-signed certificate to retain the private key in key store. This is removed once we receive a signed certificate
	// in response to a CSR sent to KeyScaler.
	success = success && createSelfSignedCertificate(key_handle, key_id);

	if (key_handle)
	{
		NCryptFreeObject(key_handle);
	}
	return success;
}

bool NcryptCertStore::importCertChain(const std::vector<std::string>& certs)
{
	if (m_leaf_only)
	{
		const std::string leaf_cert = certs.back();

		if (!importCertificate(leaf_cert))
		{
			Log::getInstance()->printf(Log::Error, "Failed to import certificate %s", leaf_cert.c_str());
			return false;
		}
		return true;
	}

	for (const auto& cert : certs)
	{
		if (!importCertificate(cert))
		{
			Log::getInstance()->printf(Log::Error, "Failed to import certificate %s", cert.c_str());
			return false;
		}
	}

	return true;
}

bool NcryptCertStore::importCertificate(const std::string& certificate) const
{
	LPBYTE p_cert = NULL;
	ULONG cert_len = cryptCertificateToBinary(certificate, p_cert);
	if (cert_len == 0 || p_cert == NULL)
	{
		return false;
	}

	PCCERT_CONTEXT p_cert_context = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, p_cert, cert_len);
	if (!p_cert_context)
	{
		LocalFree(p_cert);
		return false;
	}

	std::wstring wide_subject_name{};
	if (!getSubjectNameFromCertificateContext(p_cert_context, wide_subject_name))
	{
		CertFreeCertificateContext(p_cert_context);
		LocalFree(p_cert);
		return false;
	}

	// Ensure certificate key association is using MS PLATFORM CRYPTO PROVIDER security provider
	CRYPT_KEY_PROV_INFO key_info = {(LPWSTR)wide_subject_name.c_str(), MS_PLATFORM_CRYPTO_PROVIDER, 0, 0, 0, NULL, 0};
	if (!CertSetCertificateContextProperty(
		p_cert_context,
		CERT_KEY_PROV_INFO_PROP_ID,
		0,
		&key_info))
	{
		CertFreeCertificateContext(p_cert_context);
		LocalFree(p_cert);
		return false;
	}

	bool success = false;
	NCRYPT_PROV_HANDLE provider_handle = NULL;
	SECURITY_STATUS sec_status = NCryptOpenStorageProvider(
		&provider_handle,
		MS_PLATFORM_CRYPTO_PROVIDER,
		0);
	if (sec_status == ERROR_SUCCESS)
	{
		NCRYPT_KEY_HANDLE key_handle = NULL;
		if (getPrivateKeyHandleByCertificateSubjectName({ wide_subject_name.begin(), wide_subject_name.end() }, key_handle))
		{
			// Set the cert property on the key
			if (NCryptSetProperty(
				key_handle,
				NCRYPT_CERTIFICATE_PROPERTY,
				p_cert,
				cert_len,
				0) != ERROR_SUCCESS)
			{
				Log::getInstance()->printf(Log::Error, "Failed to set private key property");
			}
			NCryptFreeObject(key_handle);
		}

		// Delete placeholder cert before adding the replacement
		deleteCertFromCertStore({ wide_subject_name.begin(), wide_subject_name.end() });

		// Add certificate to store
		HCERTSTORE cert_store_handle = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, m_system_store_location, L"My");
		if (cert_store_handle)
		{
			if (CertAddCertificateContextToStore(cert_store_handle,
				p_cert_context,
				CERT_STORE_ADD_REPLACE_EXISTING,
				NULL))
			{
				success = true;
			}
			CertCloseStore(cert_store_handle, NULL);
		}
		NCryptFreeObject(provider_handle);
	}
	CertFreeCertificateContext(p_cert_context);
	LocalFree(p_cert);
	p_cert = NULL;

	return success;
}

bool NcryptCertStore::deleteCertFromCertStore(const std::string &subject_name) const
{
	bool success = false;

	HCERTSTORE system_cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, m_system_store_location, L"My");
	if (system_cert_store)
	{
		PCCERT_CONTEXT p_cert_context = nullptr;
		while (p_cert_context = CertEnumCertificatesInStore(system_cert_store, p_cert_context))
		{
			std::wstring wide_enum_subject_name;
			if (getSubjectNameFromCertificateContext(p_cert_context, wide_enum_subject_name))
			{
				const std::string enum_subject_name(wide_enum_subject_name.begin(), wide_enum_subject_name.end());
				if ((strcmp(enum_subject_name.c_str(), subject_name.c_str()) == 0))
				{
					PCCERT_CONTEXT p_delete_context = CertDuplicateCertificateContext(p_cert_context);
					success = CertDeleteCertificateFromStore(p_delete_context) == TRUE;
				}
			}
		}

		CertCloseStore(system_cert_store, 0);
	}

	return success;
}

bool NcryptCertStore::getPrivateKeyHandleByCertificateSubjectName(const std::string& subject_name, NCRYPT_KEY_HANDLE& private_key_handle) const
{
	CERT_NAME_BLOB nameBlob{ 0 };
	std::wstring x500_string = L"CN=";
	x500_string += std::wstring(subject_name.begin(), subject_name.end());
	if (!CertStrToNameW(X509_ASN_ENCODING, x500_string.c_str(), 0, nullptr, nameBlob.pbData, &nameBlob.cbData, nullptr))
	{
		return false;
	}
	nameBlob.pbData = new UCHAR[nameBlob.cbData];
	if (!CertStrToNameW(X509_ASN_ENCODING, x500_string.c_str(), 0, nullptr, nameBlob.pbData, &nameBlob.cbData, nullptr))
	{
		return false;
	}

	bool success = false;
	HCERTSTORE cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, m_system_store_location, L"My");
	if (cert_store)
	{
		PCCERT_CONTEXT cert_context = CertFindCertificateInStore(cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_NAME, &nameBlob, 0);
		if (cert_context)
		{
			DWORD key_spec = 0;
			CryptAcquireCertificatePrivateKey(cert_context, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, NULL, &private_key_handle, &key_spec, 0);
			CertFreeCertificateContext(cert_context);
			success = true;
		}
		CertCloseStore(cert_store, 0);
	}

	return success;
}

bool NcryptCertStore::createSelfSignedCertificate(NCRYPT_KEY_HANDLE key_handle, const std::string& subject_name) const
{
	std::wstring wide_subject_name{ subject_name.begin(), subject_name.end() };

	CRYPT_KEY_PROV_INFO key_info;
	memset(&key_info, 0, sizeof(key_info));
	key_info.pwszContainerName = (LPWSTR)wide_subject_name.c_str();
	key_info.pwszProvName = MS_PLATFORM_CRYPTO_PROVIDER;
	key_info.dwProvType = 0;
	key_info.dwKeySpec = 0;

	CERT_NAME_BLOB name_blob{ 0 };
	std::wstring x500_string = L"CN=";
	x500_string += wide_subject_name;
	if (!CertStrToNameW(X509_ASN_ENCODING, x500_string.c_str(), 0, nullptr, name_blob.pbData, &name_blob.cbData, nullptr))
	{
		return false;
	}
	name_blob.pbData = new UCHAR[name_blob.cbData];
	if (!CertStrToNameW(X509_ASN_ENCODING, x500_string.c_str(), 0, nullptr, name_blob.pbData, &name_blob.cbData, nullptr))
	{
		return false;
	}

	bool success = false;
	CERT_EXTENSIONS cert_extensions{ 0 };
	PCCERT_CONTEXT cert_context = CertCreateSelfSignCertificate(key_handle, &name_blob, 0, &key_info, nullptr, nullptr, nullptr, &cert_extensions);
	if (cert_context)
	{
		HCERTSTORE cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, m_system_store_location, L"My");
		if (cert_store)
		{
			success = CertAddCertificateContextToStore(cert_store, cert_context, CERT_STORE_ADD_REPLACE_EXISTING, nullptr);
			CertCloseStore(cert_store, 0);
		}
		CertFreeCertificateContext(cert_context);
	}

	return success;
}
