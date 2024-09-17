/**
 * \file 
 *
 * \brief A test version of the event manager that records the total number of calls to each function
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to DeviceAuthority Inc. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from DeviceAuthority Inc.
 */

#ifndef TEST_EVENT_MANAGER_HPP
#define TEST_EVENT_MANAGER_HPP

#if defined(WIN32)
#include <Windows.h>
#endif // #if defined(WIN32)
#include <string>
#include "event_manager_base.hpp"

#if !defined(WIN32)
typedef void* HMODULE;
#endif // #ifndef _WIN32

class TestEventManager 
    : public EventManagerBase
{
    public:

    /// @brief Destructor
    virtual ~TestEventManager()
    {

    }

    bool initialise(const std::string &event_library_names) override
    {
		return true;
    }

    void teardown() override
    {
    }

    bool notifyStartup(const std::string &udi) override
    {
        m_startup_count++;
        return true;
    }

    bool notifyShutdown(const std::string &udi) override
    {
        m_shutdown_count++;
        return true;
    }

    bool notifyHeartbeat() override
    {
        m_heartbeat_count++;
        return true;
    }

    bool notifyRegistrationRequired() override
    {
        m_registration_required_count++;
        return true;
    }

    bool notifyRegistrationInProgress() override
    {
        m_registration_in_progress_count++;
        return true;
    }

    bool notifyRegistrationFailure(const std::string &error) override
    {
        m_registration_failure_count++;
        return true;
    }

    bool notifyRegistrationSuccess() override
    {
        m_registration_success_count++;
        return true;
    }

    bool notifyAuthorizationInProgress() override
    {
        m_authorization_in_progress_count++;
        return true;
    }

    bool notifyAuthorizationFailure(const std::string &error) override
    {
        m_authorization_failure_count++;
        return true;
    }

    bool notifyAuthorizationSuccess() override
    {
        m_authorization_success_count++;
        return true;
    }

    bool notifyCertificateReceived() override
    {
        m_certificate_received_count++;
        return true;
    }

    bool notifyCertificateStored(const std::string &subject_name, const std::string &location, const std::string& provider, bool encrypted) override
    {
        m_certificate_stored_count++;
        return true;
    }

    bool notifyCertificateFailure(const std::string &error) override
    {
        m_certificate_failure_count++;
        return true;
    }

    bool notifyCertificateDataReceived() override
    {
        m_certificate_data_received_count++;
        return true;
    }

    bool notifyPrivateKeyCreated() override
    {
        m_private_key_created_count++;
        return true;
    }

    bool notifyPrivateKeyReceived() override
    {
        m_private_key_received_count++;
        return true;
    }

    bool notifyPrivateKeyStored(const std::string &key_id, const std::string &location, const std::string &provider, bool encrypted) override
    {
        m_private_key_stored_count++;
        return true;
    }

    bool notifyPrivateKeyFailure(const std::string &error) override
    {
        m_private_key_failure_count++;
        return true;
    }
    
    bool notifyCSRCreated() override
    {
        m_csr_created_count++;
        return true;
    }
    
    bool notifyCSRDelivered() override
    {
        m_csr_delivered_count++;
        return true;
    }
    
    bool notifyCSRFailure(const std::string &error) override
    {
        m_csr_failure_count++;
        return true;
    }
    
    bool notifyAPMReceived(const std::string &username) override
    {
        m_apm_received_count++;
        return true;
    }
    
    bool notifyAPMSuccess(const std::string &username) override
    {
        m_apm_success_count++;
        return true;
    }
    
    bool notifyAPMFailure(const std::string &error) override
    {
        m_apm_failure_count++;
        return true;
    }
    
    bool notifySATReceived() override
    {
        m_sat_received_count++;
        return true;
    }
    
    bool notifySATSuccess() override
    {
        m_sat_success_count++;
        return true;
    }
    
    bool notifySATFailure(const std::string &error) override
    {
        m_sat_failure_count++;
        return true;
    }
    
    bool notifyGroupMetadataReceived() override
    {
        m_group_metadata_received_count++;
        return true;
    }
    
    bool notifyGroupMetadataSuccess() override
    {
        m_group_metadata_success_count++;
        return true;
    }
    
    bool notifyGroupMetadataFailure(const std::string &error) override
    {
        m_group_metadata_failure_count++;
        return true;
    }

    unsigned int getStartupCount() const
    {
        return m_startup_count;
    }

    unsigned int getShutdownCount() const
    {
        return m_shutdown_count;
    }

    unsigned int getRegistrationRequiredCount() const
    {
        return m_registration_required_count;
    }

    unsigned int getRegistrationInProgressCount() const
    {
        return m_registration_in_progress_count;
    }

    unsigned int getRegistrationFailureCount() const
    {
        return m_registration_failure_count;
    }

    unsigned int getRegistrationSuccessCount() const
    {
        return m_registration_success_count;
    }

    unsigned int getAuthorizationInProgressCount() const
    {
        return m_authorization_in_progress_count;
    }

    unsigned int getAuthorizationFailureCount() const
    {
        return m_authorization_failure_count;
    }

    unsigned int getAuthorizationSuccessCount() const
    {
        return m_authorization_success_count;
    }

    unsigned int getCertificateReceivedCount() const
    {
        return m_certificate_received_count;
    }

    unsigned int getCertificateStoredCount() const
    {
        return m_certificate_stored_count;
    }

    unsigned int getCertificateFailureCount() const
    {
        return m_certificate_failure_count;
    }

    unsigned int getCertificateDataReceivedCount() const
    {
        return m_certificate_data_received_count;
    }

    unsigned int getPrivateKeyCreatedCount() const
    {
        return m_private_key_created_count;
    }

    unsigned int getPrivateKeyReceivedCount() const
    {
        return m_private_key_received_count;
    }

    unsigned int getPrivateKeyStoredCount() const
    {
        return m_private_key_stored_count;
    }

    unsigned int getPrivateKeyFailureCount() const
    {
        return m_private_key_failure_count;
    }

    unsigned int getCsrCreatedCount() const
    {
        return m_csr_created_count;
    }

    unsigned int getCsrDeliveredCount() const
    {
        return m_csr_delivered_count;
    }

    unsigned int getCsrFailureCount() const
    {
        return m_csr_failure_count;
    }

    unsigned int getApmReceivedCount() const
    {
        return m_apm_received_count;
    }

    unsigned int getApmSuccessCount() const
    {
        return m_apm_success_count;
    }

    unsigned int getApmFailureCount() const
    {
        return m_apm_failure_count;
    }

    unsigned int getSatReceivedCount() const
    {
        return m_sat_received_count;
    }

    unsigned int getSatSuccessCount() const
    {
        return m_sat_success_count;
    }

    unsigned int getSatFailureCount() const
    {
        return m_sat_failure_count;
    }

    unsigned int getGroupMetadataReceivedCount() const
    {
        return m_group_metadata_received_count;
    }

    unsigned int getGroupMetadataSuccessCount() const
    {
        return m_group_metadata_success_count;
    }

    unsigned int getGroupMetadataFailureCount() const
    {
        return m_group_metadata_failure_count;
    }

    private:
    unsigned int m_startup_count{ 0 };
    unsigned int m_shutdown_count{ 0 };
    unsigned int m_heartbeat_count{ 0 };
    unsigned int m_registration_required_count{ 0 };
    unsigned int m_registration_in_progress_count{ 0 };
    unsigned int m_registration_failure_count{ 0 };
    unsigned int m_registration_success_count{ 0 };
    unsigned int m_authorization_in_progress_count{ 0 };
    unsigned int m_authorization_failure_count{ 0 };
    unsigned int m_authorization_success_count{ 0 };
    unsigned int m_certificate_received_count{ 0 };
    unsigned int m_certificate_stored_count{ 0 };
    unsigned int m_certificate_failure_count{ 0 };
    unsigned int m_certificate_data_received_count{ 0 };
    unsigned int m_private_key_created_count{ 0 };
    unsigned int m_private_key_received_count{ 0 };
    unsigned int m_private_key_stored_count{ 0 };
    unsigned int m_private_key_failure_count{ 0 };
    unsigned int m_csr_created_count{ 0 };
    unsigned int m_csr_delivered_count{ 0 };
    unsigned int m_csr_failure_count{ 0 };
    unsigned int m_apm_received_count{ 0 };
    unsigned int m_apm_success_count{ 0 };
    unsigned int m_apm_failure_count{ 0 };
    unsigned int m_sat_received_count{ 0 };
    unsigned int m_sat_success_count{ 0 };
    unsigned int m_sat_failure_count{ 0 };
    unsigned int m_group_metadata_received_count{ 0 };
    unsigned int m_group_metadata_success_count{ 0 };
    unsigned int m_group_metadata_failure_count{ 0 };
};

#endif // #ifndef TEST_EVENT_MANAGER_HPP
