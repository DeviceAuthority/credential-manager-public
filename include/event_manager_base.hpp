/**
 * \file 
 *
 * \brief Base class for event management implementations that raise event notifications
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to DeviceAuthority Inc. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from DeviceAuthority Inc.
 */

#ifndef EVENT_MANAGER_BASE_HPP
#define EVENT_MANAGER_BASE_HPP

#include <string>

class EventManagerBase
{
    public:
    /// @brief Destructor
    virtual ~EventManagerBase() {}
    
    /// @brief Loads and initialises event libraries
    /// @param event_library_names Comma separated list of event library names
    /// @return True if successfully initialised or no event library 
    /// available, false if failure to load event library
    virtual bool initialise(const std::string &event_library_names) = 0;

    /// @brief Shutdown the event library
    virtual void teardown() = 0;

    /// @brief Raises a startup event notification
    /// @param udi The device UDI
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyStartup(const std::string &udi) = 0;

    /// @brief Raises a shutdown event notification
    /// @param udi The device UDI
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyShutdown(const std::string &udi) = 0;

    /// @brief Raise a heartbeat event notification
    /// @return True if successfully sent notification or no event library loaded 
    virtual bool notifyHeartbeat() = 0;

    /// @brief Raises a registration required event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyRegistrationRequired() = 0;

    /// @brief Raises a registration in-progress event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyRegistrationInProgress() = 0;

    /// @brief Raises a registration failure event notification
    /// @param error The error string
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyRegistrationFailure(const std::string &error) = 0;

    /// @brief Raises a registration success event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyRegistrationSuccess() = 0;

    /// @brief Raises an authorization in-progress event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyAuthorizationInProgress() = 0;

    /// @brief Raises an authorization failure event notification
    /// @param error The error string
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyAuthorizationFailure(const std::string &error) = 0;

    /// @brief Raises an authorization success event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyAuthorizationSuccess() = 0;

    /// @brief Raises a certificate received event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyCertificateReceived() = 0;

    /// @brief Raises a certificate stored event notification
    /// @brief subject_name The certificate subject name
    /// @param location The location of the stored certificate
    /// @param provider The name of the storage provider used
    /// @param encrypted True if the certificate is encrypted, else false
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyCertificateStored(const std::string &subject_name, const std::string &location, const std::string& provider, bool encrypted) = 0;

    /// @brief Raise a certificate failure event notification
    /// @param error The error string
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyCertificateFailure(const std::string &error) = 0;

    /// @brief Raise a certificate data received event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyCertificateDataReceived() = 0;

    /// @brief Raise a private key created event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyPrivateKeyCreated() = 0;

    /// @brief Raise a private key received event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyPrivateKeyReceived() = 0;

    /// @brief Raise a private key stored event notification
    /// @brief key_identifier The key identifier
    /// @param location The location of the stored private key
    /// @param provider The storage provider name
    /// @param encrypted True if the private key is encrypted, else false
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyPrivateKeyStored(const std::string &key_identifier, const std::string &location, const std::string &provider, bool encrypted) = 0;

    /// @brief Raise a private key failure event notification
    /// @param error The error string
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyPrivateKeyFailure(const std::string &error) = 0;
    
    /// @brief Raise a certificate signing request created event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyCSRCreated() = 0;
    
    /// @brief Raise a certificate signing request delivered event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyCSRDelivered() = 0;
    
    /// @brief Raise a certificate signing request failure event notification
    /// @param error The error string
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyCSRFailure(const std::string &error) = 0;
    
    /// @brief Raise an APM received event notification
    /// @param username The username of the user whose password is going to be changed
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyAPMReceived(const std::string &username) = 0;
    
    /// @brief Raise an APM success event notification
    /// @param username The username of the user whose password was changed 
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyAPMSuccess(const std::string &username) = 0;
    
    /// @brief Raise an APM failure event notification
    /// @param error The error string
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyAPMFailure(const std::string &error) = 0;
    
    /// @brief Raise a script asset transfer received event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifySATReceived() = 0;
    
    /// @brief Raise a script asset transfer success event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifySATSuccess() = 0;
    
    /// @brief Raise a script asset transfer failure event notification
    /// @param error The error string
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifySATFailure(const std::string &error) = 0;
    
    /// @brief Raise a group metadata received event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyGroupMetadataReceived() = 0;
    
    /// @brief Raise a group metadata success event notification
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyGroupMetadataSuccess() = 0;
    
    /// @brief Raise a group metadata failure event notification
    /// @param error The error string
    /// @return True if successfully sent notification or no event library loaded
    virtual bool notifyGroupMetadataFailure(const std::string &error) = 0;
};

#endif // #ifndef EVENT_MANAGER_BASE_HPP
