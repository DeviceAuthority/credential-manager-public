/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Factory that generates JSON messages
 */

#ifndef MESSAGE_FACTORY_HPP
#define MESSAGE_FACTORY_HPP

#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "account.hpp"
#include "log.hpp"

class MessageFactory
{
    public:
    /**
     * @brief Builds an asset acknowledgement message
     *
     * @param asset_id The asset identifier
     * @param success Whether the asset was successfully handled or not
     * @param failure_reason The reason for failure (if success is false)
     * @return The acknowledgement message
     */
    static const std::string buildAcknowledgeMessage(const std::string &asset_id, bool success, const std::string &failure_reason);

    /**
     * @brief Builds an authentication message
     *
     * @param dfactor_auth_json The dfactor authentication json object
     * @param ack_json The acknowledgement json
     * @return The authentication message
     */
    static const std::string buildAuthenticationMessage(const std::string &dfactor_auth_json, const std::string &ack_json);

    /**
     * @brief Builds a dfactor authentication message
     *
     * @param device_key The device key
     * @param is_edge Flag indicating if the device is an edge device
     * @param user_agent The device user agent
     * @param user_id The ID of the user
     * @param key_id The key ID
     * @param app_hash The application hash
     * @param asset_id The asset identifier
     * @return The dfactor authentication message
     */
    static const std::string buildDFactorAuthenticationMessage(
        const std::string &device_key,
        bool is_edge,
        const std::string &user_agent,
        const std::string &user_id,
        const std::string &key_id,
        const std::string &app_hash,
        const std::string &asset_id);

    /**
     * @brief Create a script result message from a script output
     *
     * @param logs_type The log type indicator
     * @param compress Whether to compress the JSON response
     * @param script_output The script output logs
     * @return The response JSON
     */
    static const std::string buildScriptResultMessage(
        const std::string &logs_type,
        bool compress,
        const std::string &script_output);

    /**
     * @brief Convert a script output into a JSON array containing each line
     *
     * @param script_output The script output
     * @return The script output in JSON format
     */
    static const std::string buildScriptOutputJson(const std::string &script_output);

    /**
     * @brief Merge two json objects as string into a single json object
     *
     * @param json_a The first object to merge
     * @param json_b The second object to merge
     * @return The merged JSON objects as a string
     */
    static const std::string mergeJsonObjects(const std::string &json_a, const std::string &json_b);

    /**
     * @brief Builds a script output message containing the script name and the script output
     *
     * @param script_id The script ID
     * @param script_output The script output
     * @return The script output in JSON format
     */
    static const std::string buildScriptOutputMessage(const std::string &script_id, const std::string &script_output);

    /**
     * @brief Builds a password change status message
     *
     * @param asset_id The asset ID
     * @param success Whether the request was successful
     * @param status The associated status message
     * @return The password change status message
     */
    static const std::string buildPasswordChangeStatusMessage(const std::string &asset_id, bool success, const std::string &status);

    /**
     * @brief Builds an APM Passwords Message
     *
     * @param accounts The accounts to include in the passwords message
     * @return The APM passwords message
     */
    static const std::string buildApmPasswordsMessage(const std::vector<account*> &accounts);

    static const std::string generateMqttPayload(
        const std::string &op,
        const std::string &udi,
        const std::string &user_agent,
        const std::string &user_id,
        const std::string &challenge_type = "",
        const char *deviceKey = "",
        const char *data = "",
        const char *assetId = "",
        const char *csr = "",
        const char *keyId = "");

    private:
    /**
     * Constructor
     */
    MessageFactory() {};

    /**
     * @brief Merge two JSON objects into a single JSON object
     *
     * @param target The target object which will receive the source object
     * @param source The source object which will be merged into the target
     * @param allocator The rapidjson allocator instance
     */
    static void mergeDocuments(rapidjson::Value &target, rapidjson::Value &source, rapidjson::Value::AllocatorType &allocator);
};

#endif /// MESSAGE_FACTORY_HPP
