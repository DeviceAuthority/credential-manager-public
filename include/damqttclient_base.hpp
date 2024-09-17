#ifndef DA_MQTT_CLIENT_BASE_HPP
#define DA_MQTT_CLIENT_BASE_HPP

#include <algorithm>
#include <list>
#include <rapidjson/document.h>
#include <rapidjson/rapidjson.h>
#include <pthread.h>
#include <queue>
#include <memory>
#include <string>
#include "log.hpp"
#include "mqtt_message.hpp"

// Forward declaration of mosquitto classes
struct mosquitto;
struct mosquitto_message;

class DAMqttClientBase
{
public:
	const std::string m_mqtt_topic_pub;
	const std::string m_mqtt_topic_sub;
	const std::string m_mqtt_host;
	const int m_mqtt_port;

	DAMqttClientBase(const std::string& pub_topic, const std::string& sub_topic, const std::string& host, int port)
        : m_mqtt_topic_pub(pub_topic.c_str())
        , m_mqtt_topic_sub(sub_topic.c_str())
        , m_mqtt_host(host.c_str())
        , m_mqtt_port(port)
    {
    	m_subscribed_for_scripts = false;

        m_pending_request_ids_mutex = PTHREAD_MUTEX_INITIALIZER;
        m_pending_request_ids = std::list<std::string>();
        m_pending_request_ids.resize(MAX_PENDING_REQUEST_IDS);
    }

    virtual ~DAMqttClientBase() {}

	virtual int init(
        void (*on_log)(struct mosquitto*, void*, int, const char*),
        void (*on_connect)(struct mosquitto*, void*, int),
        void (*on_message)(struct mosquitto*, void*, const struct mosquitto_message*),
        void (*on_subscribe)(struct mosquitto*, void*, int, int, const int*),
        void (*on_publish)(struct mosquitto*, void*, int)) = 0;
	virtual void loop() = 0;
    virtual void disconnect() = 0;
	virtual void terminate() = 0;
	virtual mosquitto* getHandle() const = 0;
    virtual void setTid(const std::string &tid) = 0;
    virtual const std::string &getTid() const = 0;

	void publish(const std::string& data)
    {
        publish(m_mqtt_topic_pub, data);
    }

    void publish(const std::string& topic, const std::string& data)
    {
        Log *p_logger = Log::getInstance();

        rapidjson::Document json;
        json.Parse(data.c_str());
        if (json.HasParseError())
        {
            p_logger->printf(Log::Error, "Ignoring bad JSON in publish data: %s", data.c_str());
            return;
        }
        if (json.HasMember("reqId"))
        {
            const rapidjson::Value &req_id_obj = json["reqId"];
            const std::string request_id = std::string(req_id_obj.GetString());
            queueRequestId(request_id);            
        }

        // Allow publish without request ID for messages that are sent to device specific topic e.g., SAT
        onPublish(topic, data);
    }

    void enqueueMessage(std::unique_ptr<MqttMessage> &&mp_message)
    {
        Log *p_logger = Log::getInstance();

        rapidjson::Document json;
        json.Parse(mp_message->m_msg.c_str());
        if (json.HasParseError())
        {
            p_logger->printf(Log::Error, "Ignoring bad JSON in message data: %s", mp_message->m_msg.c_str());
            return;
        }

        if (json.HasMember("reqId"))
        {
            const rapidjson::Value &req_id_obj = json["reqId"];
            const std::string request_id = std::string(req_id_obj.GetString());
            if (!isExpectedResponse(request_id))
            {
                p_logger->printf(Log::Debug, "Ignoring message as not addressed to this client");
                return;
            }
            
            removeRequestId(request_id); // Ignore any re-transmissions!
        }

        // Queue the message if it was either addressed to this client or was an unaddressed message (e.g., a SAT message) 
        m_message_queue.push(std::move(mp_message));
    }

    std::unique_ptr<MqttMessage> getNextMessage()
    {
        if (m_message_queue.empty())
        {
            return nullptr;
        }

        auto p_next_message = std::move(m_message_queue.front());
        m_message_queue.pop();

        return p_next_message;
    }

    bool isMessageQueued() const
    {
        return !m_message_queue.empty();
    }

    void setSubscribedForScripts(bool subscribed)
    {
        m_subscribed_for_scripts = subscribed;
    }

    bool isSubscribedForScripts() const
    {
        return m_subscribed_for_scripts;
    }

protected:
    /// @brief Called when a message is being published to allow the subclass to handle
    /// dispatch of the message data to the topic
    /// @param topic The topic to publish to
    /// @param data The JSON message to send
    virtual void onPublish(const std::string& topic, const std::string& data) = 0; 

private:
    /// @brief The maximum number of pending request IDs
    static const int MAX_PENDING_REQUEST_IDS = 32;

    /// @brief Queue of received messages to be processed
    std::queue<std::unique_ptr<MqttMessage>> m_message_queue;

    /// @brief Flag that records whether subscribed for SAT script MQTT messages
    bool m_subscribed_for_scripts;

    /// @brief Mutex object to protect read write of pending request IDs list
    pthread_mutex_t m_pending_request_ids_mutex;
    /// @brief List containing all the pending request IDs
    std::list<std::string> m_pending_request_ids;

    /// @brief Queues the request ID so we can identify and handle the response
    /// @param request_id The request ID to queue
    void queueRequestId(const std::string &request_id)
    {
        pthread_mutex_lock(&m_pending_request_ids_mutex);
        while (m_pending_request_ids.size() > MAX_PENDING_REQUEST_IDS - 1)
        {
            m_pending_request_ids.pop_back();
        }
        m_pending_request_ids.push_front(request_id);
        pthread_mutex_unlock(&m_pending_request_ids_mutex);
    }

    /// @brief Remove request ID from list of pending request IDs
    /// @param request_id The request ID to remove
    void removeRequestId(const std::string &request_id)
    {
        pthread_mutex_lock(&m_pending_request_ids_mutex);
        m_pending_request_ids.remove(request_id);
        pthread_mutex_unlock(&m_pending_request_ids_mutex);
    }

    /// @brief Verifies whether a response is expected for this client by confirming
    /// if it generated the originating request
    /// @param request_id The ID of the initiating request, to be checked against 
    /// pending request ID list
    bool isExpectedResponse(const std::string &request_id)
    {
        pthread_mutex_lock(&m_pending_request_ids_mutex);
        bool found = std::find(m_pending_request_ids.begin(), m_pending_request_ids.end(), request_id) != m_pending_request_ids.end();
        pthread_mutex_unlock(&m_pending_request_ids_mutex);
        return found;
    }

};

#endif // #ifndef DA_MQTT_CLIENT_BASE_HPP
