#ifndef MQTT_MESSAGE_HPP
#define MQTT_MESSAGE_HPP

#include <string>

struct MqttMessage
{
    int m_mid;
    const std::string m_topic;
    const std::string m_msg;

    /// @brief Constructor
    /// @param mid The message ID
    /// @param topic The topic
    /// @param msg The message
    MqttMessage(int mid, const std::string &topic, const std::string &msg)
        : m_mid(mid), m_topic(topic), m_msg(msg)
    {
    }
};

#endif // #ifndef MQTT_MESSAGE_HPP
