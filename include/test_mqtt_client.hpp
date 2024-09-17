#ifndef TEST_MQTT_CLIENT_HPP
#define TEST_MQTT_CLIENT_HPP

#include <string>
#include "damqttclient_base.hpp"

class TestMqttClient : public DAMqttClientBase
{
public:
    TestMqttClient(const std::string& pub_topic, const std::string& sub_topic, const std::string& host, int port)
        : DAMqttClientBase(pub_topic, sub_topic, host, port)
    {
        m_last_published_json = "";
    }

    virtual ~TestMqttClient()
    {

    }

	int init(
        void (*on_log)(struct mosquitto*, void*, int, const char*),
        void (*on_connect)(struct mosquitto*, void*, int),
        void (*on_message)(struct mosquitto*, void*, const struct mosquitto_message*),
        void (*on_subscribe)(struct mosquitto*, void*, int, int, const int*),
        void (*on_publish)(struct mosquitto*, void*, int)) override
    {
        return true;
    }

	void loop() override
    {
        // Do nothing - in a real MQTT client this starts the MQTT agent loop
    }

    void disconnect() override
    {

    }

	void terminate() override
    {

    }

	mosquitto* getHandle() const override
    {
        return nullptr;
    }

    void onPublish(const std::string& topic, const std::string& data) override
    {
        m_last_published_json = data;
    }

    const std::string &getLastPublishJson() const
    {
        return m_last_published_json;
    }

private:
    std::string m_last_published_json;

};

#endif // #ifndef TEST_MQTT_CLIENT_HPP
