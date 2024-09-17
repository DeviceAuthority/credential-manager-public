#ifndef DA_MQTT_CLIENT_HPP
#define DA_MQTT_CLIENT_HPP

#include <memory>
#include "damqttclient_base.hpp"

#define KEEP_ALIVE 60
#define MSG_MAX_SIZE  512

// Forward declaration of mosquitto class
struct mosquitto;

class DAMqttClient : public DAMqttClientBase
{
public:
	DAMqttClient(const std::string& pub_topic, const std::string& sub_topic, const std::string& host, int port, int keep_alive_s);
    virtual ~DAMqttClient();

	int init(
        void (*on_log)(struct mosquitto*, void*, int, const char*),
        void (*on_connect)(struct mosquitto*, void*, int),
        void (*on_message)(struct mosquitto*, void*, const struct mosquitto_message*),
        void (*on_subscribe)(struct mosquitto*, void*, int, int, const int*),
        void (*on_publish)(struct mosquitto*, void*, int)) override;
	void loop() override;
    void disconnect() override;
	void terminate() override;
	mosquitto* getHandle() const override;
    void onPublish(const std::string& topic, const std::string& data) override;
    void setTid(const std::string &tid) override;
    const std::string &getTid() const override;

private:
    /// @brief The MQTT keep alive duration in seconds
	const int m_mqtt_keep_alive_s;
	mosquitto *mp_mosquitto_handle;
    bool m_initialized;
    std::string m_tid;
};

#endif // #ifndef DA_MQTT_CLIENT_HPP
