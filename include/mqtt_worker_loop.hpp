/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Credential manager worker that uses MQTT
 */
#ifndef MQTT_WORKER_LOOP_HPP
#define MQTT_WORKER_LOOP_HPP

#include "base_worker_loop.hpp"
#include "log.hpp"
#include "damqttclient_base.hpp"

class MqttWorkerLoop :
    public BaseWorkerLoop
{
public:
    /// @brief Constructor
    /// @param sleep_period_ms The sleep period in milliseconds
    MqttWorkerLoop(const std::string &broker_host, int broker_port, const std::string &mqtt_sub, const std::string &mqtt_pub, long sleep_period_ms = 60000);

    /// @brief Default destructor
	virtual ~MqttWorkerLoop() {};

    void initialize() override;

    void run() override;

    void terminate() override;

    DAMqttClientBase *getMqttClient() const;

private:
    /// @brief The MQTT client
    std::unique_ptr<DAMqttClientBase> mp_mqtt_client;
};

#endif // #ifndef MQTT_WORKER_LOOP_HPP
