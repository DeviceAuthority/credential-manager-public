/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * A wrapper for the Device Authority SAC-MQTT calls.
 */
#ifndef DISABLE_MQTT

#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.hpp"
#include "mosquitto.h"
#include "damqttclient.hpp"

#define KEEP_ALIVE 60
#define MSG_MAX_SIZE 512

DAMqttClient::DAMqttClient(const std::string& pub_topic, const std::string& sub_topic, const std::string& host, int port, int keep_alive_s)
	: DAMqttClientBase(pub_topic, sub_topic, host, port)
	, m_mqtt_keep_alive_s(keep_alive_s)
{
	mp_mosquitto_handle = nullptr;
    m_initialized = false;
}

DAMqttClient::~DAMqttClient()
{
    terminate();
}

int DAMqttClient::init(void (*on_log)(struct mosquitto*, void*, int, const char*),
                       void (*on_connect)(struct mosquitto*, void*, int),
                       void (*on_message)(struct mosquitto*, void*, const struct mosquitto_message*),
                       void (*on_subscribe)(struct mosquitto*, void*, int, int, const int*),
                       void (*on_publish)(struct mosquitto*, void*, int))
{
    Log *p_logger = Log::getInstance();

    p_logger->printf(Log::Debug, "Mosquitto initialization");

    int rc = mosquitto_lib_init();
    if (rc == MOSQ_ERR_SUCCESS)
    {
	    mp_mosquitto_handle = mosquitto_new(nullptr, true, this);
	    if (mp_mosquitto_handle)
        {
	        // It should reigster all the call backs e.g
	        mosquitto_log_callback_set(mp_mosquitto_handle, on_log);
	        mosquitto_connect_callback_set(mp_mosquitto_handle, on_connect);
	        mosquitto_message_callback_set(mp_mosquitto_handle, on_message);
	        mosquitto_subscribe_callback_set(mp_mosquitto_handle, on_subscribe);
	        mosquitto_publish_callback_set(mp_mosquitto_handle, on_publish);

            p_logger->printf(Log::Information, "Connecting to remote MQTT host @ %s:%d", m_mqtt_host.c_str(), m_mqtt_port);
            rc = mosquitto_connect(mp_mosquitto_handle, m_mqtt_host.c_str(), m_mqtt_port, m_mqtt_keep_alive_s);
	        if (rc != MOSQ_ERR_SUCCESS)
	        {
                p_logger->printf(Log::Critical, "Unable to connect to remote MQTT host. Error: %d", rc);
		        // Handle the error if cant connect
	        }
            else
            {
                p_logger->printf(Log::Debug, "Mosquitto initialization success!");
        		m_initialized = true;
            }
        }
        else
        {
            p_logger->printf(Log::Critical, "Failed to instantiate Mosquitto handle");
            rc = MOSQ_ERR_NOMEM;
	    }
    }
    else
    {
        p_logger->printf(Log::Critical, "Unable to initialize Mosquitto. Error: %d", rc);
    }

    return rc;
}

void DAMqttClient::loop()
{
	int rc = mosquitto_loop_forever(mp_mosquitto_handle, -1, 1);
	Log::getInstance()->printf(Log::Information, "MQTT client loop, rc = %d", rc);
}

void DAMqttClient::disconnect()
{
    if (mp_mosquitto_handle != nullptr)
    {
        Log *p_logger = Log::getInstance();
	    p_logger->printf(Log::Information, "Disconnecting MQTT client from broker");
	    if (mosquitto_disconnect(mp_mosquitto_handle) == MOSQ_ERR_SUCCESS)
        {
	        p_logger->printf(Log::Information, "MQTT client disconnected!");
        }
    }
}

void DAMqttClient::terminate()
{
    Log *p_logger = Log::getInstance();

	p_logger->printf(Log::Information, "MQTT client terminated");
    if (mp_mosquitto_handle != nullptr)
    {
	    mosquitto_destroy(mp_mosquitto_handle);
        mp_mosquitto_handle = nullptr;
    }
    if (m_initialized)
    {
	    p_logger->printf(Log::Information, "Mosquitto cleanup");
	    mosquitto_lib_cleanup();
    }
}

mosquitto* DAMqttClient::getHandle() const
{
	return mp_mosquitto_handle;
}

void DAMqttClient::onPublish(const std::string& topic, const std::string& data)
{
    int rc = mosquitto_publish(mp_mosquitto_handle, nullptr, topic.c_str(), data.length() + 1, data.c_str(), 1, 0);
	if (rc == MOSQ_ERR_SUCCESS)
	{
		Log::getInstance()->printf(Log::Debug, "%d byte(s) published", data.length());
	}
	else
	{
		Log::getInstance()->printf(Log::Error, "Failed to publish, code: %d", rc);
	}
}

void DAMqttClient::setTid(const std::string &tid)
{
    m_tid = tid;
}

const std::string &DAMqttClient::getTid() const
{
    return m_tid;
}

#endif // DISABLE_MQTT