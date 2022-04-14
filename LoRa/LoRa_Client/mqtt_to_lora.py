#!/bin/python3
import paho.mqtt.client as mqtt
import os, ssl, json, binascii, base64, jwt, subprocess
from urllib.parse import urlparse
from Crypto import Random
from Crypto.Cipher import AES

cafile ="/home/pi/CERT/ecc.ca.cert.crt"
cert = "/home/pi/CERT/ecc.raspberry.cert.crt"
key = "/home/pi/CERT/ecc.raspberry.key.pem"

def encrypt(message, passphrase):
    aes = AES.new(passphrase, AES.MODE_CBC, '0011223344556677')
    return base64.b64encode(aes.encrypt(message))

def on_message(client, obj, msg):
    print(msg.topic + " " + str(msg.qos) + " " + str(msg.payload))
    data=encrypt(msg.payload,"TienThaoPhuong12")
    command ="sudo ./rf95_client "+jwt.encode( {'data':data.decode('utf-8') }, "MQTT", algorithm='HS256')
    os.system("%s"%(command))

mqttc = mqtt.Client()

# Assign event callbacks
mqttc.on_message = on_message

url_str = os.environ.get('CLOUDMQTT_URL', 'mqtt://mqtt.com:8883//esp8266')
url = urlparse(url_str)
topic = url.path[1:] or '/esp8266'

# Connect
mqttc.username_pw_set("nguyen.nguyen.doan", "1234")
mqttc.tls_set(ca_certs=cafile, certfile=cert, keyfile=key, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS, ciphers=None)
mqttc.connect(url.hostname, url.port)

# Start subscribe, with QoS level 0
mqttc.subscribe(topic, 0)

rc = 0
while rc == 0:
    rc = mqttc.loop()
