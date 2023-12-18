# IoT, LoRa, WiFi, MQTT, SSL, ATECC508, Mongoose OS, Raspberry Pi & ESP8266

# Table of contents
  * [1. Setup env for Raspberry Pi on PC](#1-setup-env-for-raspberry-pi-on-pc)
      - [Download raspberry lite and setup NFS file location](#download-raspberry-lite-and-setup-nfs-file-location)
      - [Mounting NFS on the Raspberry Pi](#mounting-nfs-on-the-raspberry-pi)
      - [Setup static IP](#setup-static-ip)
      - [Setup Dnsmasq, DHCP using PC Ethernet connection](#setup-dnsmasq--dhcp-using-pc-ethernet-connection)
      - [Activate SSH for Raspberry Pi](#activate-ssh-for-raspberry-pi)
      - [Start Rapsberry Pi](#start-rapsberry-pi)
  * [2. Setup Raspberry Pi for wifi](#2-setup-raspberry-pi-for-wifi)
      - [Init rasp-config, dnsmasq, hostapd](#init-rasp-config--dnsmasq--hostapd)
      - [Static and manual config](#static-and-manual-config)
  * [3. Create ECC key and cert](#3-create-ecc-key-and-cert)
  * [4. Raspberry Pi : Mosquitto for MQTT](#4-raspberry-pi---mosquitto-for-mqtt)
      - [Test MQTT server TLS connection](#test-mqtt-server-tls-connection)
  * [5. ESP8266: Mongoose OS + ATECC508](#5-esp8266--mongoose-os---atecc508)
      - [Install Mongoose OS](#install-mongoose-os)
      - [New MQTT app](#new-mqtt-app)
      - [Flash esp8266](#flash-esp8266)
      - [Wifi Config](#wifi-config)
      - [Install private key into ATECC508:](#install-private-key-into-atecc508-)
  * [6. Communications between ESP8266 and Raspberry Pi (WiFi and MQTT)](#6-communications-between-esp8266-and-raspberry-pi--wifi-and-mqtt-)
  * [7. Communications between Raspberry Pi and Raspberry Pi (LoRa)](#7-communications-between-raspberry-pi-and-raspberry-pi--lora-)
      - [Raspberry Pi Initial Setup](#raspberry-pi-initial-setup)
      - [LoRa Client](#lora-client)
      - [LoRa Server](#lora-server)
      - [Compling and testing the communication](#compling-and-testing-the-communication)

    
<hr/>

## 1. Setup env for Raspberry Pi on PC
#### Download raspberry lite and setup NFS file location

```
dvthao@dvthao$ mkdir PI
dvthao@dvthao$ cd PI
dvthao@dvthao:~/PI$ wget https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf2021-11-08/2021-10-30-raspios-bullseye-armhf-lite.zip
dvthao@dvthao:~/PI$ unzip 2021-10-30-raspios-bullseye-armhf-lite.zip
```

The raspbian filesystem in the client directory:

```
dvthao@dvthao:~/PI$ sudo losetup -fP 2021-10-30-raspios-bullseye-armhf-lite.img
dvthao@dvthao:~/PI$ losetup -a | grep rasp
/dev/loop25: []: (/home/dvthao/2021-10-30-raspios-bullseye-armhf-lite.img)
dvthao@dvthao:~/PI$ sudo mount /dev/loop25p2 /mnt
dvthao@dvthao:~/PI$ mkdir client
dvthao@dvthao:~/PI$ sudo rsync -xa --progress /mnt/ client/
dvthao@dvthao:~/PI$ sudo umount /mnt
```

Read boot partition from image

```
dvthao@dvthao:~/PI$ mkdir boot
dvthao@dvthao:~/PI$ sudo mount /dev/loop25p1 /mnt
dvthao@dvthao:~/PI$ cp -r /mnt/* boot/
dvthao@dvthao:~/PI$ sudo umount /mnt
```

Install `nfs-kernel-server` and `rpcbind`
```
dvthao@dvthao:~/PI$ sudo apt update
dvthao@dvthao:~/PI$ sudo apt install nfs-kernel-server rpcbind
```

Setup file `/etc/exports` for `nfs-kernel-server` : 
```
dvthao@dvthao$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
# to NFS clients. See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes hostname1(rw,sync,no_subtree_check)
#hostname2(ro,sync,no_subtree_check) # might cause nfs to fail to start
#
# Example for NFSv4:
# /srv/nfs4 gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes gss/krb5i(rw,sync,no_subtree_check)

/home/dvthao/PI/client *(rw,sync,no_subtree_check,no_root_squash)
/home/dvthao/PI/boot *(rw,sync,no_subtree_check,no_root_squash)
```

Start `nfs-kernel-server` and `rpcbind` services

```
dvthao@dvthao:~/PI$ sudo systemctl enable nfs-kernel-server
dvthao@dvthao:~/PI$ sudo systemctl enable rpcbind
dvthao@dvthao:~/PI$ sudo systemctl start nfs-kernel-server
dvthao@dvthao:~/PI$ sudo systemctl start rpcbind
```
Restart `nfs-kernel-server` service if you make changes to `/etc/exports`

```
dvthao@dvthao:~/PI$ sudo systemctl restart nfs-kernel-server
```
Check again:
```
dvthao@dvthao:~/PI$ showmount -e 127.0.0.1
Export list for 127.0.0.1:
/home/dvthao/PI/boot *
/home/dvthao/PI/client *
```
#### Mounting NFS on the Raspberry Pi
We modify the mount point of the Raspberry Pi for its filesystem, by editing the file
`~/PI/boot/cmdline.txt`
```
dvthao@dvthao$ sudo gedit PI/boot/cmdline.txt
console=serial0,115200 console=tty1 root=/dev/nfs nfsroot=10.20.30.1:/home/dvthao/PI/client,vers=3 rw ip=dhcp rootwait
```
Edit the file `etc/fstab` of Raspberry Pi in `PI/client/etc/fstab`
```
dvthao@dvthao$ cat RASPI/client/etc/fstab 
proc            /proc           proc   defaults          0       0
10.20.30.1:/home/dvthao/PI/boot /boot nfs defaults,vers=3  0   0
```
#### Setup static IP
In case IP address does not hold and keep changing. Configure static IP in file: `/etc/network/interfaces`

```
dvthao@dvthao$ cat /etc/network/interfaces
...
# interfaces(5) file used by ifup(8) and ifdown(8)
auto lo
iface lo inet loopback

auto enp4s0
iface enp4s0 inet static
        address 10.20.30.1
        netmask 255.255.255.0
        dns-nameservers 8.8.8.8
        dns-nameservers 8.8.4.4 
```

and config nameserver in `/etc/resolv.conf` for `dnsmasq` to use.
```
dvthao@dvthao$ cat /etc/resolv.conf
...
# See man:systemd-resolved.service(8) for details about the supported modes of
# operation for /etc/resolv.conf.

#options edns0
nameserver 127.0.0.53
```
#### Setup Dnsmasq, DHCP using PC Ethernet connection
We will use the `dnsmasq` command in the `script_boot_rpi` script:
```
# interface du PC connexion Raspberry
IF=enp4s0
sudo nmcli device set $IF managed no
PREFIX=10.20.30
sudo sysctl -w net.ipv4.ip_forward=1
sudo ip link set dev $IF down
sudo ip link set dev $IF up
sudo ip address add dev $IF $PREFIX.1/24
sudo iptables -t nat -A POSTROUTING -s $PREFIX.0/24 -j MASQUERADE
sudo rm /tmp/leases
sudo dnsmasq -d -z -i $IF -F $PREFIX.100,$PREFIX.150,255.255.255.0,12h -O 3,$PREFIX.1 -O 6,8.8.8.8 --pxe-service=0,"Raspberry Pi Boot" --enable-tftp --tftp-root=/home/dvthao/PI/boot -l /tmp/leases
```

#### Activate SSH for Raspberry Pi
```
dvthao@dvthao$ cat PI/client/lib/systemd/system/sshswitch.service 
[Unit]
Description=Turn on SSH if /boot/ssh is present
After=regenerate_ssh_host_keys.service
[Service]
Type=oneshot
ExecStart=/bin/sh -c "systemctl enable --now ssh"
[Install]
WantedBy=multi-user.target
```
#### Start Rapsberry Pi
Connect Rapsberry Pi to PC, run script `script_boot_rpi` and wait for DHCP handshake from dnsmasq:
``` 
dvthao@dvthao:~/PI$  sudo ./script_boot_rpi
...
dnsmasq-dhcp: DHCPDISCOVER(enp4s0) b8:27:eb:ab:ae:c4
dnsmasq-dhcp: DHCPOFFER(enp4s0) 10.20.30.129 b8:27:eb:ab:ae:c4 
dnsmasq-tftp: file /home/dvthao/PI/boot/bootsig.bin not found
dnsmasq-tftp: sent /home/dvthao/PI/boot/bootcode.bin to 10.20.30.129
dnsmasq-dhcp: DHCPDISCOVER(enp4s0) b8:27:eb:ab:ae:c4 
dnsmasq-dhcp: DHCPOFFER(enp4s0) 10.20.30.129 b8:27:eb:ab:ae:c4 
dnsmasq-tftp: file /home/dvthao/PI/boot/2073ff53/start.elf not found
dnsmasq-tftp: file /home/dvthao/PI/boot/autoboot.txt not found
dnsmasq-tftp: sent /home/dvthao/PI/boot/config.txt to 10.20.30.129
dnsmasq-tftp: file /home/dvthao/PI/boot/recovery.elf not found
dnsmasq-tftp: sent /home/dvthao/PI/boot/start.elf to 10.20.30.129
dnsmasq-tftp: sent /home/dvthao/PI/boot/fixup.dat to 10.20.30.129
dnsmasq-tftp: file /home/dvthao/PI/boot/recovery.elf not found
dnsmasq-tftp: sent /home/dvthao/PI/boot/config.txt to 10.20.30.129
dnsmasq-tftp: file /home/dvthao/PI/boot/dt-blob.bin not found
dnsmasq-tftp: file /home/dvthao/PI/boot/recovery.elf not found
dnsmasq-tftp: sent /home/dvthao/PI/boot/config.txt to 10.20.30.129
dnsmasq-tftp: file /home/dvthao/PI/boot/bootcfg.txt not found
dnsmasq-tftp: sent /home/dvthao/PI/boot/bcm2710-rpi-3-b.dtb to 10.20.30.129
dnsmasq-tftp: sent /home/dvthao/PI/boot/config.txt to 10.20.30.129
dnsmasq-tftp: sent /home/dvthao/PI/boot/cmdline.txt to 10.20.30.129
dnsmasq-tftp: file /home/dvthao/PI/boot/recovery8.img not found
dnsmasq-tftp: file /home/dvthao/PI/boot/recovery8-32.img not found
dnsmasq-tftp: file /home/dvthao/PI/boot/recovery7.img not found
dnsmasq-tftp: file /home/dvthao/PI/boot/recovery.img not found
dnsmasq-tftp: file /home/dvthao/PI/boot/kernel8-32.img not found
dnsmasq-tftp: error 0 Early terminate received from 10.20.30.129
dnsmasq-tftp: failed sending /home/dvthao/PI/boot/kernel8.img to 10.20.30.129
dnsmasq-tftp: file /home/dvthao/PI/boot/armstub8-32.bin not found
dnsmasq-tftp: error 0 Early terminate received from 10.20.30.129
dnsmasq-tftp: failed sending /home/dvthao/PI/boot/kernel7.img to 10.20.30.129
dnsmasq-tftp: sent /home/dvthao/PI/boot/kernel7.img to 10.20.30.129
dnsmasq-dhcp: DHCPDISCOVER(enp4s0) b8:27:eb:ab:ae:c4 
dnsmasq-dhcp: DHCPOFFER(enp4s0) 10.20.30.129 b8:27:eb:ab:ae:c4 
dnsmasq-dhcp: DHCPREQUEST(enp4s0) 10.20.30.129 b8:27:eb:ab:ae:c4 
dnsmasq-dhcp: DHCPACK(enp4s0) 10.20.30.129 b8:27:eb:ab:ae:c4 
dnsmasq-dhcp: DHCPREQUEST(enp4s0) 10.20.30.126 b8:27:eb:ab:ae:c4 
dnsmasq-dhcp: DHCPNAK(enp4s0) 10.20.30.126 b8:27:eb:ab:ae:c4 wrong address
dnsmasq-dhcp: DHCPDISCOVER(enp4s0) b8:27:eb:ab:ae:c4
dnsmasq-dhcp: DHCPOFFER(enp4s0) 10.20.30.129 b8:27:eb:ab:ae:c4 
dnsmasq-dhcp: DHCPREQUEST(enp4s0) 10.20.30.129 b8:27:eb:ab:ae:c4 
dnsmasq-dhcp: DHCPACK(enp4s0) 10.20.30.129 b8:27:eb:ab:ae:c4 raspberrypi

```
<hr/>
## 2. Setup Raspberry Pi for wifi
#### Init rasp-config, dnsmasq, hostapd
In our project, RaspberryPi connected in with ip `10.20.30.129`.
Raspberry Pi default password: **raspberry**
```
dvthao@dvthao$ ssh pi@10.20.30.129
```
Run `rasp-config` and config the wifi country to avoid rfkill block wifi.
Check if the file is correct.
```
pi@raspberrypi:~ $ cat /etc/wpa_supplicant/wpa_supplicant.conf 
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=FR
pi@raspberrypi:~ $ sudo rfkill unblock all
```

Install `dnsmasq` and `hostapd` for wifi hotspot in RaspberryPi
```
pi@raspberrypi:~ $ sudo apt update
pi@raspberrypi:~ $ sudo apt-get install hostapd
pi@raspberrypi:~ $ sudo apt-get install dnsmasq
```

Config Dnsmasq `/etc/dnsmasq.conf` :
```
$ sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak       #backup original file
$ sudo nano /etc/dnsmasq.conf                           #create new file
interface=wlan0        #choose the interfac
dhcp-range=192.168.4.100,192.168.4.120,255.255.255.0,12h
domain=wlan
address=/mqtt.com/192.168.4.1        #allow the dns to resolve a domain in mqtt.com
```

Config hostapd `/etc/hostapd/hostapd.conf`
```
pi@raspberrypi:~ $ cat /etc/hostapd/hostapd.conf 
country_code=FR
interface=wlan0
ssid=vn1
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=23456789
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```

Config ipv4 forwarding
```
$ sudo nano /etc/sysctl.conf

net.ipv4.ip_forward=1     #uncomment this line
```

#### Static and manual config

Add nameserver in resolvconf.conf for dnsmasq
```
pi@raspberrypi:~ $ cat /etc/resolvconf.conf 
# Configuration for resolvconf(8)
# See resolvconf.conf(5) for details

resolv_conf=/etc/resolv.conf
# If you run a local name server, you should uncomment the below line and
# configure your subscribers configuration files below.
name_servers=127.0.0.56

# Mirror the Debian package defaults for the below resolvers
# so that resolvconf integrates seemlessly.
dnsmasq_resolv=/var/run/dnsmasq/resolv.conf
pdnsd_conf=/etc/pdnsd.conf
unbound_conf=/var/cache/unbound/resolvconf_resolvers.conf
```
Set Static IP and allow-hotplug for wlan0 to UP.
```
pi@raspberrypi:~ $ cat /etc/network/interfaces
# interfaces(5) file used by ifup(8) and ifdown(8)

# Please note that this file is written to be used with dhcpcd
# For static IP, consult /etc/dhcpcd.conf and 'man dhcpcd.conf'

# Include files from /etc/network/interfaces.d:
source-directory /etc/network/interfaces.d

allow-hotplug wlan0
iface wlan0 inet static
	address 192.168.4.1
	netmask 255.255.255.0
	gateway 192.168.4.1
```

Enable hostapd
```
pi@raspberrypi:~ $ sudo systemctl unmask hostapd
pi@raspberrypi:~ $ sudo systemctl enable hostapd
pi@raspberrypi:~ $ sudo systemctl enable dnsmasq
```

Reboot Raspberry Pi
```
pi@raspberrypi:~ $ sudo reboot
```

If there is no wifi hotspot, check status of `hostapd.service`. If not running then restart `hostapd.service`
<hr/>
## 3. Create ECC key and cert

Generation of private keys for the CA, the server and the client.
    
```
pi@raspberrypi:~/CERT$ openssl ecparam -out ecc.ca.key.pem -name prime256v1 -genkey 
pi@raspberrypi:~/CERT$ openssl ecparam -out ecc.raspberry.key.pem -name prime256v1 -genkey 
pi@raspberrypi:~/CERT$ openssl ecparam -out ecc.esp8266.key.pem -name prime256v1 -genkey
```
Generation self-signed certificate of the CA which will be used to sign those of the server and client
```
pi@raspberrypi:~/CERT$
$ openssl req -config <(printf "[req]\ndistinguished_name=dn\n[dn]\n[ext]\nbasicConstraints=CA:TRUE") -new -nodes -subj "/C=FR/L=Limoges/O=TMC/OU=IOT/CN=ACTMC" -x509 -extensions ext -sha256 -key ecc.ca.key.pem -text -out ecc.ca.cert.crt

```
Generation and signing of the certificate for the server (Raspberry Pi)
```
pi@raspberrypi:~/CERT$
$ openssl req -config <(printf "[req]\ndistinguished_name=dn\n[dn]\n[ext]\nbasicConstraints=CA:FALSE") -new -subj   "/C=FR/L=Limoges/O=TMC/OU=IOT/CN=mqtt.com" -reqexts ext -sha256 -key ecc.raspberry.key.pem -text -out ecc.raspberry.csr.pem
$ openssl x509 -req -days 3650 -CA ecc.ca.cert.crt -CAkey ecc.ca.key.pem -CAcreateserial -extfile <(printf   "basicConstraints=critical,CA:FALSE") -in ecc.raspberry.csr.pem -text -out ecc.raspberry.cert.crt -addtrust clientAuth
```
Generating and signing the certificate for the client (Esp8266)
```
pi@raspberrypi:~/CERT$
$ openssl req -config <(printf "[req]\ndistinguished_name=dn\n[dn]\n[ext]\nbasicConstraints=CA:FALSE") -new -subj   "/C=FR/L=Limoges/O=TMC/OU=IOT/CN=esp8266" -reqexts ext -sha256 -key ecc.esp8266.key.pem -text -out ecc.esp8266.csr.pem
$ openssl x509 -req -days 3650 -CA ecc.ca.cert.crt -CAkey ecc.ca.key.pem -CAcreateserial -extfile <(printf   "basicConstraints=critical,CA:FALSE") -in ecc.esp8266.csr.pem -text -out ecc.esp8266.cert.crt -addtrust clientAuth
```
<hr/>
## 4. Raspberry Pi : Mosquitto for MQTT

Installation of the MQTT server packages
```
pi@raspberrypi:~ $ sudo apt-get install mosquitto 
pi@raspberrypi:~ $ sudo apt-get install mosquitto-clients
```
We copy `ecc.ca.cert.crt`, `ecc.raspberry.cert.crt` and `ecc.raspberry.key.pem` to the `/etc/mosquitto/` directories:
```
pi@raspberrypi:~ $
$ sudo cp /CERT/ecc.ca.cert.crt /etc/mosquitto/ca_certificates/
$ sudo cp /CERT/ecc.raspberry.cert.crt /etc/mosquitto/certs/
$ sudo cp /CERT/ecc.raspberry.key.pem /etc/mosquitto/certs/
```
They are referenced in the `/etc/mosquitto/mosquitto.conf` file like this:
```
allow_anonymous false
password_file /etc/mosquitto/mosquitto_passwd

listener 8883
cafile /etc/mosquitto/ca_certificates/ecc.ca.cert.crt
certfile /etc/mosquitto/certs/ecc.raspberry.cert.crt
keyfile /etc/mosquitto/certs/ecc.raspberry.key.pem
require_certificate true
```

It will enable the user authentication by password and certificate for mosquitto.

Then we use `mosquitto_passwd` to generate the user `nguyen.nguyen.doan` in file `mosquitto_passwd`:

```
pi@raspberrypi:~ $ sudo mosquitto_passwd -c /etc/mosquitto/mosquitto_passwd nguyen.nguyen.doan   
```
After copying the files, modifying the `mosquitto.conf` file and adding new user, we must restart the server:
```
pi@raspberrypi:~ $ sudo systemctl restart mosquitto.service
```
#### Test MQTT server TLS connection

To publish a topic using the username *nguyen.nguyen.doan* and pass *1234* and a client certificate (certificate for esp8266)
```
pi@raspberrypi:~ $ mosquitto_pub -h mqtt.com -p 8883 -u nguyen.nguyen.doan -P 1234 -t '/esp8266' --cafile ecc.ca.cert.crt --cert ecc.esp8266.cert.crt --key ecc.esp8266.key.pem -m 'Hello !'
```
To subcribe a topic using the username *nguyen.nguyen.doan* and pass *1234* and a server certificate (certificate for raspberry)
```
pi@raspberrypi:~ $ mosquitto_sub -h mqtt.com -p 8883 -u nguyen.nguyen.doanm -P 1234 -t '/esp8266' --cafile ecc.ca.cert.crt --cert ecc.raspberry.cert.crt --key ecc.raspberry.key.pem
Hello !
```
<hr/>
## 5. ESP8266: Mongoose OS + ATECC508 
Connect ESP8266 to PC using USB cable
```
dvthao@dvthao$ lsusb
...
Bus 001 Device 014: ID 10c4:ea60 Cygnal Integrated Products, Inc. CP210x UART Bridge / myAVR mySmartUSB light
...
```

#### Install Mongoose OS
Configure ESP8266 using Mongoose OS to generate a flash for ESP8266
Site of OS : https://mongoose-os.com


```
dvthao@dvthao$
$ sudo add-apt-repository ppa:mongoose-os/mos
$ sudo apt-get update
$ sudo apt-get install mos
$ mos --help
$ mos             #this command run WebUI version for mos 
```

To generate a flash, install docker and set the execution right

```
dvthao@dvthao$
$ sudo apt install docker.io
$ sudo groupadd docker
$ sudo usermod -aG docker $USER
```

Then restart laptop for the right to work.

#### New MQTT app 

Install new app and config file `mos.yml` like following:

```
dvthao@dvthao:~/PI$ git clone https://github.com/mongoose-os-apps/empty my-app
dvthao@dvthao:~/PI$ cd my-app
dvthao@dvthao:~/PI$ cat mos.yml
author: mongoose-os
description: A Mongoose OS app skeleton
version: 1.0
libs_version: ${mos.version}
modules_version: ${mos.version}
mongoose_os_version: ${mos.version}
# Optional. List of tags for online search.
tags:
    - c
# List of files / directories with C sources. No slashes at the end of dir names.
sources:
    - src
# List of dirs. Files from these dirs will be copied to the device filesystem

config_schema:
  - ["debug.level", 3]
  - ["sys.atca.enable", "b", true, {title: "enable atca for ATEC608"}]
  - ["i2c.enable", "b", true, {title: "Enable I2C"}]
  - ["sys.atca.i2c_addr", "i", 0x60, {title: "I2C address of the chip"}]
  - ["mqtt.enable", true]
  - ["mqtt.server", "mqtt.com:8883"]
  - ["mqtt.user", "nguyen.nguyen.doan"]
  - ["mqtt.pass", "1234"]
  - ["mqtt.ssl_ca_cert", "ecc.ca.cert.pem"]
  - ["mqtt.ssl_cert", "ecc.esp8266.cert.pem"]
  - ["mqtt.ssl_key", "ATCA:0"]

cdefs:
  MG_ENABLE_MQTT: 1
  # MG_ENABLE_SSL: 1

build_vars:
  # Override to 0 to disable ATECCx08 support.    
  # Set to 1 to enable ATECCx08 support.
  # MGOS_MBEDTLS_ENABLE_ATCA: 0
  MGOS_MBEDTLS_ENABLE_ATCA: 1


libs:
  - origin: https://github.com/mongoose-os-libs/ca-bundle
  - origin: https://github.com/mongoose-os-libs/boards
  - origin: https://github.com/mongoose-os-libs/rpc-service-config
  - origin: https://github.com/mongoose-os-libs/rpc-mqtt
  - origin: https://github.com/mongoose-os-libs/rpc-uart
  - origin: https://github.com/mongoose-os-libs/wifi
  - origin: https://github.com/mongoose-os-libs/rpc-service-i2c
  - origin: https://github.com/mongoose-os-libs/mbedtls
  - origin: https://github.com/mongoose-os-libs/atca
  - origin: https://github.com/mongoose-os-libs/rpc-service-fs
  - origin: https://github.com/mongoose-os-libs/rpc-service-atca
  
# Used by the mos tool to catch mos binaries incompatible with this file format
manifest_version: 2017-05-18
```

Copy certificate file `ecc.ca.cert.crt`, `ecc.ca.cert.pem`, `ecc.esp8266.cert.crt` and `ecc.esp8266.cert.pem` to folder `fs` inside `my-app`.

Modify the file `my-app/src/main.c` like follow:

```
dvthao@dvthao:~/PI/my-app/$ cd src
dvthao@dvthao:~/PI/my-app/$ cat main.c
#include <stdio.h>
#include "mgos.h"
#include "mgos_mqtt.h"
int i = 0;
static void my_timer_cb(void *arg) {
  if (i == 10) i = 0;
  char message[] = {'T', 'h', 'a', 'n', 'k', ' ', 'y', 'o', 'u', ' ', 'p', '-', 'f', 'b', ' ', '0'+i};
  i++;
  mgos_mqtt_pub("/esp8266", message, 16, 1, 0);
  (void) arg;
}
enum mgos_app_init_result mgos_app_init(void) {
  mgos_set_timer(5000, MGOS_TIMER_REPEAT, my_timer_cb, NULL);
  return MGOS_APP_INIT_SUCCESS;
}
```
#### Flash esp8266
Generate a flash for ESP8266 and flash with `mos flash`:
```
dvthao@dvthao:~/PI/my-app/$ sudo mos build --local --platform esp8266
Warning: --arch is deprecated, use --platform
Firmware saved to /home/kn/my-app/build/fw.zip

dvthao@dvthao:~/PI/my-app/$ sudo mos flash
Loaded my-app/esp8266 version 1.0 (20220218-022239/g2a789b0-main-dirty)
Using port /dev/ttyUSB0
Opening /dev/ttyUSB0 @ 115200...
Connecting to ESP8266 ROM, attempt 1 of 10...
  Connected, chip: ESP8266EX
Running flasher @ 921600...
  Flasher is running
Flash size: 16777216, params: 0x029f (dio,128m,80m)
Deduping...
     2320 @ 0x0 -> 0
   262144 @ 0x8000 -> 0
   592592 @ 0x100000 -> 0
      128 @ 0x3fc000 -> 0
Writing...
     4096 @ 0x7000
     4096 @ 0x3fb000
Wrote 8192 bytes in 0.08 seconds (830.14 KBit/sec)
Verifying...
     2320 @ 0x0
     4096 @ 0x7000
   262144 @ 0x8000
   592592 @ 0x100000
     4096 @ 0x3fb000
      128 @ 0x3fc000
Booting firmware...
All done!
```

#### Wifi Config

We add a few lines to `config-schema:` in file `mos.yml` to make ESP8266 can connect to wifi hotspot broadcast by raspberry pi:
```
...
config-schema:
  ...
  - ["wifi.ap.enable", "b", false, {title: "Enable"}]
  - ["wifi.sta.enable", "b", true, {title: "Connect to existing WiFi"}]
  - ["wifi.sta.ssid", "vn1"]
  - ["wifi.sta.pass", "23456789"]
  ...
```

#### Install private key into ATECC508:

```
dvthao@dvthao:~/PI/my-app/$ openssl rand -hex 32 > slot4.key
dvthao@dvthao:~/PI/my-app/$ mos -X atca-set-key 4 slot4.key --dry-run=false
AECC508A rev 0x5000 S/N 0x0123d4a032b776eeee, config is locked, data is locked

Slot 4 is a non-ECC private key slot
Writing block 0...
SetKey successful.
```

Then we add certificate key to ATECC508
```
dvthao@dvthao:~/PI/my-app/$ mos -X atca-set-key 0 ecc.esp8266.key.pem --write-key=slot4.key --dry-run=false
Using port /dev/ttyUSB0
ATECC508A rev 0x5000 S/N 0x0123d4a032b776eeee, config is locked, data is locked

Slot 0 is a ECC private key slot
Parsed EC PRIVATE KEY
Data zone is locked, will perform encrypted write using slot 4 using slot4.key
Writing block 0...
SetKey successful.
```
Finally, we start `mos console` to begin the connection.

**Simply script for ESP8266 operations**
```
dvthao@dvthao:~/PI/my-app/$ cat esp.sh
#!/bin/bash

sudo mos build --local --platform esp8266
sudo mos flash 
sudo mos put fs/ecc.ca.cert.pem 
sudo mos put fs/ecc.esp8266.cert.pem
sudo mos -X atca-set-key 4 slot4.key --dry-run=false
sudo mos -X atca-set-key 0 ecc.esp8266.key.pem --write-key=slot4.key --dry-run=false
sudo mos console
```
<hr/>

## 6. Communications between ESP8266 and Raspberry Pi (WiFi and MQTT)
To check the security connection between ESP8266 and Raspberry Pi, we run script `esp.sh`. The outputs as the following.

Output for init ATCA (ATECC) :
```
[Feb 18 02:41:49.043] mgos_deps_init.c:218    Init i2c 1.0 (cd740fa1b33b4b01bacc5a86a51fbe5d27c33f9c)...
[Feb 18 02:41:49.057] mgos_i2c_gpio_maste:248 I2C GPIO init ok (SDA: 12, SCL: 14, freq: 100000)
[Feb 18 02:41:49.057] mgos_deps_init.c:218    Init atca 1.0 (ea8308d5a944f98ea25ebd6c5e37268ab3aea882)...
[Feb 18 02:41:49.114] mgos_atca.c:117         ATECC508A @ 0/0x60: rev 0x5000 S/N 0x123d4a032b776eeee, zone lock status: yes, yes; ECDH slots: 0x0c
```

Output for wifi connected:
```
[Feb 18 02:41:53.306] esp_main.c:137          SDK: connected with vn1, channel 7
[Feb 18 02:41:53.311] esp_main.c:137          SDK: dhcp client start...
[Feb 18 02:41:53.320] mgos_wifi.c:82          WiFi STA: Connected, BSSID b8:27:eb:fe:fb:91 ch 7 RSSI -65
[Feb 18 02:41:53.325] mgos_wifi_sta.c:475     State 6 ev 1464224002 timeout 0
[Feb 18 02:41:53.325] mgos_event.c:134        ev WFI2 triggered 0 handlers
[Feb 18 02:41:53.339] mgos_net.c:93           WiFi STA: connected
[Feb 18 02:41:53.339] mgos_event.c:134        ev NET2 triggered 1 handlers
[Feb 18 02:41:56.955] esp_main.c:137          SDK: ip:192.168.4.112,mask:255.255.255.0,gw:192.168.4.1
...
[Feb 18 02:41:57.436] mgos_event.c:134        ev WFI3 triggered 0 handlers
[Feb 18 02:41:57.452] mgos_net.c:103          WiFi STA: ready, IP 192.168.4.112, GW 192.168.4.1, DNS 192.168.4.1, NTP 0.0.0.0
```

Output for certificate verify ok:
```
[Feb 18 02:41:57.462] mgos_mqtt_conn.c:435    MQTT0 connecting to mqtt.com:8883
[Feb 18 02:41:57.462] mgos_event.c:134        ev MOS6 triggered 0 handlers
[Feb 18 02:41:57.471] mongoose.c:3136         0x3ffef034 mqtt.com:8883 ecc.esp8266.cert.pem,ATCA:0,ecc.ca.cert.pem
[Feb 18 02:41:57.480] mgos_vfs.c:280          ecc.esp8266.cert.pem -> /ecc.esp8266.cert.pem pl 1 -> 1 0x3ffefb04 (refs 1)
[Feb 18 02:41:57.494] mgos_vfs.c:375          open ecc.esp8266.cert.pem 0x0 0x1b6 => 0x3ffefb04 ecc.esp8266.cert.pem 1 => 257 (refs 1)
[Feb 18 02:41:57.501] mgos_vfs.c:535          fstat 257 => 0x3ffefb04:1 => 0 (size 639)
[Feb 18 02:41:57.517] mgos_vfs.c:535          fstat 257 => 0x3ffefb04:1 => 0 (size 639)
[Feb 18 02:41:57.517] mgos_vfs.c:563          lseek 257 0 1 => 0x3ffefb04:1 => 0
[Feb 18 02:41:57.517] mgos_vfs.c:563          lseek 257 0 0 => 0x3ffefb04:1 => 0
[Feb 18 02:41:57.523] mgos_vfs.c:409          close 257 => 0x3ffefb04:1 => 0 (refs 0)
[Feb 18 02:41:57.678] mgos_vfs.c:280          ecc.ca.cert.pem -> /ecc.ca.cert.pem pl 1 -> 1 0x3ffefb04 (refs 1)
[Feb 18 02:41:57.692] mgos_vfs.c:375          open ecc.ca.cert.pem 0x0 0x1b6 => 0x3ffefb04 ecc.ca.cert.pem 1 => 257 (refs 1)
[Feb 18 02:41:57.698] mgos_vfs.c:409          close 257 => 0x3ffefb04:1 => 0 (refs 0)
[Feb 18 02:41:57.704] mongoose.c:3136         0x3fff09e4 udp://192.168.4.1:53 -,-,-
[Feb 18 02:41:57.709] mongoose.c:3006         0x3fff09e4 udp://192.168.4.1:53
[Feb 18 02:41:57.714] mgos_event.c:134        ev NET3 triggered 2 handlers
[Feb 18 02:41:57.721] mongoose.c:3020         0x3fff09e4 udp://192.168.4.1:53 -> 0
[Feb 18 02:41:57.727] mgos_mongoose.c:66      New heap free LWM: 40760
[Feb 18 02:41:57.738] mongoose.c:3006         0x3ffef034 tcp://192.168.4.1:8883
[Feb 18 02:41:57.744] mgos_mongoose.c:66      New heap free LWM: 40496
[Feb 18 02:41:57.751] mongoose.c:3020         0x3ffef034 tcp://192.168.4.1:8883 -> 0
[Feb 18 02:41:57.768] mongoose.c:4906         0x3ffef034 ciphersuite: TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
[Feb 18 02:41:57.780] mgos_vfs.c:280          ecc.ca.cert.pem -> /ecc.ca.cert.pem pl 1 -> 1 0x3ffefb04 (refs 1)
[Feb 18 02:41:57.789] mgos_vfs.c:375          open ecc.ca.cert.pem 0x0 0x1b6 => 0x3ffefb04 ecc.ca.cert.pem 1 => 257 (refs 1)
[Feb 18 02:41:57.795] mgos_vfs.c:535          fstat 257 => 0x3ffefb04:1 => 0 (size 635)
[Feb 18 02:41:57.953] ATCA ECDSA verify ok, verified
[Feb 18 02:41:57.958] mgos_vfs.c:409          close 257 => 0x3ffefb04:1 => 0 (refs 0)
[Feb 18 02:41:58.017] ATCA ECDSA verify ok, verified
[Feb 18 02:41:58.060] ATCA:2 ECDH get pubkey ok
[Feb 18 02:41:58.107] ATCA:2 ECDH ok
```

Output for MQTT publish:
```
[Feb 18 02:41:58.238] mgos_mqtt_conn.c:168    MQTT0 sub esp8266_BA915D/rpc/# @ 1
[Feb 18 02:41:58.243] mgos_mqtt_conn.c:168    MQTT0 sub esp8266_BA915D/rpc @ 1
[Feb 18 02:41:58.250] mgos_mqtt_conn.c:153    MQTT0 pub -> 1 /esp8266 @ 1 DUP (16): [VietNamVoDichAAA]
[Feb 18 02:41:58.261] mgos_mqtt_conn.c:179    MQTT0 event: 209
[Feb 18 02:41:58.307] mgos_mqtt_conn.c:179    MQTT0 event: 209
[Feb 18 02:41:58.312] mg_rpc.c:498            0x3fff0274 CHAN OPEN (MQTT)
[Feb 18 02:41:58.316] mgos_event.c:134        ev RPC0 triggered 0 handlers
[Feb 18 02:41:58.324] mgos_mqtt_conn.c:179    MQTT0 event: 204
[Feb 18 02:41:58.324] mgos_mqtt_conn.c:117    MQTT0 ack 1
[Feb 18 02:41:58.328] mgos_mqtt_conn.c:315    MQTT0 queue drained
[Feb 18 02:41:59.261] mgos_mqtt_conn.c:153    MQTT0 pub -> 4 /esp8266 @ 1 (16): [VietNamVoDichBBB]
[Feb 18 02:41:59.276] mgos_mqtt_conn.c:179    MQTT0 event: 204
[Feb 18 02:41:59.276] mgos_mqtt_conn.c:117    MQTT0 ack 4
[Feb 18 02:42:03.289] esp_main.c:137          SDK: pm open,type:0 0
[Feb 18 02:42:04.261] mgos_mqtt_conn.c:153    MQTT0 pub -> 5 /esp8266 @ 1 (16): [VietNamVoDichCCC]
[Feb 18 02:42:04.276] mgos_mqtt_conn.c:179    MQTT0 event: 204
[Feb 18 02:42:04.276] mgos_mqtt_conn.c:117    MQTT0 ack 5
[Feb 18 02:42:07.261] mgos_wifi_sta.c:475     State 8 ev -1 timeout 1
[Feb 18 02:42:09.261] mgos_mqtt_conn.c:153    MQTT0 pub -> 6 /esp8266 @ 1 (16): [VietNamVoDichDDD]
[Feb 18 02:42:09.277] mgos_mqtt_conn.c:179    MQTT0 event: 204
[Feb 18 02:42:09.277] mgos_mqtt_conn.c:117    MQTT0 ack 6
[Feb 18 02:42:14.262] mgos_mqtt_conn.c:153    MQTT0 pub -> 7 /esp8266 @ 1 (16): [VietNamVoDichEEE]
[Feb 18 02:42:14.279] mgos_mqtt_conn.c:179    MQTT0 event: 204
```
<hr/>

## 7. Communications between Raspberry Pi and Raspberry Pi (LoRa)
The Raspberry Pi which is configured with the MQTT server will behave as a LoRa client by retrieving the data published by the ESP8266 component and sending it to the second Raspberry Pi which behaves as a server through a LoRa Radio communication.
#### Raspberry Pi Initial Setup
The Raspberry Pi and the LoRa component will communicate via the SPI bus. Therefore, we must activate it on the Raspberry Pi.
```
pi@raspberrypi:~ $ sudo raspi-config
```
Select **« Interfacing Options »** and active the option **« SPI »**.<br />
Now we update and reboot Raspberry Pi.
```
pi@raspberrypi:~ $ sudo apt-get update
pi@raspberrypi:~ $ sudo apt-get upgrade
pi@raspberrypi:~ $ sudo rpi-update
pi@raspberrypi:~ $ sudo reboot
```
To activate the SPI bus used by the LoRa component, we modified the `/PI/boot/config.txt`:
```
dvthao@dvthao:~/PI/boot/$ cat config.txt
# Uncomment some or all of these to enable the optional hardware interfaces
#dtparam=i2c_arm=on
#dtparam=i2s=on
dtparam=spi=on
dtoverlay=gpio-no-irq
```
For the use of the GPIOs pins and the SPI bus, we install `bcm2835` library:
```
pi@raspberrypi:~ $ wget http://www.airspayce.com/mikem/bcm2835/bcm2835-1.71.tar.gz
pi@raspberrypi:~ $ tar zxvf bcm2835-1.71.tar.gz
pi@raspberrypi:~ $ cd bcm2835-1.71
pi@raspberrypi:~/bcm2835-1.71/$ ./configure
pi@raspberrypi:~/bcm2835-1.71/$ make
pi@raspberrypi:~/bcm2835-1.71/$ sudo make check
pi@raspberrypi:~/bcm2835-1.71/$ sudo make install
```
For the use of LoRa, we will use the following library:
```
pi@raspberrypi:~ $ git clone https://github.com/hallard/RadioHead
pi@raspberrypi:~ $ cd RadioHead/examples/raspi/rf95
```
Now we modified the two source files: `rf95_server.cpp` and `rf95_client.cpp`to select the dragino:<br />
	- comment the line that contains `#define BOARD_LORASPI` <br />
	- uncomment the line containing `//#define BOARD_DRAGINO_PIHAT`<br />
#### LoRa Client
We write a python script `mqtt_to_lora.py` on the client side:
`RadioHead/examples/raspi/rf95/mqtt_to_lora.py`
```python
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
    command ="./rf95_client "+jwt.encode( {'data':data.decode('utf-8') }, "MQTT", algorithm='HS256')
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

```
We modified the the sending message part of LoRa `C++` client program:
`RadioHead/examples/raspi/rf95/rf95_client.cpp`
```cpp
	...
	// Send a message to rf95_server
	const char* msg1;
	std::string str = argv[1]; 
	msg1 = str.c_str();
	size_t length = strlen(msg1) + 1;
          
	const char* beg = msg1;
	const char* end = msg1 + length;
	uint8_t* msg2 = new uint8_t[length];
        
	size_t i = 0;
	for (; beg != end; ++beg, ++i){
		msg2[i] = (uint8_t)(*beg);
	}
	uint8_t data[] = "hi";
	uint8_t len = sizeof(data);
        
	printf("Sending %02d bytes to node #%d => ", len, RF_GATEWAY_ID );
	printbuffer(msg2, length);
	printf("\n" );
	rf95.send(msg2, length);
	rf95.waitPacketSent();
	exit(1);
	...
```
#### LoRa Server
On the LoRa server side, we write a script in python receiving a JWT as an argument, decoding it and decrypting the AES with a key shared with the client. This python script will be executed by the LoRa `C++` server program for each LoRa packet it received.
`RadioHead/examples/raspi/rf95/server_decrypt.py`
```python
#!/bin/python3
import jwt, subprocess, sys, binascii,os, ssl, base64
from Crypto.Cipher import AES

data = sys.argv[1]
#print("Received encoded JWT: " +data)
encoded = ""
try:
        encoded = jwt.decode(data, "MQTT")
        print("AES encrypted data: " + encoded['data'])
except:
        print("Error decoding JWT")
        exit(1)

decryption_suite = AES.new('TienThaoPhuong12', AES.MODE_CBC, '0011223344556677')
try:
        plain_text = decryption_suite.decrypt(base64.b64decode(encoded['data']))
        print("AES Decrypted data : " + plain_text.decode('utf-8'))
except:
        print("Error AES decryption")
        exit(1)
```
Then we modified `RadioHead/examples/raspi/rf95/rf95_server.cpp` as the below:
```cpp
	...
	if (rf95.recv(buf, &len)) {
		printf("RSSI = %ddB;\nLoRa Raw Data: ", rssi);
		printbuffer(buf, len);
		printf("\n");
		std::string convert;
		convert.assign(buf, buf+len);

		char buffer[512];
		std::string result = "";
		std::string str = "python3 server_decrypt.py "+convert;
		const char * command = str.c_str();
		FILE* pipe = popen(command, "r");
		if (!pipe) throw std::runtime_error("popen() failed!");
		try {
				while (fgets(buffer, sizeof buffer, pipe) != NULL) {
					result += buffer;
				}
			} 
		catch (std::string const& chaine){
			pclose(pipe);
			throw;
		}
		std::cout << result << std::endl;
		pclose(pipe);
    } 
	else {
		Serial.print("receive failed");
	}
	printf("\n");
```
#### Compling and testing the communication
On both server side and client side, we must re-complie the cpp file:
```
pi@raspberrypi:~ $ cd RadioHead/examples/raspi/rf95
pi@raspberrypi:~/RadioHead/examples/raspi/rf95/$ make
```
For the Lora client, we run file `mqtt_to_lora.py`
```
pi@raspberrypi:~/RadioHead/examples/raspi/rf95/$ python3 mqtt_to_lora.py
```
For the Lora server, we run file `rf95_server`
```
pi@raspberrypi:~/RadioHead/examples/raspi/rf95/$ sudo ./rf95_server
```
