# rpirouter

# Openwrt Setup for Raspberry 3 / 3 plus and later 4



# Requirements

- Raspberry 
- SD card at least 32 Gb
- USB-Ethernet adapter
- Linux computer

optional:
- USB-GPS-Receiver
- software defined radio, for RTL2832 based DVB-T receivers
- USB-Wifi-Adapter

# Motivation

Experiment to setup a more secure system with focus on secure communication.  

# Networks

Participants of the network are connected by:

1. Yggdrasil or
2. I2P or
3. Tor (not used)

# Setup

1.   Setup from scratch like described in setupRpi3_asRouter_openwrt_ext4.sh
2.   Burn image to SD. Follow install_config_1.sh
-  Setup as client. Follow setup_as_client_2.sh
-  Setup as server. Follow setup_as_server_2.sh
3.   Setup a Linux computer to run client software like claws-mail, hexchat, mumble

![setup](https://github.com/marl2en/rpirouter/blob/main/raspberry_setup.png)


# Screenshots

![overview](https://github.com/marl2en/rpirouter/blob/main/overview.png)

![adblocker](https://github.com/marl2en/rpirouter/blob/main/adblocker.png)

![chrony](https://github.com/marl2en/rpirouter/blob/main/chrony.png)

![cpu](https://github.com/marl2en/rpirouter/blob/main/collectd_cpu.png)

![interfaces](https://github.com/marl2en/rpirouter/blob/main/collectd_interfaces.png)

![thermal](https://github.com/marl2en/rpirouter/blob/main/collectd_thermal.png)


![firewall](https://github.com/marl2en/rpirouter/blob/main/firewall.png)


![firewall-rules](https://github.com/marl2en/rpirouter/blob/main/firewall-rules.png)

