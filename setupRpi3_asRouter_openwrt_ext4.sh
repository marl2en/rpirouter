
### Follow instructions at https://openwrt.org/toh/raspberry_pi_foundation/raspberry_pi

##  OpenWrt 22.03.5


## How to flash OpenWrt to an SD card


# download the image for your model and flash SD

gzip -d imagename-factory.img.gz
dd if=imagename-factory.img of=/dev/sdX bs=2M conv=fsync
sync


### Expand file system
# open gparted
sudo gparted

# for Raspberry 4: 
# squashfs can't be expanded -> use free space on SD to create a new ext4 partition 

# for other Rasberry-models: simply expand root partition to fill entire space on disk



# start openwrt and connet to 192.168.1.1 at lan
ssh root@192.168.1.1
passwd

QAXQP34-29vpU797CUP

#####   lan #### set lan as dhcp client
uci set network.lan.proto=dhcp
uci commit
service network restart

### connect to main router
ssh root@192.168.0.5


uci show network

# opendns
uci set network.WAN.dns=208.67.222.222
uci commit
service network restart









####  software ####
# Update the package repos
opkg update
# Install software that I'd like to have on evey one of my systems
opkg install htop nano tmux iftop mc
# Install LuCI webUI, for easier management, SSL
opkg install luci-ssl-nginx
# Now enable and start the nginx
service nginx enable
service nginx start

opkg install lsof

opkg install tcpdump
tcpdump -i br-eth1 portrange 41859-41860
opkg install python3
opkg install bind-dig 

#### usb ####

opkg install kmod-usb-storage
opkg install kmod-usb2
#opkg install kmod-usb3
opkg install usbutils


lsusb
Bus 001 Device 006: ID 0bda:8153 Realtek USB 10/100/1000 LAN

## Enabling USB-to-Ethernet adapter:
# I've got rtl8153, but drivers from 1852 will work just fine
opkg install kmod-usb-net-rtl8152

dmesg # should show eth1

# create WAN interface, 
nano /etc/config/network
config device
        option type 'bridge'
        option name 'br-eth1'
        list ports 'eth1'

config interface 'WAN'
        option proto 'dhcp'
        option device 'br-eth1'

service network restart





### Using I2C and SPI

#Putting the following lines at the end of /boot/config.txt (on the FAT32 partition) allows this feature to work:

nano /boot/config.txt

dtparam=i2c1=on 
#(or dtparam=i2c0=on on old models)
dtparam=spi=on
dtparam=i2s=on

#For I2C, it is also required to install the kernel module kmod-i2c-bcm2835 that contains the Broadcom I2C master controller driver:

opkg update
opkg install kmod-i2c-bcm2835

opkg install i2c-tools
i2cdetect -y 1





##### wifi usb adapter

#lsusb
#Bus 001 Device 003: ID 148f:3070 Ralink 802.11 n WLAN
#opkg install kmod-rt2800-lib kmod-rt2800-usb kmod-rt2x00-lib kmod-rt2x00-usb


lsusb
0e8d:7610 MediaTek WiFi

opkg list | grep MediaTek


#opkg install kmod-mt76-core kmod-mt76-usb kmod-mt76x0-common
opkg install kmod-mt76x0u


##### usb wifi adapter rtl8812bu
# lsusb
# Bus 001 Device 006: ID 0bda:b812 Realtek 802.11ac NIC


opkg list | grep rtw88
kmod-rtw88 - 5.10.176+5.15.92-1-1 - Realtek RTL8822BE/RTL8822CE/RTL8723DE

opkg install kmod-rtw88


REytf5-768Tf-DFWS3Q




## openssh-sftp-server, for filezilla
opkg install openssh-sftp-server




## openvpn
opkg install openvpn-openssl openvpn-easy-rsa luci-app-openvpn






######### yggdrasil ###

opkg update
opkg list | grep yggdrasil


opkg install yggdrasil
opkg install luci-app-yggdrasil

/etc/init.d/yggdrasil stop
/etc/init.d/yggdrasil disable

nano /etc/config/yggdrasil


## tor ###
opkg install tor iptables-mod-extra tor-geoip


############ https://openwrt.org/docs/guide-user/firewall/fw3_configurations/dns_ipset
opkg update
opkg remove dnsmasq
opkg install dnsmasq-full ipset resolveip

mv /etc/config/dhcp /etc/config/dhcp.old
mv /etc/config/dhcp-opkg /etc/config/dhcp


mkdir /home
mkdir /home/backup /home/backup/etc /home/backup/etc/config



######## Adblocker ####

opkg update
opkg install adblock

# Provide web interface
opkg install luci-app-adblock


mv /etc/config/adblock /home/backup/etc/config/adblock

nano /etc/config/adblock
config adblock 'global'
	option adb_debug '0'
	option adb_safesearch '0'
	option adb_dnsfilereset '0'
	option adb_mail '0'
	option adb_backup '1'
	option adb_maxqueue '4'
	list adb_sources 'adaway'
	list adb_sources 'adguard'
	list adb_sources 'disconnect'
	list adb_sources 'yoyo'
	option adb_dns 'dnsmasq'
	option adb_fetchutil 'uclient-fetch'
	option adb_backupdir '/etc/adblock'
	option adb_enabled '1'
	option adb_forcedns '1'
	list adb_portlist '53'
	option adb_report '1'
	option adb_dnsinstance '0'
	option adb_reportdir '/tmp/adblock-Report'
	option adb_represolve '1'
	list adb_eng_sources 'unified/formats/domains.txt'
	list adb_eng_sources 'extensions/xtreme/formats/domains.txt'
	option adb_repiface 'br-lan'
	option adb_trigger 'WAN'
	list adb_zonelist 'lan'
	list adb_zonelist 'wan'

/etc/init.d/adblock restart

##### banip ####
opkg install banip luci-app-banip


cp /etc/config/banip /home/backup/etc/config/banip

/etc/init.d/banip start

/etc/init.d/banip status

###### https://openwrt.org/docs/guide-user/additional-software/extroot_configuration
## https://linuxconfig.org/how-to-extend-lede-openwrt-system-storage-with-an-usb-device
opkg install block-mount kmod-fs-ext4 e2fsprogs fdisk









#### https://openwrt.org/docs/guide-user/luci/luci_app_statistics 
opkg update
opkg install luci-app-statistics

opkg list | grep collectd-mod
opkg install collectd-mod-ethstat collectd-mod-ipstatistics collectd-mod-irq collectd-mod-load collectd-mod-ping collectd-mod-powerdns collectd-mod-sqm collectd-mod-thermal collectd-mod-wireless

opkg install collectd-mod-interface collectd-mod-threshold collectd-mod-dhcpleases collectd-mod-df collectd-mod-curl collectd-mod-disk

opkg install  collectd-mod-filecount collectd-mod-fscache collectd-mod-exec collectd-mod-dns collectd-mod-ethstat collectd-mod-iwinfo collectd-mod-lua collectd-mod-openvpn collectd-mod-processes collectd-mod-protocols


nano /etc/config/luci_statistics
/etc/init.d/collectd enable

##### GPS ######
opkg install  gpsd gpsd-clients gpsd-utils

# kmod-usb-serial - 2.6.36.2-1 - Kernel support for USB-to-Serial converters
# kmod-usb-serial-pl2303 - 2.6.36.2-1 - Kernel support for Prolific PL2303 USB-to-Serial converters

#opkg install kmod-usb-serial kmod-usb-serial-pl2303
#opkg install kmod-usb-serial-ftdi
opkg install kmod-usb-acm

lsusb
1546:01a7 u-blox AG - www.u-blox.com u-blox 7 - GPS/GNSS Receiver


# test device
cat /dev/ttyACM0

gpsd -N -D5 /dev/ttyACM0



# config

nano /etc/config/gpsd
config gpsd 'core'
        option enabled '1'
        option device '/dev/ttyACM0'
        option port '2947'
        option listen_globally '0'

/etc/init.d/gpsd stop


/etc/init.d/gpsd start




##### chrony ####
opkg install chrony collectd-mod-chrony
opkg info chrony

Version: 4.1-2
Conffiles:
 /etc/chrony/chrony.conf 73291eb1b360bddbec4ce843fd1349301f7c9b7cf53ecbdcab4b17e70ca4be88
 /etc/config/chrony 48ac4e83939fa8e02a5303e423d5434221f90dbdabd7a7b3058218a607162f85

nano /etc/config/chrony

config pool
        option hostname '192.168.0.2'
        option maxpoll '12'
        option iburst 'yes'




nano /etc/chrony/chrony.conf

refclock SHM 0 offset 0.05 delay 0.2 refid NMEA
#refclock SOCK /run/chrony.ttyACM0.sock refid GPS precision 1e-1 offset 0.9999



/etc/init.d/chronyd restart
# Disable sysntpd
/etc/init.d/sysntpd stop
/etc/init.d/sysntpd disable


### testing
chronyc sources -v 
chronyc tracking
chronyc clients
chronyc sourcestats [-v]





##   aircrack-ng
opkg update
opkg install aircrack-ng


########################## wifi schedule #########################
opkg install luci-app-wifischedule



##################### snort3 ##############################################
## https://openwrt.org/docs/guide-user/services/snort

opkg install snort3

nano /etc/config/snort
config snort 'snort'
        option config_dir '/etc/snort/'
        option alert_module 'alert_syslog'
        #option interface 'br-eth1'
        option interface 'br-eth1:br-lan'

nano /etc/snort/snort_defaults.lua


RULE_PATH = '/etc/snort/rules'
BUILTIN_RULE_PATH = '/etc/snort/builtins'
PLUGIN_RULE_PATH = '/etc/snort/so_rules'





nano /etc/snort/snort.lua

# fe80::ba27:ebff:fef9:490d/64
fe80::ba27:ebff:feac:1c58/64
fe80::2e0:6cff:fe36:618d/64


/etc/init.d/snort stop


mkdir /etc/snort/appid

## testing
snort -T -c "/etc/snort/snort.lua" -i "lo" --daq-dir /usr/lib/daq --rule-path /etc/snort/rules

snort -c /etc/snort/snort.lua -i br-eth1 --daq-dir /usr/lib/daq -A alert_syslog -d -e -v --rule-path /etc/snort/rules --warn-conf-strict

snort -c /etc/snort/snort.lua -i "br-eth1:br-lan" --daq-dir /usr/lib/daq -A alert_syslog -d -e -v --rule-path /etc/snort/rules -Q


### inline IPS mode ###

# option interface 'br-eth1:br-lan'
nano /etc/init.d/snort

procd_set_param command $PROG -q --daq-dir /usr/lib/daq/ -i "$interface" -c "$config_dir/snort.lua" -A "$alert_module" -Q

### passive mode ###

# option interface 'br-eth1'
nano /etc/init.d/snort

procd_set_param command $PROG -q --daq-dir /usr/lib/daq/ -i "$interface" -c "$config_dir/snort.lua" -A "$alert_module"





## wifi mesh #### https://openwrt.org/docs/guide-user/network/wifi/mesh/80211s
opkg remove wpad-mini
opkg remove wpad-basic
opkg remove wpad-basic-wolfssl

opkg install wpad-openssl

opkg install kmod-batman-adv
# opkg install batctl


####### software defined radio, for RTL2832 based DVB-T receivers
opkg update
opkg install rtl-sdr

ls -l /usr/bin | grep rtl
-rwxr-xr-x    1 root     root         16397 Jun 13  2021 rtl_adsb
-rwxr-xr-x    1 root     root         12091 Jun 13  2021 rtl_eeprom
-rwxr-xr-x    1 root     root         29120 Jun 13  2021 rtl_fm
-rwxr-xr-x    1 root     root         25028 Jun 13  2021 rtl_power
-rwxr-xr-x    1 root     root         16371 Jun 13  2021 rtl_sdr
-rwxr-xr-x    1 root     root         20490 Jun 13  2021 rtl_tcp
-rwxr-xr-x    1 root     root         16401 Jun 13  2021 rtl_test



# example
/usr/bin/rtl_power -f 88M:108M:125k /home/sdr/fm_stations.csv
/usr/bin/rtl_power -f 100M:1G:1M -e 1h | gzip > /home/sdr/survey.csv.gz

# Convert CSV to a waterfall graphic with: http://kmkeen.com/tmp/heatmap.py.txt 




########################### adduser ############  https://openwrt.org/docs/guide-user/additional-software/create-new-users
cat /etc/passwd

"""    User name
    Encrypted password
    User ID number (UID)
    User’s group ID number (GID)
    Full name of the user (GECOS)
    User home directory
    Login shell ( /bin/ash is the valid shell on OpenWrt, write /bin/false instead to disable the shell for this user)"""


opkg install shadow-useradd

nano /etc/group
# The fields are group name, group password, group ID, and group members, separated by commas.
mailuser::501:joe

useradd --gid mailuser --create-home -u 501 --shell /bin/ash joe
useradd --gid mailuser --create-home -u 502 --shell /bin/false bob
useradd --gid mailuser --create-home -u 503 --shell /bin/false alice
useradd --gid mailuser --create-home -u 504 --shell /bin/false max
useradd --gid mailuser --create-home -u 505 --shell /bin/false ann
useradd --gid mailuser --create-home -u 506 --shell /bin/false lucy




passwd joe
### ogGY8-7IKGiTT

passwd bob
### eq6Fl-Uyt3Y

passwd alice
### Q1pjc-wygc0

passwd max
## 78tuyg-nrytER

passwd ann
## Veq01s-zAhjjgJ

passwd lucy
## LhtEWr-ts4d2h8

cat /etc/passwd

### setup lan as dhcp server ############################

uci -N show dhcp.@dnsmasq[0]

uci -N show dhcp.@dhcp[0]
dhcp.lan=dhcp
dhcp.lan.interface='lan'
dhcp.lan.start='100'
dhcp.lan.limit='150'
dhcp.lan.leasetime='12h'


cat /etc/config/network
config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option netmask '255.255.255.0'
	option ip6assign '60'
	option ipaddr '192.168.0.2'




uci set network.lan.proto=static
uci set network.lan.ipaddr=192.168.5.5
uci commit
service network restart

### connect to main router 
ssh root@192.168.5.5



### setup wifi ###
cat /etc/config/wireless

## go to https://192.168.5.5/cgi-bin/luci/admin/network/wireless

# set SSID: rpi_router
# wlan passwd: psdQPVBRZs13127xc1b3weqlp293

# get info
iwinfo



############# tor ###################
opkg update
opkg install tor iptables-mod-extra tor-geoip


nano /etc/tor/torrc


User tor

RunAsDaemon 1
#AllowUnverifiedNodes middle,rendezvous
Log notice syslog
## Only run as a client, never a relay or exit
ClientOnly 1
DataDirectory /var/lib/tor
#HiddenServiceDir /var/lib/tor/hidden_service/
#HiddenServicePort 1234 127.0.0.1:1234
SocksPort 9050
SocksPort 192.168.5.5:9050
SocksPolicy accept 127.0.0.1/32
SocksPolicy accept 192.168.5.0/24
SocksPolicy reject *
#AutomapHostsSuffixes .exit,.onion
AutomapHostsSuffixes "."
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 10.192.0.0/10
TransPort 192.168.5.5:9040
DNSPort 192.168.5.5:9053
#TruncateLogFile 1
LogMessageDomains 1
#StrictNodes 1
#ExitNodes {IS}


nano /etc/config/firewall

config zone 'tor'
    option name 'tor'
    option network 'lan'
    option input 'REJECT'
    option output 'ACCEPT'
    option forward 'REJECT'
    option conntrack '1'

config rule
    option name 'Allow-Tor-DHCP'
    option src 'tor'
    option proto 'udp'
    option dest_port '67'
    option target 'ACCEPT'
    option family 'ipv4'

config rule
    option name 'Allow-Tor-DNS'
    option src 'tor'
    option proto 'udp'
    option dest_port '9053'
    option target 'ACCEPT'
    option family 'ipv4'

config rule
    option name 'Allow-Tor-Transparent'
    option src 'tor'
    option proto 'tcp'
    option dest_port '9040'
    option target 'ACCEPT'
    option family 'ipv4'

config rule
    option name 'Allow-Tor-SOCKS'
    option src 'tor'
    option proto 'tcp'
    option dest_port '9050'
    option target 'ACCEPT'
    option family 'ipv4'


service firewall restart



/etc/init.d/tor stop
/etc/init.d/tor disable
/etc/init.d/tor start





############################ create-self-signed-certificates-keys ##################################
########## https://mariadb.com/docs/xpand/security/data-in-transit-encryption/create-self-signed-certificates-keys-openssl/

## Creating the Certificate Authoritys Certificate and Keys

# 1. Generate a private key for the CA:

openssl genrsa 2048 > ca-key.pem

# 2. Generate the X509 certificate for the CA:

openssl req -new -x509 -nodes -days 365000 \
       -key ca-key.pem \
       -out ca-cert.pem

'Country Name (2 letter code) [AU]:SE
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:Stockholm
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:rpirouter.lan
Email Address []:
'



## Creating the Servers Certificate and Keys

# 1. Generate the private key and certificate request:

openssl req -newkey rsa:2048 -nodes -days 365000 \
   -keyout server-key.pem \
   -out server-req.pem



# 2. Generate the X509 certificate for the server:

openssl x509 -req -days 365000 -set_serial 01 \
       -in server-req.pem \
       -out server-cert.pem \
       -CA ca-cert.pem \
       -CAkey ca-key.pem

### Creating the Clients Certificate and Keys

# 1.Generate the private key and certificate request:

openssl req -newkey rsa:2048 -nodes -days 365000 \
   -keyout client-key.pem \
   -out client-req.pem

# 2. Generate the X509 certificate for the client:

openssl x509 -req -days 365000 -set_serial 01 \
       -in client-req.pem \
       -out client-cert.pem \
       -CA ca-cert.pem \
       -CAkey ca-key.pem

### Verifying the Certificates

# Verify the server certificate:

openssl verify -CAfile ca-cert.pem \
   ca-cert.pem \
   server-cert.pem

openssl x509 -noout -in server-cert.pem -text -purpose

openssl x509 -noout -in ca-cert.pem -text -purpose


# Verify the client certificate:

openssl verify -CAfile ca-cert.pem \
   ca-cert.pem \
   client-cert.pem


openssl x509 -noout -in client-cert.pem -text -purpose





############## Diffie-Hellman_parameters

openssl dhparam -out dhparams.pem 4096


########################## install IRC server ################

opkg install ngircd




chmod 644 server-key.pem

mv server-key.pem /etc/ssl/server-key.pem
mv server-cert.pem /etc/ssl/server-cert.pem
cp ca-key.pem /etc/ssl/private/ca-key.pem
cp ca-cert.pem /etc/ssl/certs/ca-cert.pem
mv dhparams.pem /etc/ssl/dhparams.pem


nano /etc/ngircd.conf

#
# This is a sample configuration file for the ngIRCd IRC daemon, which must
# be customized to the local preferences and needs.
#
# Comments are started with "#" or ";".
#
# A lot of configuration options in this file start with a ";". You have
# to remove the ";" in front of each variable to actually set a value!
# The disabled variables are shown with example values for completeness only
# and the daemon is using compiled-in default settings.
#
# Use "ngircd --configtest" (see manual page ngircd(8)) to validate that the
# server interprets the configuration file as expected!
#
# Please see ngircd.conf(5) for a complete list of configuration options
# and their descriptions.
#

[Global]
	# The [Global] section of this file is used to define the main
	# configuration of the server, like the server name and the ports
	# on which the server should be listening.
	# These settings depend on your personal preferences, so you should
	# make sure that they correspond to your installation and setup!

	# Server name in the IRC network, must contain at least one dot
	# (".") and be unique in the IRC network. Required!
	Name = rpirouter.lan

	# Information about the server and the administrator, used by the
	# ADMIN command. Not required by server but by RFC!
	AdminInfo1 = Description
	AdminInfo2 = Location
	AdminEMail = admin@rpi_router.lan

	# Text file which contains the ngIRCd help text. This file is required
	# to display help texts when using the "HELP <cmd>" command.
	;HelpFile = /usr/share/doc/ngircd/Commands.txt

	# Info text of the server. This will be shown by WHOIS and
	# LINKS requests for example.
	Info = Rpi IRC Server

	# Comma separated list of IP addresses on which the server should
	# listen. Default values are:
	# "0.0.0.0" or (if compiled with IPv6 support) "::,0.0.0.0"
	# so the server listens on all IP addresses of the system by default.
	Listen = 127.0.0.1,192.168.5.5,::

	# Text file with the "message of the day" (MOTD). This message will
	# be shown to all users connecting to the server:
	;MotdFile = /etc/ngircd.motd

	# A simple Phrase (<127 chars) if you don't want to use a motd file.
	MotdPhrase = "Welcome to my IRC Server!"

	# The name of the IRC network to which this server belongs. This name
	# is optional, should only contain ASCII characters, and can't contain
	# spaces. It is only used to inform clients. The default is empty,
	# so no network name is announced to clients.
	;Network = aIRCnetwork

	# Global password for all users needed to connect to the server.
	# (Default: not set)
	Password = abc-def-123

	# This tells ngIRCd to write its current process ID to a file.
	# Note that the pidfile is written AFTER chroot and switching the
	# user ID, e.g. the directory the pidfile resides in must be
	# writable by the ngIRCd user and exist in the chroot directory.
	;PidFile = /var/run/ngircd/ngircd.pid

	# Ports on which the server should listen. There may be more than
	# one port, separated with ",". (Default: 6667)
	;Ports = 6667, 6668, 6669
	Ports = 60666
	
	# Group ID under which the ngIRCd should run; you can use the name
	# of the group or the numerical ID. ATTENTION: For this to work the
	# server must have been started with root privileges!
	ServerGID = 65534

	# User ID under which the server should run; you can use the name
	# of the user or the numerical ID. ATTENTION: For this to work the
	# server must have been started with root privileges! In addition,
	# the configuration and MOTD files must be readable by this user,
	# otherwise RESTART and REHASH won't work!
	ServerUID = 65534

[Limits]
	# Define some limits and timeouts for this ngIRCd instance. Default
	# values should be safe, but it is wise to double-check :-)

	# The server tries every <ConnectRetry> seconds to establish a link
	# to not yet (or no longer) connected servers.
	ConnectRetry = 60

	# Number of seconds after which the whole daemon should shutdown when
	# no connections are left active after handling at least one client
	# (0: never, which is the default).
	# This can be useful for testing or when ngIRCd is started using
	# "socket activation" with systemd(8), for example.
	;IdleTimeout = 0

	# Maximum number of simultaneous in- and outbound connections the
	# server is allowed to accept (0: unlimited):
	MaxConnections = 30

	# Maximum number of simultaneous connections from a single IP address
	# the server will accept (0: unlimited):
	MaxConnectionsIP = 5

	# Maximum number of channels a user can be member of (0: no limit):
	MaxJoins = 10

	# Maximum length of an user nickname (Default: 9, as in RFC 2812).
	# Please note that all servers in an IRC network MUST use the same
	# maximum nickname length!
	MaxNickLength = 15

	# Maximum penalty time increase in seconds, per penalty event. Set to -1
	# for no limit (the default), 0 to disable penalties altogether. The
	# daemon doesn't use penalty increases higher than 2 seconds during
	# normal operation, so values greater than 1 rarely make sense.
	;MaxPenaltyTime = -1

	# Maximum number of channels returned in response to a /list
	# command (0: unlimited):
	MaxListSize = 100

	# After <PingTimeout> seconds of inactivity the server will send a
	# PING to the peer to test whether it is alive or not.
	PingTimeout = 120

	# If a client fails to answer a PING with a PONG within <PongTimeout>
	# seconds, it will be disconnected by the server.
	PongTimeout = 20

[Options]
	# Optional features and configuration options to further tweak the
	# behavior of ngIRCd. If you want to get started quickly, you most
	# probably don't have to make changes here -- they are all optional.

	# List of allowed channel types (channel prefixes) for newly created
	# channels on the local server. By default, all supported channel
	# types are allowed. Set this variable to the empty string to disallow
	# creation of new channels by local clients at all.
	;AllowedChannelTypes = #&+

	# Are remote IRC operators allowed to control this server, e.g.
	# use commands like CONNECT, SQUIT, DIE, ...?
	;AllowRemoteOper = no

	# A directory to chroot in when everything is initialized. It
	# doesn't need to be populated if ngIRCd is compiled as a static
	# binary. By default ngIRCd won't use the chroot() feature.
	# ATTENTION: For this to work the server must have been started
	# with root privileges!
	;ChrootDir = /var/empty

	# Set this hostname for every client instead of the real one.
	# Use %x to add the hashed value of the original hostname.
	;CloakHost = cloaked.host

	# Use this hostname for hostname cloaking on clients that have the
	# user mode "+x" set, instead of the name of the server.
	# Use %x to add the hashed value of the original hostname.
	;CloakHostModeX = cloaked.user

	# The Salt for cloaked hostname hashing. When undefined a random
	# hash is generated after each server start.
	;CloakHostSalt = abcdefghijklmnopqrstuvwxyz

	# Set every clients' user name to their nickname
	;CloakUserToNick = yes

	# Try to connect to other IRC servers using IPv4 and IPv6, if possible.
	;ConnectIPv6 = yes
	;ConnectIPv4 = yes

	# Default user mode(s) to set on new local clients. Please note that
	# only modes can be set that the client could set using regular MODE
	# commands, you can't set "a" (away) for example! Default: none.
	;DefaultUserModes = i

	# Do DNS lookups when a client connects to the server.
	;DNS = yes

	# Do IDENT lookups if ngIRCd has been compiled with support for it.
	# Users identified using IDENT are registered without the "~" character
	# prepended to their user name.
	;Ident = yes

	# Directory containing configuration snippets (*.conf), that should
	# be read in after parsing this configuration file.
	;IncludeDir = /etc/conf.d

	# Enhance user privacy slightly (useful for IRC server on TOR or I2P)
	# by censoring some information like idle time, logon time, etc.
	;MorePrivacy = no

	# Normally ngIRCd doesn't send any messages to a client until it is
	# registered. Enable this option to let the daemon send "NOTICE *"
	# messages to clients while connecting.
	;NoticeBeforeRegistration = no

	# Should IRC Operators be allowed to use the MODE command even if
	# they are not(!) channel-operators?
	;OperCanUseMode = no

	# Should IRC Operators get AutoOp (+o) in persistent (+P) channels?
	;OperChanPAutoOp = yes

	# Mask IRC Operator mode requests as if they were coming from the
	# server? (This is a compatibility hack for ircd-irc2 servers)
	;OperServerMode = no

	# Use PAM if ngIRCd has been compiled with support for it.
	# Users identified using PAM are registered without the "~" character
	# prepended to their user name.
	;PAM = yes

	# When PAM is enabled, all clients are required to be authenticated
	# using PAM; connecting to the server without successful PAM
	# authentication isn't possible.
	# If this option is set, clients not sending a password are still
	# allowed to connect: they won't become "identified" and keep the "~"
	# character prepended to their supplied user name.
	# Please note: To make some use of this behavior, it most probably
	# isn't useful to enable "Ident", "PAM" and "PAMIsOptional" at the
	# same time, because you wouldn't be able to distinguish between
	# Ident'ified and PAM-authenticated users: both don't have a "~"
	# character prepended to their respective user names!
	;PAMIsOptional = no

	# When PAM is enabled, this value determines the used PAM
	# configuration.
	# This setting allows to run multiple ngIRCd instances with
	# different PAM configurations on each instance.
	# If you set it to "ngircd-foo", PAM will use
	# /etc/pam.d/ngircd-foo instead of the default
	# /etc/pam.d/ngircd.
	;PAMServiceName = ngircd

	# Let ngIRCd send an "authentication PING" when a new client connects,
	# and register this client only after receiving the corresponding
	# "PONG" reply.
	;RequireAuthPing = no

	# Silently drop all incoming CTCP requests.
	;ScrubCTCP = no

	# Syslog "facility" to which ngIRCd should send log messages.
	# Possible values are system dependent, but most probably auth, daemon,
	# user and local1 through local7 are possible values; see syslog(3).
	# Default is "local5" for historical reasons, you probably want to
	# change this to "daemon", for example.
	;SyslogFacility = local1

	# Password required for using the WEBIRC command used by some
	# Web-to-IRC gateways. If not set/empty, the WEBIRC command can't
	# be used. (Default: not set)
	;WebircPassword = xyz

[SSL]
	# SSL-related configuration options. Please note that this section
	# is only available when ngIRCd is compiled with support for SSL!
	# So don't forget to remove the ";" above if this is the case ...

	# SSL Server Key Certificate
	CertFile = /etc/ssl/server-cert.pem

	# Select cipher suites allowed for SSL/TLS connections. This defaults
	# to HIGH:!aNULL:@STRENGTH (OpenSSL) or SECURE128 (GnuTLS).
	# See 'man 1ssl ciphers' (OpenSSL) or 'man 3 gnutls_priority_init'
	# (GnuTLS) for details.
	# For OpenSSL:
	;CipherList = HIGH:!aNULL:@STRENGTH:!SSLv3
	# For GnuTLS:
	;CipherList = SECURE128:-VERS-SSL3.0

	# Diffie-Hellman parameters
	DHFile = /etc/ssl/dhparams.pem

	# SSL Server Key
	KeyFile = /etc/ssl/server-key.pem

	# password to decrypt SSLKeyFile (OpenSSL only)
	;KeyFilePassword = secret

	# Additional Listen Ports that expect SSL/TLS encrypted connections
	Ports = 9999

[Operator]
	# [Operator] sections are used to define IRC Operators. There may be
	# more than one [Operator] block, one for each local operator.

	# ID of the operator (may be different of the nickname)
	Name = joe

	# Password of the IRC operator
	Password = WSQre-Gy90uhi

	# Optional Mask from which /OPER will be accepted
	;Mask = *!ident@somewhere.example.com

[Operator]
	# More [Operator] sections, if you like ...

[Server]
	# Other servers are configured in [Server] sections. If you
	# configure a port for the connection, then this ngircd tries to
	# connect to the other server on the given port; if not it waits
	# for the other server to connect.
	# There may be more than one server block, one for each server.
	#
	# Server Groups:
	# The ngIRCd allows "server groups": You can assign an "ID" to every
	# server with which you want this ngIRCd to link. If a server of a
	# group won't answer, the ngIRCd tries to connect to the next server
	# in the given group. But the ngircd never tries to connect to two
	# servers with the same group ID.

	# IRC name of the remote server, must match the "Name" variable in
	# the [Global] section of the other server (when using ngIRCd).
	;Name = irc2.example.net

	# Internet host name or IP address of the peer (only required when
	# this server should establish the connection).
	;Host = connect-to-host.example.net

	# IP address to use as _source_ address for the connection. if
	# unspecified, ngircd will let the operating system pick an address.
	;Bind = 10.0.0.1

	# Port of the server to which the ngIRCd should connect. If you
	# assign no port the ngIRCd waits for incoming connections.
	;Port = 6667

	# Own password for the connection. This password has to be configured
	# as "PeerPassword" on the other server.
	;MyPassword = MySecret

	# Foreign password for this connection. This password has to be
	# configured as "MyPassword" on the other server.
	;PeerPassword = PeerSecret

	# Group of this server (optional)
	;Group = 123

	# Set the "Passive" option to "yes" if you don't want this ngIRCd to
	# connect to the configured peer (same as leaving the "Port" variable
	# empty). The advantage of this option is that you can actually
	# configure a port an use the IRC command CONNECT more easily to
	# manually connect this specific server later.
	;Passive = no

	# Connect to the remote server using TLS/SSL (Default: false)
	;SSLConnect = yes

	# Define a (case insensitive) list of masks matching nicknames that
	# should be treated as IRC services when introduced via this remote
	# server, separated by commas (",").
	# REGULAR SERVERS DON'T NEED this parameter, so leave it empty
	# (which is the default).
	# When you are connecting IRC services which mask as a IRC server
	# and which use "virtual users" to communicate with, for example
	# "NickServ" and "ChanServ", you should set this parameter to
	# something like "*Serv" or "NickServ,ChanServ,XyzServ".
	;ServiceMask = *Serv,Global

[Server]
	# More [Server] sections, if you like ...

[Channel]
	# Pre-defined channels can be configured in [Channel] sections.
	# Such channels are created by the server when starting up and even
	# persist when there are no more members left.
	# Persistent channels are marked with the mode 'P', which can be set
	# and unset by IRC operators like other modes on the fly.
	# There may be more than one [Channel] block, one for each channel.

	# Name of the channel
	Name = #home

	# Topic for this channel
	Topic = private talk

	# Initial channel modes, as used in "MODE" commands. Modifying lists
	# (ban list, invite list, exception list) is supported.
	# This option can be specified multiple times, evaluated top to bottom.
	;Modes = +tnk mykey +l 5
	;Modes = +b nick!~user@bad.host.example.com

	# Key file, syntax for each line: "<user>:<nick>:<key>".
	# Default: none.
	;KeyFile = /etc/#chan.key

[Channel]
	# More [Channel] sections, if you like ...

# -eof-

/etc/init.d/ngircd stop
/etc/init.d/ngircd disable



ngircd --configtest

/etc/init.d/ngircd start

logread

lsof -i | grep ngircd


#### in HexChat

/oper <operator name> <password>

##################### ZNC - IRC Bouncer ###############################

opkg list | grep znc
opkg install znc
opkg install znc-mod-crypt znc-mod-blockuser znc-mod-certauth znc-mod-cert znc-mod-notify-connect znc-mod-route-replies znc-mod-webadmin znc-mod-adminlog znc-mod-clientnotify

opkg install znc-mod-dcc znc-mod-fail2ban znc-mod-flooddetach

opkg install znc-mod-awaystore

/etc/init.d/znc stop
/etc/init.d/znc disable

cp /etc/config/znc /home/backup/etc/config/znc
mkdir /home/backup/etc/init.d
cp /etc/init.d/znc /home/backup/etc/init.d/znc


mkdir /home/znc
chown znc:znc /home/znc

znc --makepem --datadir /home/znc
chown znc:znc /home/znc/znc.pem


'Global Modules
adminlog	Log user connects, disconnects, and failed logins to a file and/or to syslog.
blockuser	Blocks certain users from using ZNC, saying their account was disabled.
certauth	This module lets users to log in via SSL client keys.
cyrusauth	This module is intended for admins who run a shell/web/email/etc server and want to provide ZNC access to their existing users.
fail2ban	Block IPs for some time after a failed login.
identfile	Posts the ident of a user to a file when they are trying to connect.
imapauth	Allow users to authenticate via IMAP.
lastseen	Logs when a user last logged in to ZNC.
modperl		Loads Perl scripts as ZNC modules.
modpython	Allows you to use modules written on Python.
notify_connect	Sends a notice to all admins when a user logs in or out of ZNC.
partyline	Allows ZNC users to join internal channels and query other ZNC users on the same ZNC.
webadmin	Allows you to add/remove/edit users and settings on the fly via a web browser.'

'User Modules

admin		(Now controlpanel) Allows you to add/remove/edit users and settings on the fly via IRC messages.
autoattach	Watches your detached channels and reattaches you automatically when there is specified activity in a channel you added to your autoattach list.
autoreply	Gives a automatic reply if someone messages you while you are away.
block_motd	Blocks the servers Message of the Day.
bouncedcc	Bounces DCC transfers through the znc server instead of sending them directly to the user.
buffextras	Add nick changes, joins, parts, topic changes etc. to your playback buffer.
chansaver	Saves channels to config when user joins and parts.
charset		Normalizes (i.e. converts) character encodings.
clearbufferonmsg	This module attempts to bridge the gap between being inundated with old buffer if you have KeepBuffer=true; and possibly missing messages when you ping out, if you have KeepBuffer=false.
clientnotify	Notify about new incoming connections to your user.
controlpanel	Allows you to add/remove/edit users and settings on the fly via IRC messages.
ctcpflood	This module tries to block CTCP floods.
dcc			This module allows you to transfer files to and from ZNC
disconkick	This module will kick your client from all channels if ZNC disconnects from server.
flooddetach	This module detaches you from channels which are flooded.
listsockets	This module displays a list of all open sockets in ZNC.
log			Log chat activity to file.
missingmotd	This user module will send 422 to clients when they login.
notes		Keep and replay notes. This is an example of WebMods.
sample		This is an example module to help with writing modules to do whatever you want.
send_raw	Allows you to send raw traffic to IRC from other users.
shell		Access your Unix shell via query right inside of your IRC client.

Network Modules

autocycle	Rejoin a channel when you are the only one there (to gain operator status).
autoop		Automatically give operator status to the good guys.
modtcl		Allows you to run Tcl scripts in ZNC.
autovoice	Automatically give voice status to everyone who joins some channel.
awaynick	Change your nick while you are away.
awaystore	When you are set away or detached, this module will save all private messages for you. The messages can be read until you delete them. This module will also set you away when you are idle some time.
cert		This module lets users use their own SSL certificate to connect to a server.
crypt		Encryption for channel/private messages.
keepnick	Tries to get and keep your primary nick if it is taken.
kickrejoin	Implements auto-rejoin-on-kick.
modules_online	Fakes online status of ZNC modules to fix some clients.
nickserv	Auths you with NickServ.
perform		Performs commands on connect.
q			Auths you with Q (and a little more).
raw			View all of the raw traffic.
route_replies	Routes back answers to the right client when connected with multiple clients.
sasl		Allows you to authenticate to an IRC network via SASL
savebuff	Saves your channel buffers into an encrypted file so they can survive restarts and reboots.
schat		SSL (encrypted) DCC chats.
simple_away	Automatically set you away on IRC when disconnected from the bouncer.
stickychan	Keeps you in specified channels.
watch		Monitor activity for specific text patterns from specific users and have the text sent to a special query window.
'


# nano /etc/config/znc
# not used






znc --makeconf --datadir /home/znc --allow-root 

[ ** ] -- Global settings --
[ ** ] 
[ ?? ] Listen on port (1025 to 65534): 5000
[ ?? ] Listen using SSL (yes/no) [no]: yes
[ ?? ] Listen using both IPv4 and IPv6 (yes/no) [yes]: 
[ .. ] Verifying the listener...
[ ** ] Enabled global modules [webadmin]
[ ** ] 
[ ** ] -- Admin user settings --
[ ** ] 
[ ?? ] Username (alphanumeric): stardust
[ ?? ] Enter password: UgiiL-Q371chDC-Z2B7ln
[ ?? ] Confirm password: UgiiL-Q371chDC-Z2B7ln
[ ?? ] Nick [stardust]: 
[ ?? ] Alternate nick [stardust_]: 
[ ?? ] Ident [stardust]: 
[ ?? ] Real name (optional): 
[ ?? ] Bind host (optional): 
[ ** ] Enabled user modules []
[ ** ] 
[ ?? ] Set up a network? (yes/no) [yes]: 
[ ** ] 
[ ** ] -- Network settings --
[ ** ] 
[ ?? ] Name [freenode]: 127.0.0.1
[ ?? ] Name [freenode]: localhost
[ ?? ] Server host (host only): localhost
[ ?? ] Server uses SSL? (yes/no) [no]: yes
[ ?? ] Server port (1 to 65535) [6697]: 9999
[ ?? ] Server password (probably empty): 
[ ?? ] Initial channels: #home
[ ** ] Enabled network modules []
[ ** ] 
[ .. ] Writing config [/home/znc/configs/znc.conf]...
[ ** ] 
[ ** ] To connect to this ZNC you need to connect to it as your IRC server
[ ** ] using the port that you supplied.  You have to supply your login info
[ ** ] as the IRC server password like this: user/network:pass.
[ ** ] 
[ ** ] Try something like this in your IRC client...
[ ** ] /server <znc_server_ip> +5000 stardust:<pass>
[ ** ] 
[ ** ] To manage settings, users and networks, point your web browser to
[ ** ] https://<znc_server_ip>:5000/
[ ** ] 
[ ?? ] Launch ZNC now? (yes/no) [yes]: no





chown znc:znc -R /home/znc

nano /etc/init.d/znc

#!/bin/sh /etc/rc.common
# Copyright (C) 2010 Openwrt.org

START=60

USE_PROCD=1

ZNC_CONFIG_PATH=/home/znc
PID_FILE=${ZNC_CONFIG_PATH}/znc.pid
ZNC_CONFIG=${ZNC_CONFIG_PATH}/configs/znc.conf


RUNAS_USER=znc
RUNAS_GROUP=znc

. /lib/functions.sh

start_service() {
	procd_open_instance
	procd_set_param command /usr/bin/znc --foreground --datadir $ZNC_CONFIG_PATH --debug
	#procd_append_param command -f -d $ZNC_CONFIG_PATH
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param user ${RUNAS_USER}
	procd_set_param respawn
	procd_close_instance
}



# open web console at  https://192.168.5.5:5000/

# on local computer in LAN: open hexchat to server 192.168.5.5:5000







################################## µMurmur   https://openwrt.org/docs/guide-user/services/voip/umurmur ###################

opkg info umurmur-openssl

# Firewall: The default ports are 64738 tcp and 64738 udp. open them up in /etc/config/firewall. 

opkg install umurmur-openssl

nano /etc/umurmur.conf


netstat -lp | grep umurmurd




### on remote computer
sudo apt-get install mumble

# follow wizard to connect to server at 192.168.5.5


/etc/init.d/umurmur stop
/etc/init.d/umurmur disable


#################### mail server ############################

opkg update
opkg install postfix

postconf -a
'cyrus
dovecot'


# backup config
cp -R /etc/postfix /home/backup/etc/postfix

nano /etc/postfix/main.cf



### ipv6 for yggdrasil
inet_protocols = ipv4, ipv6


default_database_type = cdb
config_directory = /etc/postfix
command_directory = /usr/sbin
daemon_directory = /usr/libexec/postfix
shlib_directory = /usr/lib/postfix
manpage_directory = no
data_directory = /usr/var/lib/postfix
queue_directory = /usr/var/spool/postfix
mail_spool_directory = /usr/var/mail
myhostname = rpirouter
mydomain = lan
mynetworks_style = subnet

smtputf8_enable = no
# [200::]/8 -> yggdrasil network
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 192.168.5.0/24 [200::]/8
#### list all hostnames connected to your network
mydestination = $myhostname, rpirouter.lan, lan, localhost.localdomain, localhost, rpi4.lan

myorigin = rpirouter.lan
relayhost =
biff = no

### ssl section
shlib_directory = /usr/lib/postfix
smtp_tls_CAfile = /etc/ssl/certs/ca-cert.pem
smtp_tls_note_starttls_offer = yes
smtpd_sasl_auth_enable = yes
smtpd_sasl_local_domain = lan
#smtpd_sasl_path = private/auth
#smtpd_sasl_type = dovecot
smtpd_sasl_type = cyrus
smtpd_tls_ask_ccert = yes
smtpd_tls_auth_only = no
smtpd_tls_ccert_verifydepth = 2
smtpd_tls_cert_file = /etc/ssl/server-cert.pem
smtpd_tls_key_file = /etc/ssl/server-key.pem
### for debugging
#smtpd_tls_loglevel = 4
smtpd_tls_loglevel = 0
smtpd_tls_received_header = yes
smtpd_tls_security_level = may
smtpd_tls_session_cache_timeout = 3600s
smtpd_use_tls = yes



nano /etc/postfix/master.cf
# service type  private unpriv  chroot  wakeup  maxproc command + args
#### option -v -> verbose
#smtp      inet  n       -       n       -       -       smtpd -v
#smtp      inet  n       -       n       -       1       postscreen
#smtpd     pass  -       -       n       -       -       smtpd
#dnsblog   unix  -       -       n       -       0       dnsblog
#tlsproxy  unix  -       -       n       -       0       tlsproxy
submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=may
  -o smtpd_sasl_auth_enable=yes
#
smtps     inet  n       -       n       -       -       smtpd
   -o syslog_name=postfix/smtps
   -o smtpd_sasl_auth_enable=yes
   -o smtpd_tls_wrappermode=yes




service postfix restart

###################### mutt - mail client 
opkg install mutt

mutt -f /usr/var/mail/root

#### dovecot ####################################
opkg list | grep dovecot
dovecot-pigeonhole - 2.3.20-0.5.20-1 - Pigeonhole provides mail filtering facilities for Dovecot using the Sieve (RFC 5228) language.
dovecot-utils - 2.3.20-1 - doveadm and dsync utilities for Dovecot
dovecot2.3.20 - 2.3.20-1 - Dovecot is a program which provides POP3 and IMAP services.


opkg install dovecot2.3.20

/etc/init.d/dovecot stop
/etc/init.d/dovecot disable



nano /etc/dovecot/conf.d/10-master.conf

service imap-login {
  inet_listener imap {
    #port = 143
  }
  inet_listener imaps {
  #  port = 993
  #  ssl = yes
  }
}


service pop3-login {
  inet_listener pop3 {
    #port = 110
  }
  inet_listener pop3s {
    #port = 995
    #ssl = yes
  }
}


service submission-login {
  inet_listener submission {
    #port = 587
  }
}

service auth {
  unix_listener auth-userdb {
    #mode = 0666
    mode = 0777
    user = postfix
    group = root
  }
  #unix_listener /usr/var/spool/postfix/private/auth {
    #mode = 0660
    #mode = 0777
    #user = postfix
    #group = postfix
  #}
}

service auth-worker {
  #user = root
  group = root
}




nano /etc/dovecot/conf.d/10-auth.conf
auth_username_format = %n
auth_mechanisms = plain login
#auth_mechanisms = login
#disable_plaintext_auth = yes


!include auth-system.conf.ext

nano /etc/dovecot/conf.d/auth-system.conf.ext
passdb {
  driver = passwd
}
passdb {
  driver = shadow
}
userdb {
  # <doc/wiki/AuthDatabase.Passwd.txt>
  driver = passwd
}

nano /etc/dovecot/conf.d/10-logging.conf
log_path = syslog
# for debugging
auth_verbose = yes
mail_debug = yes
verbose_ssl = yes
auth_verbose_passwords = yes
auth_debug = yes



### Ports 110 (POP3 with STARTTLS), and 995 (POP3S)  # 143 (IMAP with STARTTLS), 993 (IMAPS) 

nano /etc/dovecot/dovecot.conf
#postmaster_address = postmaster at rpi4.lan 
#protocols = imap submission
# protocols = imap pop3 ##imaps  pop3s : obsolete
protocols = pop3 
#Allows Dovecot to listen to all input connections (ipv4 / ipv6)
listen = *, ::

#mail_location = maildir:/usr/var/mail/%n
# https://doc.dovecot.org/configuration_manual/mail_location/mbox/
mail_location = mbox:~/mail:INBOX=/usr/var/mail/%u



nano /etc/dovecot/conf.d/10-ssl.conf
ssl = yes
ssl_cert = </etc/ssl/server-cert.pem
ssl_key = </etc/ssl/server-key.pem
ssl_verify_client_cert = no
ssl_dh = </etc/ssl/dhparams.pem




grep mail_location -R /etc/dovecot 
/etc/dovecot/conf.d/10-mail.conf:# path given in the mail_location setting.
/etc/dovecot/conf.d/10-mail.conf:#   mail_location = maildir:~/Maildir


nano /etc/dovecot/conf.d/10-mail.conf
# https://doc.dovecot.org/configuration_manual/mail_location/mbox/
mail_location = mbox:~/mail:INBOX=/usr/var/mail/%u


### debug
/usr/sbin/dovecot -F


netstat -ntpl | grep dovecot



/etc/init.d/dovecot start






#### i2p ###############################################################################################
opkg install i2pd

/etc/init.d/i2pd stop
/etc/init.d/i2pd disable


nano /etc/config/i2pd

config i2pd
        # Set where i2pd should store its data (netDB, certificates, addresses, etc)
        # By default we store it in RAM so no data is written to ROM.
        # IMPORTANT!
        # Data is consistently rewritten. DO NOT POINT IT TO INNER ROM. Flash will
        # die.
        option data_dir '/var/lib/i2pd'

        # If you don't store i2pd data permanently, you can still choose to store only
        # netDb. If not, i2pd will be forced to do HTTP reseeding on every start.
        # Storing netDb may be useful if HTTP reseeding is not possible or blocked
        # (by censorship).
        # Even netDb doesn't take up too much space, extroot is still strongly
        # recommended to avoid flash wear-out.
        #option netdb_dir '/etc/i2pd/netDb'

        # Also you can store permanently addressbook, which is used for accessing
        # to i2p addresses using human-understandable addresses in .i2p zone.
        # If not, it will be fetched from subscription at start after 3 minutes.
        option addressbook_dir '/etc/i2pd/addressbook'





cp -R /etc/i2pd /home/backup


nano /etc/i2pd/i2pd.conf


## Configuration file for a typical i2pd user
## See https://i2pd.readthedocs.io/en/latest/user-guide/configuration/
## for more options you can use in this file.

## Lines that begin with "## " try to explain what's going on. Lines
## that begin with just "#" are disabled commands: you can enable them
## by removing the "#" symbol.

## Tunnels config file
## Default: ~/.i2pd/tunnels.conf or /var/lib/i2pd/tunnels.conf
tunconf = /etc/i2pd/tunnels.conf

## Tunnels config files path
## Use that path to store separated tunnels in different config files.
## Default: ~/.i2pd/tunnels.d or /var/lib/i2pd/tunnels.d
tunnelsdir = /etc/i2pd/tunnels.d

## Path to certificates used for verifying .su3, families
## Default: ~/.i2pd/certificates or /var/lib/i2pd/certificates
certsdir = /usr/share/i2pd/certificates

## Where to write pidfile (default: i2pd.pid, not used in Windows)
# pidfile = /run/i2pd.pid

## Logging configuration section
## By default logs go to stdout with level 'info' and higher
## For Windows OS by default logs go to file with level 'warn' and higher
##
## Logs destination (valid values: stdout, file, syslog)
##  * stdout - print log entries to stdout
##  * file - log entries to a file
##  * syslog - use syslog, see man 3 syslog
log = syslog
## Path to logfile (default - autodetect)
# logfile = /var/log/i2pd/i2pd.log
## Log messages above this level (debug, info, *warn, error, none)
## If you set it to none, logging will be disabled
loglevel = none
## Write full CLF-formatted date and time to log (default: write only time)
# logclftime = true

## Daemon mode. Router will go to background after start. Ignored on Windows
# daemon = true

## Specify a family, router belongs to (default - none)
# family =

## Network interface to bind to
## Updates address4/6 options if they are not set
# ifname =
## You can specify different interfaces for IPv4 and IPv6
# ifname4 =
# ifname6 =


## Local address to bind transport sockets to
## Overrides host option if:
## For ipv4: if ipv4 = true and nat = false
## For ipv6: if 'host' is not set or ipv4 = true
# address4 =
# address6 =

## External IPv4 or IPv6 address to listen for connections
## By default i2pd sets IP automatically
## Sets published NTCP2v4/SSUv4 address to 'host' value if nat = true
## Sets published NTCP2v6/SSUv6 address to 'host' value if ipv4 = false
# host = 1.2.3.4

## Port to listen for connections
## By default i2pd picks random port. You MUST pick a random number too,
## don't just uncomment this
port = 36865

## Enable communication through ipv4
ipv4 = true
## Enable communication through ipv6
ipv6 = true 

## Enable SSU transport (default = true)
ssu = true 

## Bandwidth configuration
## L limit bandwidth to 32KBs/sec, O - to 256KBs/sec, P - to 2048KBs/sec,
## X - unlimited
## Default is L (regular node) and X if floodfill mode enabled. If you want to
## share more bandwidth without floodfill mode, uncomment that line and adjust
## value to your possibilities
# bandwidth = L
## Max % of bandwidth limit for transit. 0-100. 100 by default
# share = 100

## Router will not accept transit tunnels, disabling transit traffic completely
## (default = false)
notransit = false

## Router will be floodfill
## Note: that mode uses much more network connections and CPU!
# floodfill = true

[ntcp2]
## Enable NTCP2 transport (default = true)
# enabled = true
## Publish address in RouterInfo (default = true)
# published = true
## Port for incoming connections (default is global port option value)
# port = 4567


[ssu2]
## Enable SSU2 transport (default = false for 2.43.0)
enabled = true
## Publish address in RouterInfo (default = false for 2.43.0)
published = true
## Port for incoming connections (default is global port option value or port + 1 if SSU is enabled)
# port = 4567

[http]
## Web Console settings
## Uncomment and set to 'false' to disable Web Console
enabled = true
## Address and port service will listen on
address = 192.168.5.5
port = 7070
## Path to web console, default "/"
# webroot = /
## Uncomment following lines to enable Web Console authentication
auth = true
user = i2pd
pass = TF5f-DFea2-gYvbJHv
## Select webconsole language
## Currently supported english (default), afrikaans, armenian, chinese, french,
## german, russian, turkmen, ukrainian and uzbek languages
# lang = english

[httpproxy]
## Uncomment and set to 'false' to disable HTTP Proxy
enabled = true
## Address and port service will listen on
address = 192.168.5.5
port = 4444
## Optional keys file for proxy local destination
# keys = http-proxy-keys.dat
## Enable address helper for adding .i2p domains with "jump URLs" (default: true)
# addresshelper = true
## Address of a proxy server inside I2P, which is used to visit regular Internet
# outproxy = http://false.i2p
## httpproxy section also accepts I2CP parameters, like "inbound.length" etc.


[socksproxy]
## Uncomment and set to 'false' to disable SOCKS Proxy
enabled = true
## Address and port service will listen on
address = 192.168.5.5
port = 4447
## Optional keys file for proxy local destination
# keys = socks-proxy-keys.dat
## Socks outproxy. Example below is set to use Tor for all connections except i2p
## Uncomment and set to 'true' to enable using of SOCKS outproxy
# outproxy.enabled = false
## Address and port of outproxy
# outproxy = 127.0.0.1
# outproxyport = 9050
## socksproxy section also accepts I2CP parameters, like "inbound.length" etc.

[sam]
## Comment or set to 'false' to disable SAM Bridge
enabled = true 
## Address and port service will listen on
address = 192.168.5.5
port = 7656

[bob]
## Uncomment and set to 'true' to enable BOB command channel
# enabled = false
## Address and port service will listen on
# address = 127.0.0.1
# port = 2827

[i2cp]
## Uncomment and set to 'true' to enable I2CP protocol
# enabled = false
## Address and port service will listen on
# address = 127.0.0.1
# port = 7654

[i2pcontrol]
## Uncomment and set to 'true' to enable I2PControl protocol
# enabled = false
## Address and port service will listen on
# address = 127.0.0.1
# port = 7650
## Authentication password. "itoopie" by default
# password = itoopie


[precomputation]
## Enable or disable elgamal precomputation table
## By default, enabled on i386 hosts
# elgamal = true

[upnp]
## Enable or disable UPnP: automatic port forwarding (enabled by default in WINDOWS, ANDROID)
enabled = false
## Name i2pd appears in UPnP forwardings list (default = I2Pd)
# name = I2Pd

[meshnets]
## Enable connectivity over the Yggdrasil network
# yggdrasil = true
## You can bind address from your Yggdrasil subnet 300::/64
## The address must first be added to the network interface
# yggaddress = 

[reseed]
## Options for bootstrapping into I2P network, aka reseeding
## Enable or disable reseed data verification.
verify = true
## URLs to request reseed data from, separated by comma
## Default: "mainline" I2P Network reseeds
# urls = https://reseed.i2p-projekt.de/,https://i2p.mooo.com/netDb/,https://netdb.i2p2.no/
## Reseed URLs through the Yggdrasil, separated by comma
# yggurls = http://[324:9de3:fea4:f6ac::ace]:7070/
## Path to local reseed data file (.su3) for manual reseeding
# file = /path/to/i2pseeds.su3
## or HTTPS URL to reseed from
# file = https://legit-website.com/i2pseeds.su3
## Path to local ZIP file or HTTPS URL to reseed from
# zipfile = /path/to/netDb.zip
## If you run i2pd behind a proxy server, set proxy server for reseeding here
## Should be http://address:port or socks://address:port
# proxy = http://127.0.0.1:8118
## Minimum number of known routers, below which i2pd triggers reseeding. 25 by default
# threshold = 25

[addressbook]
## AddressBook subscription URL for initial setup
## Default: reg.i2p at "mainline" I2P Network
defaulturl = http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/hosts.txt
## Optional subscriptions URLs, separated by comma
subscriptions = http://reg.i2p/hosts.txt,http://identiguy.i2p/hosts.txt,http://stats.i2p/cgi-bin/newhosts.txt,http://rus.i2p/hosts.txt

[limits]
## Maximum active transit sessions (default:2500)
transittunnels = 500
## Limit number of open file descriptors (0 - use system limit)
# openfiles = 0
## Maximum size of corefile in Kb (0 - use system limit)
# coresize = 0

[trust]
## Enable explicit trust options. false by default
# enabled = true
## Make direct I2P connections only to routers in specified Family.
# family = MyFamily
## Make direct I2P connections only to routers specified here. Comma separated list of base64 identities.
# routers =
## Should we hide our router from other routers? false by default
# hidden = true

[exploratory]
## Exploratory tunnels settings with default values
# inbound.length = 2
# inbound.quantity = 3
# outbound.length = 2
# outbound.quantity = 3

[persist]
## Save peer profiles on disk (default: true)
# profiles = true
## Save full addresses on disk (default: true)
# addressbook = true

[cpuext]
## Use CPU AES-NI instructions set when work with cryptography when available (default: true)
# aesni = true
## Use CPU AVX instructions set when work with cryptography when available (default: true)
# avx = true
## Force usage of CPU instructions set, even if they not found
## DO NOT TOUCH that option if you really don't know what are you doing!
# force = false




nano /etc/config/firewall

config zone 'i2p'
        option name 'i2p'
        option network 'lan'
        option input 'REJECT'
        option output 'ACCEPT'
        option forward 'REJECT'
        option conntrack '1'


config rule
        option enabled '1'
        option name 'Allow-I2p-HttpProxy'
        option src 'i2p'
        option proto 'tcp'
        option dest_port '4444'
        option target 'ACCEPT'
        option family 'ipv4'

config rule
        option enabled '1'
        option name 'Allow-I2p-SOCKS'
        option src 'i2p'
        option proto 'tcp'
        option dest_port '4447'
        option target 'ACCEPT'
        option family 'ipv4'


service firewall restart



/etc/init.d/i2pd start

logread -e i2pd

