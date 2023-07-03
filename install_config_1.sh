
# download the image for your model and flash SD

# extract/unzip
tar -xvf openwrt_image_file.tar.gz

# burn to SD card
dd if=rpirouter.3.img of=/dev/sdX bs=2M conv=fsync
sync

# insert SD card in Raspberry, start


# connect by LAN or WLAN

# start openwrt and connet to 192.168.5.5 at lan
ssh root@192.168.5.5

# change root passwd
passwd

QAXQP34-29vpU797CUP



### setup wifi ###
cat /etc/config/wireless

## go to https://192.168.5.5/cgi-bin/luci/admin/network/wireless

# set SSID: rpi_router
# wlan passwd: psdQPVBRZs13127xc1b3weqlp293

# get info
iwinfo



#### manage users ####
## change password: as root:
passwd bob



## remove user:

nano /etc/passwd 
# remove
bob:x:502:501::/home/bob:/bin/false

nano /etc/shadow
# remove 
bob:$1$.6H07Cnf$WBbExyJslLTwIorxG6IIR1:19533:0:99999:7:::


# remove home directory
rm -R /home/bob

### add user
useradd --gid mailuser --create-home -u 507 --shell /bin/ash tom

### change host name
uci show system

nano /etc/config/system

service system restart


##### show all services: running, stopped, enabled, disabled
service 

service | grep running

# stop/disable service at boot
/etc/init.d/tor stop
/etc/init.d/tor disable


########### change yggdrasil conf
# generate a new conf file, than insert values in /etc/config/yggdrasil
yggdrasil -genconf > yggdrasil.conf

cat yggdrasil.conf

#change values for PublicKey/PrivateKey in /etc/config/yggdrasil
nano /etc/config/yggdrasil

config yggdrasil 'yggdrasil'
	option PublicKey '60ba5338aeb0a74896399734c01382f926e711f853986375de071dd969d7344a'
	option PrivateKey '79f584d8875cc996f89e06c317436cdaa4ea0f939aae3859b9ceb9de942a828a60ba5338aeb0a74896399734c01382f926e711f853986375de071dd969d7344a'

