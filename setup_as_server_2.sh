

### yggdrasil ###


##### for running yggdrasil as a peer (optional), listen on port: 55550
nano /etc/config/yggdrasil

config listen_address
	option uri 'tcp://0.0.0.0:55550'


### forward port in firewall, WAN side port: 55551
nano /etc/config/firewall

config redirect
	option target 'DNAT'
	list proto 'tcp'
	option src 'wan'
	option dest_port '55550'
	option src_dport '55551'
	option name 'YGGDRASIL-INCOMING'


service firewall restart





# clients connect to your peer 
nano /etc/config/yggdrasil

config peer
	option uri 'tcp://123.123.123.123:55551'


## configure more peers



#### allow yggdrasil to access services 



nano /etc/config/firewall


config rule
	option name 'Allow-Murmur-Yggdrasil'
	option src 'yggdrasil'
	option dest_port '64738'
	option target 'ACCEPT'

config rule
	option name 'Allow-IRC-SSL-Yggdrasil'
	list proto 'tcp'
	option src 'yggdrasil'
	option dest_port '9999'
	option target 'ACCEPT'

config rule
	option name 'Allow-IRC-noSSL-Yggdrasil'
	list proto 'tcp'
	option src 'yggdrasil'
	option dest_port '60666'
	option target 'ACCEPT'

config rule
	option name 'Allow-POP3S-Yggdrasil'
	list proto 'tcp'
	option src 'yggdrasil'
	option dest_port '995'
	option target 'ACCEPT'

config rule
	option name 'Allow-SMTPS-Yggdrasil'
	list proto 'tcp'
	option src 'yggdrasil'
	option dest_port '465'
	option target 'ACCEPT'



service firewall restart


### test port from outside
# nmap -sS -O -p9999 ext_IP



service yggdrasil restart




### debug postfix yggdrasil
openssl s_client -starttls smtp -crlf -connect [201:7d16:b31d:453d:62dd:a719:a32c:ffb1]:465



yggdrasilctl getself



yggdrasilctl getPeers

### add yggdrasil addresses to hosts, important for resolving names, mailserver
nano /etc/hosts
202:b761:f59b:405f:602e:5421:b248:2253 rpirouter2.lan
201:7d16:b31d:453d:62dd:a719:a32c:ffb1 rpirouter.lan



/etc/init.d/dnsmasq restart

logread




############################ create-self-signed-certificates-keys ##################################
########## https://mariadb.com/docs/xpand/security/data-in-transit-encryption/create-self-signed-certificates-keys-openssl/

cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.org

nano /etc/ssl/openssl.cnf


## Creating the Certificate Authoritys Certificate and Keys

# 1. Generate a private key for the CA:

openssl genrsa 2048 > ca-key.pem

# 2. Generate the X509 certificate for the CA:

openssl req -new -x509 -nodes -days 365000 \
       -key ca-key.pem \
       -out ca-cert.pem


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


# copy/move files

chmod 644 server-key.pem

mv server-key.pem /etc/ssl/server-key.pem
mv server-cert.pem /etc/ssl/server-cert.pem
cp ca-key.pem /etc/ssl/private/ca-key.pem
cp ca-cert.pem /etc/ssl/certs/ca-cert.pem
mv dhparams.pem /etc/ssl/dhparams.pem



##################################### I2P network ##############################################################

nano /etc/i2pd/i2pd.conf

# i2p wan port, could be opened on firewall
port = 12345

[http]
enabled = true
address = 192.168.5.5
port = 7070
auth = true
user = i2pd
pass = YOUR-PASSWD



[meshnets]
## Enable connectivity over the Yggdrasil network
# yggdrasil = true
## You can bind address from your Yggdrasil subnet 300::/64
## The address must first be added to the network interface
# yggaddress = 



#### remove old backup key files

rm /home/backup/i2pd/*.dat




# create hidden tunnels to services on rpirouter

nano /etc/i2pd/tunnels.conf


[SERVER-SMPTS]
type = server
host = 127.0.0.1
port = 465
keys = server-smtp.dat

[SERVER-POP3S]
type = server
host = 127.0.0.1
port = 995
keys = server-pop3s.dat

[SERVER-IRC-SSL]
type = irc
host = 127.0.0.1     
port = 9999
keys = server-irc-ssl.dat

[SERVER-IRC]
type = irc
host = 127.0.0.1
port = 60666
keys = server-irc.dat



/etc/init.d/i2pd start

# backup server tunnel keys (keys placed in ram disk)
cp -a /var/lib/i2pd/server*.dat /home/backup/i2pd


# change start script
nano /etc/init.d/i2pd

# restore key files for tunnels (created and located in RAM)
cp -a /home/backup/i2pd/server*.dat "$data_dir"



## go to i2pd webconsole:  http://192.168.5.5:7070/  


i2pd webconsole

Client Tunnels:
IRC-ILITA ⇐ ncn23u3c4rhs4purzymsxfade2arqiapmmydx2lxe7lhzfekcr6a.b32.i2p
HTTP Proxy ⇐ ib2x3b27ucmu7isgfltwy5uemmr5i22fgoqkmqk2ajj2ohfudzqq.b32.i2p
SOCKS Proxy ⇐ ib2x3b27ucmu7isgfltwy5uemmr5i22fgoqkmqk2ajj2ohfudzqq.b32.i2p

Server Tunnels:
SERVER-IRC-SSL ⇒ evp6c43hjnvz5d7gzbmrlrrdxrx5vcoafrpw5kzimpctd4syv5aa.b32.i2p:9999
SERVER-IRC ⇒ lolc6ox3j4bbtg3kyxcrqisasx6m3d4zauzgrnmki6g5ckta6ina.b32.i2p:60666
SERVER-POP3S ⇒ w5f6gfo5oqw4mvsscvuvamgpgfdzazrnpnth44ksezgdc4kiixaq.b32.i2p:995
SERVER-SMPTS ⇒ xukvtb6m54y45lmzpgemlk2ihosr7swukyfx7x67s4on3ewdwa7q.b32.i2p:465


### i2p addresses of server tunnels needed by clients to connect to










##################################################### services ##########################################




#### SMTP: postfix ##############################################
/etc/postfix/main.cf

#### list all hostnames connected to your network. should be in /etc/hosts as well
mydestination = $myhostname, rpirouter.lan, lan, localhost.localdomain, localhost, rpi4.lan

/etc/init.d/postfix stop

/etc/init.d/postfix start

# show config
postconf -n



#### POP3: dovecot ##############################################
/etc/init.d/dovecot start




################### IRC Server: ngircd ##################
nano /etc/ngircd.conf


[Global]
	Name = rpirouter.lan
	AdminInfo1 = Description
	AdminInfo2 = Location
	AdminEMail = admin@rpi_router.lan
	Info = Rpi IRC Server
	Listen = 127.0.0.1,192.168.5.5,::
	MotdPhrase = "Welcome to my IRC Server!"
	# Global password for all users needed to connect to the server.
	# (Default: not set)
	Password = abc-def-123
	Ports = 60666


[SSL]
	CertFile = /etc/ssl/server-cert.pem
	DHFile = /etc/ssl/dhparams.pem
	KeyFile = /etc/ssl/server-key.pem
	# password to decrypt SSLKeyFile (OpenSSL only)
	;KeyFilePassword = secret
	# Additional Listen Ports that expect SSL/TLS encrypted connections
	Ports = 9999

[Operator]
	Name = joe
	# Password of the IRC operator
	Password = WSQre-Gy90uhi


[Channel]
	Name = #home
	Topic = private talk






ngircd --configtest

/etc/init.d/ngircd stop
/etc/init.d/ngircd start


logread

lsof -i | grep ngircd


##################### optional: ZNC - IRC Bouncer ###############################

# remove old dir
rm -r /home/znc

# create new one
mkdir /home/znc
chown znc:znc /home/znc


# create new certificate
znc --makepem --datadir /home/znc
chown znc:znc /home/znc/znc.pem

# setup new conf file
znc --makeconf --datadir /home/znc --allow-root 

# change owner
chown znc:znc -R /home/znc


/etc/init.d/znc start

##################### uMurmur VoIP server ###############################

/etc/init.d/umurmur start


