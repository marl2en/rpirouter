################# on Linux computer connected to rpirouter ####################################


### email client: claws-mail ######
sudo apt-get update
sudo apt-get install claws-mail

### irc client: hexchat ###########
sudo apt-get install hexchat

### VoIP client: mumble ###########
sudo apt-get install mumble




############## if local rpirouter is running as server: ################################################################################################


## services on local rpirouter (192.158.5.5) on ports:
- IRC SSL: 		9999
- IRC noSSL: 	60666
- POP3 SSL: 	995
- SMTP SSL: 	465





### configure claws-mail ########################

configuration -> create new account -> new

account preferences:
- basic: 
	Full name: joe
	email addres: 			joe@rpirouter.lan
	server for receiving: 	192.158.5.5
	SMTP server (send): 	192.158.5.5
	User ID: 				joe
	Password:				joes unix password

- SSL/TLS:
	POP: 			use SSL/TLS
	Send (SMTP):	use SSL/TLS

- Advanced:
	SMTP Port:		465
	POP Port:		995


### configure hexchat ########################


### SSL, server port 9999 ####
- network list -> add
	servers: 									192.158.5.5/9999
	Use SSL for all servers on this network: 	yes
	Accept invalid SSL certificates:			yes
	Login method: 								default
	Password: 									abc-def-123 		# /etc/ngircd.conf -> [Global] -> Password


### no SSL ####
- network list -> add
	servers: 									192.158.5.5/60666
	Use SSL for all servers on this network: 	no
	Accept invalid SSL certificates:			no
	Login method: 								default
	Password: 									abc-def-123 		# /etc/ngircd.conf -> [Global] -> Password


### configure mumble ########################

Mumble Server Connect
- Add New ...
		Address: 	192.158.5.5
		Port: 		64738
		Username: 	YOUR_CHOISE
		Label:		YOUR_CHOISE












############## using yggdrasil network ################################################################################################

# install yggdrasil 
# should auto connect to yggdrasil on rpirouter
# important for routing IPv6 yggdrasil traffic

# https://yggdrasil-network.github.io/installation.html

sudo apt-get install yggdrasil

# sudo nano /etc/yggdrasil.conf
# not needed to configure peers here because of auto connection in lan when multicast active at yggdrasil node (rpirouter local router)


sudo yggdrasilctl getPeers

# yggdrasil should run at local computer, rpirouter and remote rpirouter


### configure claws-mail ########################

configuration -> create new account -> new

account preferences:
- basic: 
	Full name: joe
	email addres: 			joe@rpirouter.lan
	server for receiving: 	201:7d16:b31d:453d:62dd:a719:a32c:ffb1	#yggdrasil address of rpirouter running postfix/dovecot
	SMTP server (send): 	201:7d16:b31d:453d:62dd:a719:a32c:ffb1
	User ID: 				joe
	Password:				joes unix password

- SSL/TLS:
	POP: 			use SSL/TLS
	Send (SMTP):	use SSL/TLS

- Advanced:
	SMTP Port:		465
	POP Port:		995


### configure hexchat ########################


### SSL, server port 9999 ####
- network list -> add
	servers: 									201:7d16:b31d:453d:62dd:a719:a32c:ffb1/9999			#yggdrasil address of rpirouter running ngircd
	Use SSL for all servers on this network: 	yes
	Accept invalid SSL certificates:			yes
	Login method: 								default
	Password: 									abc-def-123 		# /etc/ngircd.conf -> [Global] -> Password


### no SSL ####
- network list -> add
	servers: 									201:7d16:b31d:453d:62dd:a719:a32c:ffb1/60666
	Use SSL for all servers on this network: 	no
	Accept invalid SSL certificates:			no
	Login method: 								default
	Password: 									abc-def-123 		# /etc/ngircd.conf -> [Global] -> Password


### configure mumble ########################

Mumble Server Connect
- Add New ...
		Address: 	201:7d16:b31d:453d:62dd:a719:a32c:ffb1
		Port: 		64738
		Username: 	YOUR_CHOISE
		Label:		YOUR_CHOISE


############## using i2p network ################################################################################################


### see: setup_as_client_2.sh 


## services on remote rpirouter are now accessable via i2p network on ports:
- IRC SSL: 		9998
- IRC noSSL: 	60667
- POP3 SSL: 	9950
- SMTP SSL: 	4650

# on local rpirouter with address 192.158.5.5


### configure claws-mail ########################

configuration -> create new account -> new

account preferences:
- basic: 
	Full name: joe
	email addres: 			joe@rpirouter.lan
	server for receiving: 	192.158.5.5
	SMTP server (send): 	192.158.5.5
	User ID: 				joe
	Password:				joes unix password

- SSL/TLS:
	POP: 			use SSL/TLS
	Send (SMTP):	use SSL/TLS

- Advanced:
	SMTP Port:		4650
	POP Port:		9950


### configure hexchat ########################


### SSL, server port 9999->9998 ####
- network list -> add
	servers: 									192.158.5.5/9998
	Use SSL for all servers on this network: 	yes
	Accept invalid SSL certificates:			yes
	Login method: 								default
	Password: 									abc-def-123 		# /etc/ngircd.conf -> [Global] -> Password


### no SSL port 60666 -> 60667 ####
- network list -> add
	servers: 									192.158.5.5/60667
	Use SSL for all servers on this network: 	no
	Accept invalid SSL certificates:			no
	Login method: 								default
	Password: 									abc-def-123 		# /etc/ngircd.conf -> [Global] -> Password

