
### stop/disable services

/etc/init.d/postfix stop
/etc/init.d/postfix disable

/etc/init.d/dovecot stop
/etc/init.d/dovecot disable

/etc/init.d/ngircd stop
/etc/init.d/ngircd disable

/etc/init.d/umurmur stop
/etc/init.d/umurmur disable

/etc/init.d/znc stop
/etc/init.d/znc disable


############################# Yggdrasil Network #####################################################
# a new PublicKey/PrivateKey should be generated and configured in /etc/config/yggdrasil

## add peers

nano /etc/config/yggdrasil

config peer
	option uri 'tcp://123.123.123.123:55551'

# multicast for auto connecting clients in LAN
config multicast_interface
	option beacon '0'
	option listen '1'
	option port '55789'
	option regex '.*'



service yggdrasil restart


yggdrasilctl getPeers

logread




############################# I2P Network #####################################################

### Server Tunnels i2p addresses should be provided 


## go to webconsole:  http://192.168.5.5:7070/  
# user = i2pd
# pass = TF5f-DFea2-gYvbJHv


# i2pd webconsole

# Server Tunnels:
# SERVER-IRC-SSL ⇒ evp6c43hjnvz5d7gzbmrlrrdxrx5vcoafrpw5kzimpctd4syv5aa.b32.i2p:9999
# SERVER-IRC ⇒ lolc6ox3j4bbtg3kyxcrqisasx6m3d4zauzgrnmki6g5ckta6ina.b32.i2p:60666
# SERVER-POP3S ⇒ w5f6gfo5oqw4mvsscvuvamgpgfdzazrnpnth44ksezgdc4kiixaq.b32.i2p:995
# SERVER-SMPTS ⇒ xukvtb6m54y45lmzpgemlk2ihosr7swukyfx7x67s4on3ewdwa7q.b32.i2p:465



### now configure client tunnels ###


nano /etc/i2pd/tunnels.conf


[CLIENT-IRC-SSL-RPIROUTER]
type = client
address = 192.168.5.5
port = 9998
destination = evp6c43hjnvz5d7gzbmrlrrdxrx5vcoafrpw5kzimpctd4syv5aa.b32.i2p
destinationport = 9999
keys = client-irc-ssl-rpirouter.dat

[CLIENT-IRC-NOSSL-RPIROUTER]
type = client
address = 192.168.5.5
port = 60667
destination = lolc6ox3j4bbtg3kyxcrqisasx6m3d4zauzgrnmki6g5ckta6ina.b32.i2p
destinationport = 60666
keys = client-irc-nossl-rpirouter.dat

[CLIENT-POP3S-RPIROUTER]
type = client
address = 192.168.5.5
port = 9950
destination = w5f6gfo5oqw4mvsscvuvamgpgfdzazrnpnth44ksezgdc4kiixaq.b32.i2p
destinationport = 995
keys = client-pop3s-rpirouter.dat

[CLIENT-SMTPS-RPIROUTER]
type = client
address = 192.168.5.5
port = 4650
destination = xukvtb6m54y45lmzpgemlk2ihosr7swukyfx7x67s4on3ewdwa7q.b32.i2p
destinationport = 465
keys = client-smtps-rpirouter.dat



/etc/init.d/i2pd stop
/etc/init.d/i2pd start_service


# check connections
lsof -i

netstat -ltp | grep i2pd
tcp        0      0 rpirouter2.lan:60667    0.0.0.0:*               LISTEN      8644/i2pd
tcp        0      0 rpirouter2.lan:4444     0.0.0.0:*               LISTEN      8644/i2pd
tcp        0      0 rpirouter2.lan:9950     0.0.0.0:*               LISTEN      8644/i2pd
tcp        0      0 rpirouter2.lan:7070     0.0.0.0:*               LISTEN      8644/i2pd
tcp        0      0 rpirouter2.lan:4447     0.0.0.0:*               LISTEN      8644/i2pd
tcp        0      0 0.0.0.0:36865           0.0.0.0:*               LISTEN      8644/i2pd
tcp        0      0 rpirouter2.lan:7656     0.0.0.0:*               LISTEN      8644/i2pd
tcp        0      0 rpirouter2.lan:4650     0.0.0.0:*               LISTEN      8644/i2pd
tcp        0      0 rpirouter2.lan:6668     0.0.0.0:*               LISTEN      8644/i2pd
tcp        0      0 rpirouter2.lan:9998     0.0.0.0:*               LISTEN      8644/i2pd
tcp        0      0 :::36865                :::*                    LISTEN      8644/i2pd


## services on remote rpirouter are now accessable via i2p network on ports:
- IRC SSL: 		9998
- IRC noSSL: 	60667
- POP3 SSL: 	9950
- SMTP SSL: 	4650

# on local rpirouter with address 192.158.5.5

