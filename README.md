# PoC: Cobalt Strike DNS Beacon Decoder

## Get queries

Create a file called  `queries.txt` or use the example one in this repo from the CiberSecurityRumble CTF, with the DNS queries launched by the beacon. Example:

```Text
api.03dd750ef.19997cf2.wallet.thedarkestside.org
api.13dd750ef.19997cf2.wallet.thedarkestside.org
post.1270.0479c52e5.19997cf2.wallet.thedarkestside.org
post.3657d50d5ae8ba94f41aa8e08b0b338fc7433937e55450fa1743b2baa.4bb997434d5f7eb8af5764d51d5d49a3abdaa2adc52fb9471a0e61e1.7714853c0b76b77c5f9ae4e2c00d5dd33dcaa26eeb429b3d98aa0258.1479c52e5.19997cf2.wallet.thedarkestside.org
post.39acfcd9773cbb3083f55654737ab525e8fde1a8c3928fa6a147d3971.751e83955b70226bbe97f4a96c467e90b9ac0f0e344970c9ce02662d.dd9b02991a44408b84dadbfa7b8ff592e7ef9befe704211b86f24bba.2479c52e5.19997cf2.wallet.thedarkestside.org
```

## Get keys

Use DidierStevens cs-extract-key.py tool to get the keys used by the beacon using its memory dump. If possible specify an example query using the `t` parameter. 

Example: if you have the following queries:
```
post.140.009842910.19997cf2.wallet.thedarkestside.org
post.2942880f933a45cf2d048b0c14917493df0cd10a0de26ea103d0eb1b3.4adf28c63a97deb5cbe4e20b26902d1ef427957323967835f7d18a42.109842910.19997cf2.wallet.thedarkestside.org
post.1debfa06ab4786477.209842910.19997cf2.wallet.thedarkestside.org
```

Execute the tool as:  
```
python3 cs-extract-key.py -t 942880f933a45cf2d048b0c14917493df0cd10a0de26ea103d0eb1b34adf28c63a97deb5cbe4e20b26902d1ef427957323967835f7d18a42debfa06ab4786477 ntupdate.exe_211110_145816.dmp
``` 

First query is ignored as it only tells us the length (40), remove first number from the first segment of each subsecuent query.

Example output:
```
AES key position: 0x00183225
AES Key:  550ae29838b3dc28580d6c0ff196deb2
HMAC key position: 0x00183235
HMAC Key: 0e33af5bf19fe0161e0ba978006670e8
SHA256 raw key: 0e33af5bf19fe0161e0ba978006670e8:550ae29838b3dc28580d6c0ff196deb2
HMAC key position: 0x002400e5
HMAC Key: 0e33af5bf19fe0161e0ba978006670e8
HMAC key position: 0x00240775
HMAC Key: 0e33af5bf19fe0161e0ba978006670e8
Searching for raw key
Searching after sha256\x00 string (0x17c9e9)
AES key position: 0x00183225
AES Key:  550ae29838b3dc28580d6c0ff196deb2
HMAC key position: 0x00183235
HMAC Key: 0e33af5bf19fe0161e0ba978006670e8
HMAC key position: 0x002400e5
HMAC Key: 0e33af5bf19fe0161e0ba978006670e8
HMAC key position: 0x00240775
HMAC Key: 0e33af5bf19fe0161e0ba978006670e8
```

## Compile and run this tool

Requisites: any Java 17 (example: openjdk-17-jdk) and Maven

Compiling: 
```bash
mvn clean package
```

Running tool:
```bash
java -jar target/cs-dns-parser-1.0-SNAPSHOT.jar [aeskey] [hmackey]
```

Example: 
```bash
java -jar target/cs-dns-parser-1.0-SNAPSHOT.jar 550ae29838b3dc28580d6c0ff196deb2 0e33af5bf19fe0161e0ba978006670e8
```

Example output:
```
[WARNING] Unknown query types found: [www, api, cdn, 19997cf2]

>>>>>>> Id: 09842910 >>>>>> 
Type: OUTPUT
Raw data: brightsoul\bvitalik

<<<<<<<<<<<<<<<<<<<

>>>>>>> Id: 736378dc >>>>>> 
Type: TODO
Raw data: ����C:\users\*
D	0	11/10/2021 11:27:45	.
D	0	11/10/2021 11:27:45	..
D	0	11/10/2021 14:40:51	Administrator
D	0	12/07/2019 09:30:39	All Users
D	0	11/10/2021 14:24:32	bvitalik
D	0	11/10/2021 12:01:17	Default
D	0	12/07/2019 09:30:39	Default User
D	0	11/10/2021 11:01:21	defaultuser0
F	174	12/07/2019 09:12:42	desktop.ini
D	0	11/10/2021 11:12:46	Kevin
D	0	11/10/2021 11:11:19	Public

<<<<<<<<<<<<<<<<<<<

>>>>>>> Id: 1b902135 >>>>>> 
Type: BEACON_GETCWD
Raw data: C:\users
<<<<<<<<<<<<<<<<<<<

>>>>>>> Id: 479c52e5 >>>>>> 
Type: OUTPUT
Raw data: 
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

<<<<<<<<<<<<<<<<<<<

WARNING: Invalid HMAC, skipping packet
>>>>>>> Id: 1b6b6338 >>>>>> 
Skipped processing
<<<<<<<<<<<<<<<<<<<

>>>>>>> Id: 2ef72274 >>>>>> 
Type: BEACON_GETCWD
Raw data: C:\users\bvitalik
<<<<<<<<<<<<<<<<<<<

>>>>>>> Id: 50f011be >>>>>> 
Type: OUTPUT
Raw data: pragma solidity ^0.8.3;

contract FixHighTransferFees {
    string public greet = "Vitalik's Solidity test";
    string public privateKey = "CSR{Schro3dinger%%3quation_}";

    //TODO: everything
}
<<<<<<<<<<<<<<<<<<<

>>>>>>> Id: 337c3537 >>>>>> 
Type: OUTPUT
Raw data: WKSTN1

<<<<<<<<<<<<<<<<<<<


Process finished with exit code 0

```

## Query format explanation

The query uses the following format:
```
$configurableprefix.$N$part1.$part2.$partN.$conversationCounter$conversationID.$beaconID.domain
```

### Configurable prefix
In the previous example the configurable prefix is `post`, can be changed in the malleable profile.

```
set beacon               "doc.bc.";
set get_A                "doc.1a.";
set get_AAAA             "doc.4a.";
set get_TXT              "doc.tx.";
set put_metadata         "doc.md.";
set put_output           "doc.po.";
 ```
### N and Parts
Number of subdomains to be parsed as data. In the query `post.1270.0479c52e5.19997cf2.wallet.thedarkestside.org`, it is `1`, and the data would be `270`. Becouse this is the first query of the conversation, the `270` represents the total size of the encrypted data in bytes.

In the next queries:
```
post.3657d50d5ae8ba94f41aa8e08b0b338fc7433937e55450fa1743b2baa.4bb997434d5f7eb8af5764d51d5d49a3abdaa2adc52fb9471a0e61e1.7714853c0b76b77c5f9ae4e2c00d5dd33dcaa26eeb429b3d98aa0258.1479c52e5.19997cf2.wallet.thedarkestside.org
post.39acfcd9773cbb3083f55654737ab525e8fde1a8c3928fa6a147d3971.751e83955b70226bbe97f4a96c467e90b9ac0f0e344970c9ce02662d.dd9b02991a44408b84dadbfa7b8ff592e7ef9befe704211b86f24bba.2479c52e5.19997cf2.wallet.thedarkestside.org
```

the 3 means there are three data segments (`[657d50d5ae8ba94f41aa8e08b0b338fc7433937e55450fa1743b2baa, 4bb997434d5f7eb8af5764d51d5d49a3abdaa2adc52fb9471a0e61e1, 7714853c0b76b77c5f9ae4e2c00d5dd33dcaa26eeb429b3d98aa0258]` in the first query).

After joining all data for conversation `479c52e5` we get a length of `270`, matching the stated previously.


### Conversation Counter and ConversationID
Identify the conversation and the packet order of the queries.
Using the same example as before:
```
post.1270.0479c52e5.19997cf2.wallet.thedarkestside.org
post.3657d50d5ae8ba94f41aa8e08b0b338fc7433937e55450fa1743b2baa.4bb997434d5f7eb8af5764d51d5d49a3abdaa2adc52fb9471a0e61e1.7714853c0b76b77c5f9ae4e2c00d5dd33dcaa26eeb429b3d98aa0258.1479c52e5.19997cf2.wallet.thedarkestside.org
post.39acfcd9773cbb3083f55654737ab525e8fde1a8c3928fa6a147d3971.751e83955b70226bbe97f4a96c467e90b9ac0f0e344970c9ce02662d.dd9b02991a44408b84dadbfa7b8ff592e7ef9befe704211b86f24bba.2479c52e5.19997cf2.wallet.thedarkestside.org
```
ConvesationId is `479c52e5`, and the packets are already ordered (0,1,2).

### BeaconID

Identifies which keys should be used in the team server to decrypt the messages. Keys are transmitted when the beacon sends the metadata petition, encrypted using the teamserver public key. 
Using the same example as before:
```
post.1270.0479c52e5.19997cf2.wallet.thedarkestside.org
post.3657d50d5ae8ba94f41aa8e08b0b338fc7433937e55450fa1743b2baa.4bb997434d5f7eb8af5764d51d5d49a3abdaa2adc52fb9471a0e61e1.7714853c0b76b77c5f9ae4e2c00d5dd33dcaa26eeb429b3d98aa0258.1479c52e5.19997cf2.wallet.thedarkestside.org
post.39acfcd9773cbb3083f55654737ab525e8fde1a8c3928fa6a147d3971.751e83955b70226bbe97f4a96c467e90b9ac0f0e344970c9ce02662d.dd9b02991a44408b84dadbfa7b8ff592e7ef9befe704211b86f24bba.2479c52e5.19997cf2.wallet.thedarkestside.org
```
The beaconId would be: `19997cf2`.

### Domain 
Domain registered by attackers to recieve the DNS queries and answer them. In our example: `.wallet.thedarkestside.org`

## Acknowledgements

@SergioP3rez for the help solving the challenge and @DidierStevens for its Cobalt Strike tools.
