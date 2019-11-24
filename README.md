# kyd - know your devices, a method for profiling devices using dhcp
KYD is a method for creating the DHCP fingerprints/hashes of the clients internal to an organization that connect to the organization's DHCP servers.
KYD technique is based on the ability for the NSM to see the internal network traffic, specifically DHCP traffic.
The fingerprinting is done on the unique sequence of options presented by the DHCP client in the 'parameters list' option of the DHCP request.

DHCP fingerprinting has been around for a while now and have been talked about in past.
The concept is very simple and efficiently explained by this infloblox presentation avialable online: https://archive.nanog.org/sites/default/files/tues.general.coffeen.fingerprinting.6.pdf

The organizations with BYOD (Bring Your Own Device) policies can benefit from this method and can profile the usage of different kind of devices that connect to their network.
The Fingerbank.org used to maintain a GitHub account of the DHCP fingerprints but due to the increasing size of the database they moved to an API based method of providing access to the fingerprints to the users.
  
This method allows you to interrogate a local dhcp-db.txt file (in this repo) with different DHCP fingerprints and obtain the device information that matches that fingerprint. It also provides a confidence level (score) on a scale of 100 for the patterns provided.

The database of fingerprints - dhcp-db.txt, provided with this package, is a continuos effort and developed over time, by quering the Fingerbank's api with the DHCP fingerprints seen on the network to get the device information associated and the score. Also, some of the fingerprints included are collected from the network and back traced to the registered device to get the information regarding the system that are not found in the Fingerbank's database.

The python script used to query Fingerbank's database is also provided, to build your own local database of the fingerprints seen on your network which are unknown to the dhcp-db.txt. More details on the usage follows in the Build Your Own KYD Database section.

## Usage & installation:

### How to use it in Zeek?

 The scripts are available as a Zeek package, hence you can install by using the Zeek Package Manager and this one simple command:
 
 `$ zkg install kyd`
 
 OR download the files to zeek/share/zeek/site/kyd and add this line to your local.zeek script:
 
 `@load ./kyd`

There is an redef option in the script : `dbfile` that needs to be updated to the path where you store dhcp-db.txt db file provided with this package.
It is currently set to `/usr/local/bro/feeds/dhcp-db.txt` , change it to h=whatever location you want to copy dhcp-db.txt file.

After loading the scripts, restart your Zeek cluster and a new file `dhcpfp.log` should start getting genarated logging the device information and DHCP hashes/fingerprints seen in the traffic.

### How to use it on PCAP?
The python script - kyd.py provided in the python folder of this repository takes pcap file as an input and prints out the DHCP hash and the DHCP fingerprint. It is a python wrapper around kyd logic in order to produce valid DHCP fingerprints from an input PCAP file.
Following shows an example of reading pcap file and generating DHCP hash using kyd.py (it requires python package - dpkt to be installed first) :
```
$ pip install dpkt
$ python kyd.py --json file.pcap

[
    {
        "DHCPFP": "1,28,3,6,15,35,66,150", 
        "DHCPFP_hash": "ba8acc3498ccc44294fe9fc47f3f7022", 
        "destination_ip": "192.168.55.12", 
        "destination_port": 67, 
        "source_ip": "192.168.55.3", 
        "source_port": 68, 
        "timestamp": 1566404777.404548
    }, 
    {
        "DHCPFP": "1,3,6,15,31,33,43,44,46,47,119,121,249,252", 
        "DHCPFP_hash": "86eed4bae372606b6c52393465543d87", 
        "destination_ip": "192.168.55.12", 
        "destination_port": 67, 
        "source_ip": "192.168.55.6", 
        "source_port": 67, 
        "timestamp": 1566404777.523932
    }
]
```
## Build Your Own KYD database (Fingerbank integration)

Once you load the scripts for DHCP FP, Zeek will start generating `dhcpfp.log` which will contain the DHCP fingerprints seen on your network. OR if you have a PCAP , run `kyd.py` and it will generate the DHCP fingerprints.

You can get the unknown DHCP fingerprints and hashes seen in a day (or whatever time period you want to choose) on your network and run those through the python script - `dhcp-unknown.py`

If the matches are found in the FingerBank's database, you can then add those unknown hashes to the `dhcp-db.txt`, the input framework will automatically refresh the table contents when it detects a change to the input file - dhcp-db.txt

### Pre-requisite for using dhcp-unknown.py

`dhcp-unknown.py` - Queries the Fingerbank's api for a list of unknown DHCP fingerprints and returns the response from the api.fingerbank.org as output in seperate files.

To query and use the Fingerbank's API, you need to get an `API key`, it is free and can get by logging into https://api.fingerbank.org/ with your github account.
Once logged in you can go your profile by clicking on your user account at the top right corner.  
In the profile, it lists the API key and per minute API limit, which is 300/hr and 1,000,000/month. These limits are far more than enough to query the API database, as we hardly see 30-40 uniq DHCP hashes/fingerprints per day that are unknown in our network.

### Using dhcp-unknown.py

I/Ps: 
```
-k <required: api key>
-f <required: File containing two columns(DHCP-hashes & DHCP FPs) separated by space with no new lines at the end>
-p <optional: proxy url>
```
        
O/Ps: 
```
dhcp-db-FBQ : Tab separated txt file to Update/append to the dhcp-db.txt , to log DHCP fingerprints local to your network
Also prints out the responses on the standard output
```

Getting the inputs:
```
-k : Api-key: https://api.fingerbank.org/users/register
-f : via kyd.py in case of pcap, or via zeek dhcpfp.log
```

Usage Example:
```
$ zcat /usr/local/zeek/2.6.2/logs/2019-08-28/dhcpfp.*.gz | grep "Unknown" | awk -F'\t' '{print $9,$10}' | sort | uniq > unknown-hash

$ cat unknown-hash

7fa15642c7d22c817a6a614068a85afa 3,51,1,15,6,66,67,120,44,43,150,12,7,42
9b1ee9aff3eb29371efe446ac89e5c3f 1,3,6,15,26,28,51,58,59,43

$ python dhcp_unknown.py -k c21b54exxxxxxxxxxxxxxxc1786 -f unknown_hash -p https://192.168.0.1:4100

7fa15642c7d22c817a6a614068a85afa   3,51,1,15,6,66,67,120,44,43,150,12,7,42   Switch and Wireless Controller/Juniper Switches   73
9b1ee9aff3eb29371efe446ac89e5c3f   1,3,6,15,26,28,51,58,59,43    Operating System/Google OS/Android OS   87
```

## Contribute!
Because sharing is caring :) 
When you run `dhcp_unknown.py`, it will generate `dhcp-db-FBQ` that you can contribute to the database text file provided in this repo - `dhcp-db.txt`.
It will help others to make use of the already queried DHCP fingerprint and device information that will then be available to them locally.

