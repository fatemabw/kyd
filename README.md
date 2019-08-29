# kyd - know your devices, a method for profiling devices using dhcp
KYD is a method for creating the DHCP fingerprints/hashes of the clients internal to an organization that connect to the organization's DHCP servers.
KYD technique is based on the ability for the NSM to see the internal network traffic, specifically DHCP traffic.
The fingerprinting is done on the unique sequence of options presented by the DHCP client in the 'parameters list' option of the DHCP request.

DHCP fingerprinting has been around for a while now and have been talked about in past.
The concept is very simple and efficiently explained by this infloblox presentation avialable online: https://archive.nanog.org/sites/default/files/tues.general.coffeen.fingerprinting.6.pdf

The organizations with BYOD (Bring Your Own Device) policies can benefit from this method and can profile the usage of different kind of devices that connect to their network.
The Fingerbank.org used to maintain a GitHub account of the DHCP fingerprints but due to the increasing size of the database they moved to an API based method of providing access to the fingerprints to the users.
  
This method allows you to interrogate a local dhcp-db.txt file (in this repo) with different DHCP fingerprints and obtain the device information that matches that fingerprint. It also provides a confidence level (score) on a scale of 100 for the patterns provided.

The database of fingerprints - dhcp-db.txt, provided with this package, is developed over time, by quering the Fingerbank's api with the DHCP fingerprints seen on the network to get the device associated and the score.
The python script used to query Fingerbank's database is also provided, to build your own local database of the fingerprints seen on your network which are unknown to the dhcp-db.txt. More details on the usage follows in the Usage section.

## Usage & installation:

### How to use it in Zeek?
There are two scripts that you would need to load in your local.bro file:
 
 `dhcp-db.bro` (containing the DHCP hash and DHCP device info)
 
 `dhcp-fp.bro` (The script that uses dhcp-db.bro for matching the dhcp fingerprints and generates a new log file in your zeek logs folder named: `dhcpfp.log`)

 The scripts are available as a Zeek package, hence you can install by using the Bro Package Manager and this one simple command:
 
 `$ zkg install kyd`
 
 OR download the files to bro/share/bro/site/kyd and add this line to your local.bro script:
 
 `@load ./kyd`

After loading the scripts, restart your zeek cluster and a new file `dhcpfp.log` should start getting genarated logging the device information and DHCP hashes/fingerprints seen in the traffic.

## Build Your Own KYD database (Fingerbank integration)

Once you load the scripts for DHCP FP, Zeek will start generating `dhcpfp.log` which will containg the DHCP fingerprints seen on your network.
For the ones that are not in the local `dhcp-db.bro` database file, will be logged as "Unknown".
You can get the unknown DHCP fingerprints and hashes seen in a day (or whatever time period you want to chose) on your network and run those through the python script - `dhcp-unknown.py`

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
dhcp-db-extend : file with bro formatted entries to append to dhcp-db.bro
dhcp-db-FBQ : Tab separated txt file to add to the dhcp-db.txt , to log DHCP fingerprints local to your network
Also prints out the responses on the standard output
```

Getting the inputs:
```
-k : Api-key: https://api.fingerbank.org/users/register
-f : $ zcat /usr/local/bro/2.6.2/logs/2019-08-28/dhcpfp.*.gz | grep "Unknown" | awk -F'\t' '{print $9,$10}' | sort | uniq > unknown-hash
```

Usage Example:
```
$ zcat /usr/local/bro/2.6.2/logs/2019-08-28/dhcpfp.*.gz | grep "Unknown" | awk -F'\t' '{print $9,$10}' | sort | uniq > unknown-hash

$ cat unknown-hash

7fa15642c7d22c817a6a614068a85afa 3,51,1,15,6,66,67,120,44,43,150,12,7,42
9b1ee9aff3eb29371efe446ac89e5c3f 1,3,6,15,26,28,51,58,59,43
ccfe2db9ed5c1e1233e85f2b577d05df 1,2,3,6,15,26,28,88,44,45,46,47,70,69,78,79,120

$ python dhcp_unknown.py -k c21b54e80cbf10147f9a960e38f8b9aea1f3a786 -f unknown_hash -p https://192.168.0.1:4100

7fa15642c7d22c817a6a614068a85afa   3,51,1,15,6,66,67,120,44,43,150,12,7,42   Switch and Wireless Controller/Juniper Switches   73
9b1ee9aff3eb29371efe446ac89e5c3f   1,3,6,15,26,28,51,58,59,43    Operating System/Google OS/Android OS   87
ccfe2db9ed5c1e1233e85f2b577d05df   1,2,3,6,15,26,28,88,44,45,46,47,70,69,78,79,120      Printer or Scanner/Xerox Printer   73
```

## Contribute!
Because sharing is caring :) 
When you run `dhcp_unknown.py`, it will generate `dhcp-db-FBQ` that you can contribute to the database text file provided in this repo - `dhcp-db.txt`.
It will help others to make use of the already queried DHCP fingerprint and device information that will then be available to them locally.

## Coming Soon...

A general method (most probably a python script) to genarate DHCP hashes from the DHCP fingerprints that can be extracted from any pcap captures available that has captured DHCP conversations,
So that this can be integrated with other sniffing NSMs/IDSs for doing device classification using dhcp-db.txt database or directly quering Fingerbanks API using `dhcp-unknown.py`.
