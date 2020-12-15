import sys
import requests
import time
import json
import argparse
from collections import defaultdict

def queryFingerbank(file_dic,key,proxy):
    """query Fingerbank API for the DHCP FPs provided in file_dic with the API key"""

    headers = {'Content-type': 'application/json'}
    url = 'https://api.fingerbank.org/api/v2/combinations/interrogate?key='+key


    resp_dic = defaultdict(list)
    f = open("dhcp-db-FBQ", "w")

    if "https" in proxy:
        proxies={"https" : proxy}
    else:
        proxies={"http" : proxy}

    for hash, fp in file_dic.items():
        data = '{"dhcp_fingerprint":"' + fp +'"}'
        resp_dic[hash].append(fp)
        try:
            # Try to get the data and json.load it 3 times, then give up
            tries = 3
            while tries >= 0:
                try:
                    if proxy == "not_set":
                        response = requests.post(url, headers=headers, data=data)
                    else:
                        response = requests.post(url, headers=headers, data=data, proxies=proxies)

                    json_response = json.loads(response.text)

                    if "device_name" not in json_response:
                        resp_dic[hash].append("Unknown in FB")
                        resp_dic[hash].append(0)

                    else:
                        resp_dic[hash].append(json_response["device_name"])
                        resp_dic[hash].append(json_response["score"])

                    print '\n'+hash,
                    f.write(hash +'\t')

                    for x in [0,1,2]:
                        s = str(resp_dic[hash][x]).strip('[]')
                        print '\t'+ s,
                        if isinstance(s, unicode):
                            f.write(s.encode("utf-8") + '\t')
                        else:
                            f.write(s + '\t')
                    f.write('\n')
                    break

                except:
                    print "Exception occured retrying"
                    if tries == 0:
                        # If we keep failing, raise the exception for the outer exception
                        # handling to deal with
                        raise
                    else:
                        # Wait a few seconds before retrying and hope the problem goes away
                        time.sleep(3)
                        tries -= 1
                        continue

        except:
            print ("Oops! an exception have occured", sys.exc_info()[0])
            raise
        #finally:
    f.close()

def main():
    """Intake arguments from the user (file & API key) and output the dhcp-db-extend and dhcp-db-FBQ of the DHCP FP in FingerBank."""

    desc = "A python script for quering the Fingerbank API for unknown DHCP Fingerprints"
    parser = argparse.ArgumentParser(description=(desc))

    help_text = "The api key for the FingerBank access"
    parser.add_argument("-k", "--api_key", required=True, type=str, help=help_text)

    input_file_group = parser.add_mutually_exclusive_group(required=True)

    help_text = "File containing unknown DHCP Hashes and DHCP FP"
    input_file_group.add_argument("-f", "--file_unknown_hashes", type=str, help=help_text)

    help_text = "JSON file (output of kyd.py) containing unknown DHCP hashes and DHCP FP"
    input_file_group.add_argument("-j", "--json_unknown_hashes", type=str, help=help_text)

    help_text = "Proxy support for the isolated servers, give the proxy url as arg ex: http://ip:port"
    parser.add_argument("-p", "--proxy", required=False, type=str, help=help_text)

    args = parser.parse_args()
    api_key = args.api_key

    file_dic = {}

    if args.file_unknown_hashes:
        with open(args.file_unknown_hashes) as f:
        #next(f)
            for line in f:
                (key, val) = line.split()
                file_dic[key] = val
        f.close()
    elif args.json_unknown_hashes:
        with open(args.json_unknown_hashes) as f:
            json_data = f.read()
            raw_dic = json.loads(json_data)
        for e in raw_dic:
            file_dic[e['DHCPFP_hash']] = e['DHCPFP']

    if args.proxy:
        proxy = args.proxy
    else:
        proxy = "not_set"

    queryFingerbank(file_dic,api_key,proxy)

if __name__ == "__main__":
    main()
