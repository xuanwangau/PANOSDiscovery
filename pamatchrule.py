# parulematch.py

# This script looks for all possible matching rules based on source and destination ip address provided. 
# Any other match condition such like source and destination ports is not checked

import urllib3
import getpass
import sys

# local modules
import pa_utils
import parse_fw
import parse_pano

# disable ssl cert warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# collect login, determin platform

dev_ip = input("Enter IP address or hostname of the firewall to test rule match: ")
username = input("Enter username: ")
password = getpass.getpass("Enter password: ")

while True:

    print("Generating API key...")
    api_key = pa_utils.get_api_key(dev_ip,username,password)

    # get system info
    print(f"Retrieve system information...")

    sys_params = {
        'type':"op",
        'cmd': "<show><system><info></info></system></show>",
        'key':api_key
    }

    sys_info_raw = pa_utils.parse_request(dev_ip, sys_params)

    if sys_info_raw.get('response',{}).get('@status') == 'success':
        sys_info = sys_info_raw.get('response').get('result').get('system')

    else:
        print("Error parsing system info.")
        sys.exit()
    
    if sys_info.get('model').lower() == 'panorama':
        dev_ip = input(f"Rule match should be performed on a firewall instead of Panorama '{dev_ip}'. \
              \nProvide an IP address or hostname of a firewall to start:")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
    else:
        fw_ip, fw_key = dev_ip, api_key

        mgd_params ={
            'type':'config',
            'action':'get',
            'xpath':"/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/panorama",
            'key':fw_key
        }

        mgd_response = pa_utils.parse_request(fw_ip, mgd_params)
        if mgd_raw := mgd_response.get('response').get('result',{}):
            if pano_ip := mgd_raw.get('panorama').get('local-panorama',{}).get('panorama-server'):
                print(f"This firewall is managed by Panorama {pano_ip}.")
                pano_un = input ("Enter Panorama username:")
                pano_pw = getpass.getpass("Enter password:")

                print(f"Generating API key of Panorama {pano_ip} ...")
                pano_key = pa_utils.get_api_key(pano_ip,pano_un,pano_pw)
            else:
                pano_ip='' # Panorama not available or cloud
        else:
            pano_ip='' # standalone firewall
        break

# define xpath: pano shared, pano device group and fw vsys
pano_shared_xpath = "/config/shared"
pano_dg_xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group"
fw_vsys_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys"

if not pano_ip: # standalone firewall
    
    # get vsys root
    print(f"Analyzing firewall configuration...")

    vsys_params = {
        'type':'config',
        'action':'get',
        'xpath':fw_vsys_xpath,
        'key':fw_key
    }

    vsys_root_raw = pa_utils.parse_request(fw_ip, vsys_params)

    if vsys_root_raw.get('response').get('result'):       
        vsys_root = pa_utils.ensure_list(vsys_root_raw.get('response').get('result').get('vsys').get('entry'))

        all_address, all_addr_grp, all_secrule = parse_fw.fw_map(vsys_root)

    else:
        print(f"No vsys found on firewall {fw_ip}.")
        sys.exit()
    
else: # fw managed by Panorama
    print(f"panorama ip: {pano_ip}")
    # from fw rule hit api, get all active rules
    # use all active rules as reference to retrieve rule details from Panorama



# call address to IP address function
# for each rule, source and destination, if contains group, flatten group to address set
# for each address in the set, check given ip address, if match collect the rule
# report all collected rules

for addr in all_address:
    print(f"Address object: {addr}")
for addr_grp in all_addr_grp:
    print(f"Group: {addr_grp}")
for rule in all_secrule:
    print(f"Security rule: {rule}")