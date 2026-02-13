# pacleanup.py

# This script looks for unused address objects and groups
# on Palo Alto firewalls and Panorama

import urllib3
import getpass
import sys

# modules
import pa_utils
import parse_fw
import parse_pano


# disable ssl cert warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# === collect device login and generate API key =====

dev_ip = input("Enter Device IP address or hostname: ")
username = input("Enter username: ")
password = getpass.getpass("Enter password: ")

print("Generating API key...")
api_key = pa_utils.get_api_key(dev_ip,username,password)


# === get system info =======

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


# === retrieve config sections based on sys model, call Pano/NGFW analysis modules ===

# define xpath: pano shared, pano device group and fw vsys
pano_shared_xpath = "/config/shared"
pano_dg_xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group"
fw_vsys_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys"

if sys_info.get('model').lower() == 'panorama':

    print(f"Analyzing Panorama configuration...")

    # get device group config from Panorama
    dg_params = {
        'type':'config',
        'action':'get',
        'xpath':pano_dg_xpath,
        'key':api_key
    }

    dg_root_raw = pa_utils.parse_request(dev_ip, dg_params)

    if dg_root_raw.get('response').get('result'):
        dg_root = pa_utils.ensure_list(dg_root_raw.get('response').get('result').get('device-group').get('entry'))
    else:
        print(f"No device group found on {dev_ip}.")
        dg_root=[]
    
    # get shared object config from Panorama
    shared_params = {
        'type':'config',
        'action':'get',
        'xpath':pano_shared_xpath,
        'key':api_key
    }

    shared_root_raw = pa_utils.parse_request(dev_ip, shared_params)

    if shared_root_raw.get('response').get('result'):
        shared_root = shared_root_raw.get('response').get('result').get('shared')
    else:
        print(f"No shared object found on {dev_ip}.")
        shared_root = {}
    
    # if neither dg_root and shared_root is empty, call Panorama module
    
    if dg_root and shared_root:
        defined_addr_names, defined_group_names, group_map, used_references = parse_pano.parse(dev_ip, dg_root, shared_root, api_key)
    else:
        print(f"No configuration to clean up on {dev_ip}")
        sys.exit()

    # finalize used object and group
    final_used_addresses = set()
    processed_groups = set() # already expanded groups in used_references, also used groups

    for item in used_references:
        pa_utils.expand_usage(item, group_map, processed_groups, final_used_addresses)

    # finalize results and report

    unused_groups = defined_group_names - processed_groups
    unused_addresses = defined_addr_names - final_used_addresses

    pa_utils.pa_report(dev_ip, 'Panorama', unused_groups, unused_addresses)

else: # system is NGFW, get vsys config from firewall
    
    print(f"Analyzing firewall configuration...")

    vsys_params = {
        'type':'config',
        'action':'get',
        'xpath':fw_vsys_xpath,
        'key':api_key
    }

    vsys_root_raw = pa_utils.parse_request(dev_ip, vsys_params)

    if vsys_root_raw.get('response').get('result'):
        vsys_root = pa_utils.ensure_list(vsys_root_raw.get('response').get('result').get('vsys').get('entry'))
 
        for vsys_ins in vsys_root:
            vsys_name = vsys_ins.get('@name')
            print(f"Processing {vsys_name}...")

            # call parse_fw module
            defined_addr_names, defined_group_names, group_map, used_references = parse_fw.parse(dev_ip, vsys_ins, api_key)
            
            # finalize used object and group
            final_used_addresses = set()
            processed_groups = set() # already expanded groups in used_references, also used groups

            for item in used_references:
                pa_utils.expand_usage(item, group_map, processed_groups, final_used_addresses)

            # finalize results and report

            unused_groups = defined_group_names - processed_groups
            unused_addresses = defined_addr_names - final_used_addresses

            pa_utils.pa_report(dev_ip, vsys_name, unused_groups, unused_addresses)


    else:
        print(f"Nothing to clean up on {dev_ip}.")
        sys.exit()

    



