# pafinddup.py

# look for duplicated address objects on Panorama and NGFW

import urllib3
import getpass
import sys

# local modules
import pa_utils

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

sys_info_xpath = "<show><system><info></info></system></show>"
sys_info_resp = pa_utils.op_request(dev_ip, api_key, sys_info_xpath)

if sys_info_resp.get('response',{}).get('@status') == 'success':
    sys_info = sys_info_resp.get('response').get('result').get('system')

else:
    print("Error parsing system info.")
    sys.exit()


# process address objects based on system model

# define xpath: pano shared, pano device group and fw vsys

pano_shared_xpath, pano_dg_xpath, fw_vsys_xpath = pa_utils.root_xpaths()

if sys_info.get('model').lower() == 'panorama':

    print(f"Analyzing Panorama configuration...")

    # get device group config from Panorama

    dg_root_response = pa_utils.conf_request(dev_ip, api_key, pano_dg_xpath) 

    if dg_root_raw:=dg_root_response.get('response',{}).get('result'):
        dg_root = pa_utils.ensure_list(dg_root_raw.get('device-group').get('entry'))
    else:
        print(f"No device group found on {dev_ip}.")
        dg_root=[]
    
    # get shared object config from Panorama

    shared_root_response = pa_utils.conf_request(dev_ip, api_key, pano_shared_xpath)
    
    if shared_root_raw:=shared_root_response.get('response',{}).get('result'):
        shared_root = shared_root_raw.get('shared')
    else:
        print(f"No shared object found on {dev_ip}.")
        shared_root = {}
    
    # if neither dg_root and shared_root is empty, process panorama objects
    
    if dg_root and shared_root:
        reverse_addr_map = {}

        if shared_root.get('address',{}):
            shared_addrs = pa_utils.ensure_list(shared_root.get('address').get('entry'))
            
        for obj in shared_addrs:
            pa_utils.update_reverse_map(reverse_addr_map, obj)
            
        for dg in dg_root:     

            if dg.get('address',{}):
                dg_addrs = pa_utils.ensure_list(dg.get('address').get('entry'))

            for obj in dg_addrs:
                pa_utils.update_reverse_map(reverse_addr_map, obj)

        dup_addr_map ={}
        for key, value in reverse_addr_map.items():
            if len(value)> 1:
                dup_addr_map[key]= reverse_addr_map[key]
        
        pa_utils.pa_dup_report(dev_ip, 'Panorama', dup_addr_map)
                

    else:
        print(f"No address object defined on {dev_ip}")
        sys.exit()

else: # system is NGFW, get vsys config from firewall
    
    vsys_root_resp = pa_utils.conf_request(dev_ip, api_key, fw_vsys_xpath)

    if vsys_root_raw:= vsys_root_resp.get('response').get('result'):
        vsys_root = pa_utils.ensure_list(vsys_root_raw.get('vsys').get('entry'))
 
        for vsys_ins in vsys_root:
            vsys_name = vsys_ins.get('@name')
            print(f"Analyzing firewall {vsys_name} configuration...")

            reverse_addr_map = {}

            if vsys_ins.get('address',{}):
                vsys_addrs = pa_utils.ensure_list(vsys_ins.get('address').get('entry'))                

            for obj in vsys_addrs:
                pa_utils.update_reverse_map(reverse_addr_map, obj)

            dup_addr_map ={}
            for key, value in reverse_addr_map.items():
                if len(value)> 1:
                    dup_addr_map[key]= reverse_addr_map[key]

            pa_utils.pa_dup_report(dev_ip, 'firewall '+ vsys_name, dup_addr_map)
        
    else:
        print(f"Nothing to clean up on {dev_ip}.")
        sys.exit()