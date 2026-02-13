import requests
import xmltodict
import urllib3
import getpass
import sys
import re
from pathlib import Path
from datetime import datetime

# disable ssl cert warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================================
# ======== collect device login and generate API key =========================================

dev_ip = input("Enter Device IP address or hostname: ")
username = input("Enter username: ")
password = getpass.getpass("Enter password: ")

# function: generate API key

def get_api_key(ip, user, pw):

    url = fr"https://{ip}/api/"
    params = {
        'type':'keygen',
        'user': user,
        'password': pw
    }

    try:
        response = requests.post(url, params=params, verify=False)
        response.raise_for_status()
        parsed = xmltodict.parse(response.text)
        return parsed['response']['result']['key']
    
    except Exception as e:
        print(f"Failed to generate API key: {e}")
        exit()

print("Generating API key...")
api_key=get_api_key(dev_ip,username,password)


# ========================================================================
# ======= get system info, determine model ===============================

# function to send api request and return xmltodict response

def parse_request( ip, prm):

    url = fr"https://{ip}/api/"
    
    response = requests.get(url, params=prm, verify=False)
    response.raise_for_status()
    parsed = xmltodict.parse(response.text)

    return parsed

# get sys info

print(f"Retrieve system information...")

sys_params = {
    'type':"op",
    'cmd': "<show><system><info></info></system></show>",
    'key':api_key
}

if parse_request(dev_ip, sys_params).get('response',{}).get('@status') == 'success':
    sys_info = parse_request(dev_ip, sys_params).get('response').get('result').get('system')


# ================================================================================================
# ===== get config section of vsys (firewall), device group and shared (panorama) ================

pano_shared_base_path = "/config/shared"
pano_dg_base_path = "/config/devices/entry[@name='localhost.localdomain']/device-group"
fw_vsys_base_path = "/config/devices/entry[@name='localhost.localdomain']/vsys"

# function to format xmltodict objects: if None, return empty list, 
# if single value, wrap in list, if multiple, return list of dict as is

def ensure_list(data):
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return [data]

if sys_info.get('model').lower() == 'panorama':
    dg_params = {
        'type':'config',
        'action':'get',
        'xpath':pano_dg_base_path,
        'key':api_key
    }

    if parse_request(dev_ip, dg_params).get('response').get('result'):
        dg_root = ensure_list(parse_request(dev_ip, dg_params).get('response').get('result').get('device-group').get('entry'))
        for item in dg_root:
            print(f"Device group name: {item.get('@name')}")

    shr_params = {
        'type':'config',
        'action':'get',
        'xpath':pano_shared_base_path,
        'key':api_key
    }

    if parse_request(dev_ip, shr_params).get('response').get('result'):
        shared_root = parse_request(dev_ip, shr_params).get('response').get('result').get('shared')
        for key in shared_root.keys():
            print(f"Shared configuration section: {key}")

else:
    vsys_params = {
        'type':'config',
        'action':'get',
        'xpath':fw_vsys_base_path,
        'key':api_key
    }
    
    if parse_request(dev_ip, vsys_params).get('response').get('result'):
        vsys_root = ensure_list(parse_request(dev_ip, vsys_params).get('response').get('result').get('vsys').get('entry'))
        for item in vsys_root:
            print(f"vsys name: {item.get('@name')}")

