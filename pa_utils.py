# pa_utils.py

import xmltodict
import requests
import sys
import re
from datetime import datetime
from pathlib import Path


def get_api_key(ip, user, pw): # generate API key

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
        print(f"Error generating API key on {ip}: {e}")
        sys.exit()


def conf_request(ip, key, xpath):

    url = fr"https://{ip}/api/"
    params ={
        'type':'config',
        'action': 'get',
        'xpath': xpath,
        'key': key
    }

    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()
    parsed = xmltodict.parse(response.text)
    return parsed

def op_request(ip, key, xpath):

    url = fr"https://{ip}/api/"
    params ={
        'type':'op',
        'cmd': xpath,
        'key': key
    }

    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()
    parsed = xmltodict.parse(response.text)
    return parsed

def root_xpaths():
    pano_shared_xpath = "/config/shared"
    pano_dg_xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group"
    fw_vsys_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys"

    return pano_shared_xpath, pano_dg_xpath, fw_vsys_xpath

def ensure_list(data): # ensure data is list type
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return [data]


def expand_usage(obj_name, group_map, processed_groups, final_used_addresses): # expand groups to address recursively

    if obj_name in processed_groups:
        return
    
    if obj_name in group_map:
        processed_groups.add(obj_name)
        for member in group_map[obj_name]:
            expand_usage(member, group_map, processed_groups, final_used_addresses) # recursive expand

    else:
        final_used_addresses.add(obj_name)


def pa_unused_report(ip, sysname, unused_groups, unused_addresses): # generate report

    # prepare a file to save report
    timestamp = datetime.now().strftime("%m%d_%H%M%S")
    
    p=Path('report')
    if not p.is_dir():
        p.mkdir()

    filename = f"PANOS_{ip}_{sysname}_report_{timestamp}.txt"
    output_file = p / filename

    # write result to file
    with open(output_file, mode='w', encoding='utf-8') as f:
        f.write(f"Analysis report for {ip} {sysname} - Generated on: {datetime.now()}\n\n")

        f.write(f"-"*40 + "\n\n")

        f.write(f"Total unused groups - {len(unused_groups)}:\n\n")
        for group in unused_groups:
            f.write(f"{group}\n")

        f.write(f"\n"+"-"*40 +"\n\n")

        f.write(f"Total unused address objects - {len(unused_addresses)}:\n\n")
        for obj in unused_addresses:
            f.write(f"{obj}\n")

        f.write(f"\n----End of Report----\n")

    print(fr"Found {len(unused_groups)} unused groups and {len(unused_addresses)} unused address objects in {sysname}.")
    print(fr"Report saved in {output_file}")


def update_reverse_map(map, obj):
    addr_types = ['ip-netmask', 'ip-range', 'ip-wildcard', 'fqdn']
    
    for key, value in obj.items():
        if key in addr_types:
            map_key=value.removesuffix('/32')
            if map_key in map:
                map[map_key].append(obj.get('@name'))
            else:
                map[map_key] = [obj.get('@name')]


def pa_dup_report(ip, sysname, map):
    # prepare a file to save report
    timestamp = datetime.now().strftime("%m%d_%H%M%S")
    
    p=Path('report')
    if not p.is_dir():
        p.mkdir()

    filename = f"PANOS_{ip}_{sysname}_report_{timestamp}.txt"
    output_file = p / filename

    # write result to file
    with open(output_file, mode='w', encoding='utf-8') as f:
        f.write(f"Analysis report for {ip} {sysname} - Generated on: {datetime.now()}\n\n")

        f.write(f"-"*40 + "\n\n")

        f.write(f"Found {len(map)} duplicated objects...\n")

        for key, value in map.items():
            f.write (f"\nDuplicate objects: {key}\n")
            for v in value:
                f.write(f"Object name: {v}\n")

        f.write(f"\n----End of Report----\n")

    print(f"Found {len(map)} duplicated objects on {ip} {sysname}.")
    print(f"Report saved in {output_file}")
        

def fqdn_to_ip(fqdn_text):
    # 1. Split the text into blocks by looking for the domain names
    # This assumes domains start at the beginning of a line
    blocks = re.split(r'\n(?=[a-zA-Z0-9])', fqdn_text.strip())

    data_map = {}

    for block in blocks:
        lines = block.strip().split('\n')
        domain = lines[0].strip()
        
        # 2. Extract only IPv4 addresses from the rest of the block
        # Logic: \b boundaries and 4 sets of 1-3 digits
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ipv4_pattern, block)
        
        data_map[domain] = ips

    return data_map

