# pa_utils.py

import xmltodict
import requests
import sys
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


def parse_request( ip, params): # send api request and return xmltodict response

    url = fr"https://{ip}/api/"
    
    response = requests.get(url, params=params, verify=False)
    response.raise_for_status()
    parsed = xmltodict.parse(response.text)

    return parsed


def get_dyn_group (ip, grp_name, api_key): # get dynamic group members
     
    url = fr"https://{ip}/api/"

    params = {
         'type': 'op',
         'cmd': f"<show><object><dynamic-address-group><name>{grp_name}</name></dynamic-address-group></object></show>",
         'key': api_key
     }

    try:
        response = requests.post(url, params=params, verify=False)
        response.raise_for_status()
        parsed = xmltodict.parse(response.text)
        return parsed['response']['result']
    
    except Exception as e:
        print(f"Error get group {grp_name}, members ignored: {e}")
        return {}


def ensure_list(data): # ensure data is list type
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return [data]


def gen_obj(type, root): # generate address/group set

    if root.get(type,{}):
        all_obj = ensure_list(root.get(type).get('entry'))
        defined_obj_names = {item['@name'] for item in all_obj} # Set of all address/group names        
    else:
        all_obj = []
        defined_obj_names = set()        
    return all_obj, defined_obj_names


def gen_rule_fw(type, root): # generate rule set on NGFW

    if root.get('rulebase').get(type):
        all_rule = ensure_list(root.get('rulebase').get(type).get('rules').get('entry'))        
    else:
        all_rule = []

    return all_rule


def gen_rule_pano(pre_or_post, type, root): # generate rule set on Panorama

    if root.get(pre_or_post).get(type,{}).get('rules'):
        all_rule=ensure_list(root.get(pre_or_post).get(type).get('rules').get('entry'))        
    else:
        all_rule=[]
        
    return all_rule


def expand_usage(obj_name, group_map, processed_groups, final_used_addresses): # expand groups to address recursively

    if obj_name in processed_groups:
        return
    
    if obj_name in group_map:
        processed_groups.add(obj_name)
        for member in group_map[obj_name]:
            expand_usage(member, group_map, processed_groups, final_used_addresses) # recursive expand

    else:
        final_used_addresses.add(obj_name)


def pa_report(ip, sysname, unused_groups, unused_addresses): # generate report

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
    print(fr"Report saved in \{output_file}")
