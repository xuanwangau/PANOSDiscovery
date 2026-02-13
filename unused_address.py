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
# ======== collect login info and generate API key =============================================

fw_ip = input("Enter firewall IP address: ")
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
api_key=get_api_key(fw_ip,username,password)



# ============================================================================================
# ======== use API query to get configuration ================================================

# define xpaths

addr_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
group_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group"
rulesec_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security"
rulenat_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat"

# function: use xpath to get config

def get_config(ip, xpath, key):
    
    base_url = f"https://{ip}/api/"

    #define params
    params = {
        'type': "config",
        'action':'get',
        'key': key,
        'xpath':xpath
    }

    try:
        #send request, ignore cert verification
        response= requests.get(base_url, params=params, verify=False)

        response.raise_for_status()

        return response.text

    except Exception as e:
        print(f"Connection failed for xpath {xpath}: {e}")
        exit()

# get config data, use xmltodict.parse() to turn API response to raw dictionary

print('Retrieving configured objects...')
addr_raw =      xmltodict.parse(get_config(fw_ip, addr_xpath, api_key))
group_raw =     xmltodict.parse(get_config(fw_ip, group_xpath, api_key))
rulesec_raw =   xmltodict.parse(get_config(fw_ip, rulesec_xpath, api_key))
rulenat_raw =   xmltodict.parse(get_config(fw_ip, rulenat_xpath, api_key))



# ==============================================================================================
# ======== format address and group dictionary =================================================

# function to format xmltodict objects: if None, return empty list, 
# if single value, wrap in list, if multiple, return list of dict as is

def ensure_list(data):
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return [data]

# get all address objects

addr_result = addr_raw.get('response').get('result') or {} # return empty dict if no address configured
if addr_result:
    all_addrs = ensure_list(addr_result.get('address').get('entry'))   
    defined_addr_names = {item['@name'] for item in all_addrs} # Set of all address names
    print(f"Found {len(defined_addr_names)} address objects.")
else:
    all_addrs = []
    defined_addr_names = set()
    print('No address object configured!')
    sys.exit()

# get all address groups

group_result = group_raw.get('response').get('result') or {} # return empty dict if no address-group configured
if group_result:
    all_groups = ensure_list(group_result.get('address-group').get('entry'))
    defined_group_names = { item['@name'] for item in all_groups} # set of all group names
    print(f"Found {len(defined_group_names)} address groups.")
else:
    all_groups = []
    defined_group_names = set()
    print('No address group configured!')

# structure group map: {'group_name':['member 1', 'member 2']}

# function to split multiple tags in dynamic group definition

def split_filter(text):
    pattern = r"\s+or\s+"
    result = re.split(pattern, text)
    new_result = []
    for tag in result:
        new_result.append(tag.strip("' "))
    return new_result

group_map={}
group_filters = set()

if all_groups:    
    for group in all_groups:
        
        if group.get('static'):
            members = ensure_list(group.get('static').get('member'))
        else: # must be dynamic group
            filters = split_filter(group.get('dynamic').get('filter'))
            for tag in filters:
                group_filters.update([tag])
                
        group_map[group['@name']] = members



# ================================================================================================
# ====== format rule dictionaries ================================================================

print('Retrieving configured rules...')

# get security rules

rulesec_result = rulesec_raw.get('response').get('result') or {} # return {} if no security rule defined
if rulesec_result:
    all_rulesec = ensure_list(rulesec_result.get('security').get('rules').get('entry'))
    print(f"Found {len(all_rulesec)} security rules.")
else:
    all_rulesec = []
    print("No security rule configured!")

# get nat rules

rulenat_result = rulenat_raw.get('response').get('result') or {} # return {} if no nat rule defined
if rulenat_result:
    all_rulenat = ensure_list(rulenat_result.get('nat').get('rules').get('entry'))
    print(f"Found {len(all_rulenat)} NAT rules.")
else:
    all_rulenat = []
    print("No NAT rule configured!")



# ===============================================================================================
# =========== Identify used objects in configuration ====================================================

print("Processing object usages...")

used_references = set()

# identify objects in security rules source and destination

if all_rulesec:
    for rule in all_rulesec:
        used_references.update(ensure_list(rule.get('source').get('member')))
        used_references.update(ensure_list(rule.get('destination').get('member')))

# identify objects in nat rules source and destination, source-translation, destination-translation

if all_rulenat:
    for rule in all_rulenat:
        used_references.update(ensure_list(rule.get('source').get('member')))
        used_references.update(ensure_list(rule.get('destination').get('member')))
        
        if rule.get('destination-translation'):
            used_references.update(ensure_list(rule.get('destination-translation').get('translated-address'))) 

        if rule.get('source-translation'):
            src_trans = rule.get('source-translation')
            for key, value in src_trans.items():
                if src_trans.get('static-ip'):
                    used_references.update(ensure_list(src_trans.get('static-ip').get('translated-address')))
                else:
                    for key, value in src_trans.items():
                        if isinstance(value, dict) and value.get('translated-address'):
                            used_references.update(ensure_list(value.get('translated-address',{}).get('member')))         

# identify address objects referenced in dynamic groups

for address in all_addrs:
    if address.get('tag'):
        addr_tags = ensure_list(address.get('tag').get('member'))
        for tag in addr_tags:
            if tag in group_filters:                
                used_references.update(ensure_list(address.get('@name')))



# =============================================================================================
# ============ Recursive group to address flattening =============================================

final_used_addresses = set()
processed_groups = set() # already expanded groups in used_references, also used groups

# function to expand groups recursively

def expand_usage(obj_name):

    if obj_name in processed_groups:
        return
    
    if obj_name in group_map:
        processed_groups.add(obj_name)
        for member in group_map[obj_name]:
            expand_usage(member) # recursive expand

    else:
        final_used_addresses.add(obj_name)

for item in used_references:
    expand_usage(item)



# ==============================================================================================
# ========= finalize result and report =========================================================

unused_groups = defined_group_names - processed_groups
unused_addresses = defined_addr_names - final_used_addresses

# prepare a file to save report

timestamp = datetime.now().strftime("%m%d_%H%M%S")

folder='report'
p=Path(folder)
if p.is_dir():
    output_file=Path(fr".\report\PA_firewall_{fw_ip}_unused_object_report_{timestamp}.txt")
else:
    Path(folder).mkdir()
    output_file=Path(fr".\report\PA_firewall_{fw_ip}_unused_object_report_{timestamp}.txt")

# write result to file
with open(output_file, mode='w', encoding='utf-8') as f:
    f.write(f"Analysis report - Generated on: {datetime.now()}\n\n")

    f.write(f"-"*40 + "\n\n")

    f.write(f"Total unused groups - {len(unused_groups)}:\n\n")
    for group in unused_groups:
        f.write(f"{group}\n")

    f.write(f"\n"+"-"*40 +"\n\n")

    f.write(f"Total unused address objects - {len(unused_addresses)}:\n\n")
    for obj in unused_addresses:
        f.write(f"{obj}\n")

    f.write(f"\n----End of Report----\n")

print(fr"Report saved in \{output_file}")
print(fr"Total {len(unused_groups)} unused groups and {len(unused_addresses)} unused address objects.")


