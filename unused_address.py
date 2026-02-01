import requests
import xmltodict
import urllib3
import getpass
import sys
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

# function to format objects: if multiple, return list of dict, if single return list is singel instance

def normalize_obj(result, type):
    if isinstance(result.get(type).get('entry'), list):
        return result.get(type).get('entry')
    else:
        return [result.get(type).get('entry')]

# get all address objects

addr_result = addr_raw.get('response').get('result') or {} # return empty dict if no address configured
if addr_result:
    all_addrs = normalize_obj(addr_result, 'address')
    defined_addr_names = {item['@name'] for item in all_addrs} # Set of all address names
    print(f"Found {len(defined_addr_names)} address objects.")
else:
    all_addr = []
    defined_addr_names = set()
    print('No address object configured!')
    sys.exit()

# get all address groups

group_result = group_raw.get('response').get('result') or {} # return empty dict if no address-group configured
if group_result:
    all_groups = normalize_obj(group_result, 'address-group')
    defined_group_names = { item['@name'] for item in all_groups} # set of all group names
    print(f"Found {len(defined_group_names)} address groups.")
else:
    all_groups = []
    defined_group_names = set()
    print('No address group configured!')

# structure group map: {'group_name':['member 1', 'member 2']}

# function to format members

def normalize_member(instance, key):
    if isinstance(instance.get(key).get('member'), list):
        return instance.get(key).get('member')
    else:
        return [instance.get(key).get('member')]

group_map={}

if all_groups:    
    for group in all_groups:
        # handles static group type only, if dynamic, members = []
        if group.get('dynamic'):
            members = []
        else:
            members = normalize_member(group, 'static')

        group_map[group['@name']] = members


# ================================================================================================
# ====== format rule dictionaries ================================================================

print('Retrieving configured rules...')

# function to format types of ruleset

def normalize_rule(result, rule_type):
    if isinstance(result.get(rule_type).get('rules').get('entry'), list):
        return result.get(rule_type).get('rules').get('entry')
    else:
        return [result.get(rule_type).get('rules').get('entry')]

# get security rules

rulesec_result = rulesec_raw.get('response').get('result') or {} # return {} if no security rule defined
if rulesec_result:
    all_rulesec = normalize_rule(rulesec_result, 'security')
    print(f"Found {len(all_rulesec)} security rules.")
else:
    all_rulesec = []
    print("No security rule configured!")

# get nat rules

rulenat_result = rulenat_raw.get('response').get('result') or {} # return {} if no nat rule defined
if rulenat_result:
    all_rulenat = normalize_rule(rulenat_result, 'nat')
    print(f"Found {len(all_rulenat)} NAT rules.")
else:
    all_rulenat = []
    print("No NAT rule configured!")


# ===============================================================================================
# =========== Identify used objects in rules ====================================================

print("Processing object usages...")

used_references = set()

# process security rules source and destination

if all_rulesec:
    for rule in all_rulesec:
        used_references.update(normalize_member(rule, 'source'))
        used_references.update(normalize_member(rule, 'destination'))

# function to format translated-address in nat rules

def normalize_trans_addr(instance, type):
    if isinstance(instance.get(type).get('translated-address'), list):
        return instance.get(type).get('translated-address')
    else:
        return [instance.get(type).get('translated-address')]
    
# process nat rules source and destination, source-translation, destination-translation

if all_rulenat:
    for rule in all_rulenat:
        used_references.update(normalize_member(rule, 'source'))
        used_references.update(normalize_member(rule, 'destination'))
        try:
            if rule.get('destination-translation'):
                used_references.update(normalize_trans_addr(rule, 'destination-translation')) 

            if rule.get('source-translation'):
                src_trans = rule.get('source-translation')
                if src_trans.get('static-ip'):
                    used_references.update(normalize_trans_addr(src_trans, 'static-ip'))
                else:
                    for key in src_trans.keys():
                        if src_trans[key].get('translated-address'):
                            used_references.update(normalize_member(src_trans[key], 'translated-address'))
                            

        except KeyError:
            print(f"Error parsing NAT rule {rule['@name']}")
            continue


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


