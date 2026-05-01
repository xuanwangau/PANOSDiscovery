# padisrule.py

# This script disable security rule on PA firewall according to rule name list provided

import urllib3
import getpass
import csv
from pathlib import Path

# modules
import pa_utils


# disable ssl cert warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# build rule name list from csv file

base_path = r".\PANOSDiscovery\inv"

file_name = f"rule_list.csv"

inv_csv = Path(base_path)/file_name

rule_list = []

try:
    with open(inv_csv, mode='r', encoding='utf-8-sig') as openCSV:
        reader = csv.DictReader(openCSV)

        for instance in reader:
            rule = instance['Name'].removeprefix('[Disabled]').strip()          
                  
            if rule:
                rule_list.append(rule)
                                
except FileNotFoundError:
    print (f'Error: Could not find inventory file {inv_csv}')
    exit()

# === collect device login and generate API key =====

dev_ip = input("Enter Device IP address or hostname: ")
username = input("Enter username: ")
password = getpass.getpass("Enter password: ")

print("Generating API key...")
api_key = pa_utils.get_api_key(dev_ip,username,password)


# set rule profile group'

element_profile = r'<profile-setting><group><member>default-AV-AS-VP-WF</member></group></profile-setting>'

for rule in rule_list:
    # NGFW xpath for particular rule name
    xpath_rule = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{rule}']"

    # Panorama xpath for shared/pre-rule security rule name
    # xpath_rule = f"/config/shared/pre-rulebase/security/rules/entry[@name='{rule}']"

    # Panorama xpath for device group post-rule security rule name
    # xpath_rule = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='Perth']/post-rulebase/security/rules/entry[@name='{rule}']"

    response_set_profile = pa_utils.set_config(dev_ip,api_key,xpath_rule,element_profile)

    if response_set_profile.get('response').get('@status')=='success':
        print (f"Rule '{rule}' profile is updated. ", end='')
    else:
        print(f"Error updating profile for rule '{rule}'.")

    # append date and admin in description
    # NGFW xpath for rule description
    xpath_desc = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{rule}']/description"

    # Panorama xpath for shared/pre-rule rule description
    # xpath_desc = f"/config/shared/pre-rulebase/security/rules/entry[@name='{rule}']/description"

    # Panorma xpath for device group post-rule rule description
    # xpath_desc = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='Perth']/post-rulebase/security/rules/entry[@name='{rule}']/description"

    response_desc = pa_utils.conf_request(dev_ip, api_key, xpath_desc)
    if description_result:= response_desc.get('response').get('result'):
        rule_description = description_result.get('description')
        new_description = rule_description + '\nUpdate profile setting on 1/05/2026'   

    else:
        new_description = 'Update profile setting on 1/05/2026'

    element_desc = rf'<description>{new_description}</description>'
    response_set_desc = pa_utils.set_config(dev_ip,api_key,xpath_rule,element_desc)

    if response_set_desc.get('response').get('@status')=='success':
        print ('Description is updated.')
    else:
        print(f"Error updating description.")

print ('Task completed. Please commit on firewall.')