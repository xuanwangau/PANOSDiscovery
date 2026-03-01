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
import pa_ipformat

# disable ssl cert warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# collect login, determin platform

dev_ip = input("Enter IP address or hostname of the firewall to test rule match: ")
username = input("Enter username: ")
password = getpass.getpass("Enter password: ")

while True:
    
    api_key = pa_utils.get_api_key(dev_ip,username,password)

    # get system info
    print(f"Retrieve system information...")

    sys_info_xpath = "<show><system><info></info></system></show>"
    sys_info_resp = pa_utils.op_request(dev_ip, api_key, sys_info_xpath)

    if sys_info_resp.get('response',{}).get('@status') == 'success':
        sys_info = sys_info_resp.get('response').get('result').get('system')

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

        mgd_xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/panorama"
        mgd_response = pa_utils.conf_request(fw_ip, fw_key, mgd_xpath)

        if mgd_raw := mgd_response.get('response').get('result',{}):
            if pano_ins := mgd_raw.get('panorama').get('local-panorama'):
                pano_ip = pano_ins.get('panorama-server')
                print(f"This firewall is managed by Panorama {pano_ip}.")
                pano_un = input ("Enter Panorama username:")
                pano_pw = getpass.getpass("Enter password:")
                
                pano_key = pa_utils.get_api_key(pano_ip,pano_un,pano_pw)
            else:
                pano_ip='' # Panorama not available or cloud
        else:
            pano_ip='' # standalone firewall
        break

# define xpath: pano shared, pano device group and fw vsys
pano_shared_xpath, pano_dg_xpath, fw_vsys_xpath = pa_utils.root_xpaths()

# get address map, group map, and rule map from firewall local config
print(f"Analyzing firewall configuration...")

vsys_root_resp = pa_utils.conf_request(fw_ip, fw_key, fw_vsys_xpath)

if vsys_root_raw:= vsys_root_resp.get('response').get('result'):       
    vsys_root = pa_utils.ensure_list(vsys_root_raw.get('vsys').get('entry'))

    all_address, all_addr_grp, all_secrule = parse_fw.fw_map(vsys_root)

else:
    print(f"No vsys found on firewall {fw_ip}.")
    sys.exit()
    
if pano_ip: # firewall managed by Panorama
    serial=sys_info.get('serial')

    print("Analyzing Panorama configuration...")

    #get address map, group map, and fule rule map from Panorama
    shared_root_resp = pa_utils.conf_request(pano_ip, pano_key, pano_shared_xpath)

    if shared_root_raw:=shared_root_resp.get('response').get('result'):
        shared_root = shared_root_raw.get('shared')
    
    dg_root_resp = pa_utils.conf_request(pano_ip, pano_key, pano_dg_xpath)

    if dg_root_raw:= dg_root_resp.get('response').get('result'):
        dg_root = pa_utils.ensure_list(dg_root_raw.get('device-group').get('entry'))

    pano_address, pano_addr_grp, pano_secrule = parse_pano.pano_map(shared_root, dg_root, serial)

    all_address = all_address + pano_address
    all_addr_grp = all_addr_grp + pano_addr_grp
    all_secrule = all_secrule + pano_secrule

# creat fqdn map
fqdn_xpath = '<show><dns-proxy><fqdn><all></all></fqdn></dns-proxy></show>'
fqdn_resp = pa_utils.op_request(fw_ip, fw_key, fqdn_xpath)
fqdn_map = pa_utils.fqdn_map(fqdn_resp.get('response').get('result',''))

for name, ips in fqdn_map.items():
    fqdn_map[name] = [ pa_ipformat.convert_to_ipset(ip) for ip in ips]

# format all_address map, exclude 'ip-wildcard' which will be treated seperately
address_map={}

for address in all_address:
    if address_string:= address.get('ip-netmask',{}):
        address['ipset'] = pa_utils.ensure_list(pa_ipformat.convert_to_ipset(address_string))        
    elif address_string:= address.get('ip-range',{}):
        address['ipset'] = pa_utils.ensure_list(pa_ipformat.convert_to_ipset(address_string))        
    elif address_string:= address.get('fqdn',{}):
        address['ipset'] = fqdn_map.get(address_string,[])
    
    address_map[address.get('@name')] = address

# create group to address map
group_map = {}
if all_addr_grp:
    group_map = pa_utils.group_address_mapping(fw_ip,fw_key,all_addr_grp)

# format rule map
# for each rule in secrule: get source and destination member and flatten member set

for rule in all_secrule:
    src_or_dst = ['source', 'destination']
    for sd in src_or_dst:        
        sd_members = pa_utils.ensure_list(rule.get(sd).get('member'))
        processed_groups = set()
        member_addrs= set()

        if 'any' in sd_members:
            member_addrs.add('any')
        else:
            for addr in sd_members:
                if addr in address_map or addr in group_map:
                    pa_utils.expand_usage(addr, group_map, processed_groups, member_addrs)
                else: # TBC: match EDL, match direct input address in rule
                    member_addrs.add('any')            
                # else: # bug fix for '@dirtyId' in api response when configd is hung
                #     name = addr.get('#text','')
                #     pa_utils.expand_usage(name, group_map, processed_groups, member_addrs)

        rule[f"{sd}-address-set"] = member_addrs

# rule matching
while True:
    src_ip = input("Enter source ip address:")
    if pa_ipformat.is_valid_ip(src_ip):
        break
    else:
        print('Invalid IP address')

while True:   
    dst_ip = input("Enter destination ip address:")
    if pa_ipformat.is_valid_ip(dst_ip):
        break
    else:
        print('Invalid IP address')

matching_rule = [] # matching rule collection

for rule in all_secrule:    
    src_match = False
    dst_match = False

    for addr in rule.get('source-address-set'):
        src_match = pa_utils.rule_address_match(addr, address_map, src_ip)
        if src_match:
            break

    for addr in rule.get('destination-address-set'):
        dst_match = pa_utils.rule_address_match(addr, address_map, dst_ip)
        if dst_match:
            break

    if src_match and dst_match:
        matching_rule.append(rule.get('@name'))

for name in matching_rule:
    print(f"Possible matching rule: {name}")
