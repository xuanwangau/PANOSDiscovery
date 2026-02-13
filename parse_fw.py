# parse_fw.py

# analyze each vsys config section

# modules
import pa_utils

def parse(ip, vsys, api_key):

    # vsys is a dictionary looks like 
    # {'@name': vsys_name, 'rulebase':{'security':{'rules':{'entry':[]}}}, 'address':{'entry':[]}, ...}

    # get all address objects
    all_addrs, defined_addr_names = pa_utils.gen_obj('address', vsys)
    
    # get all address groups
    all_groups, defined_group_names = pa_utils.gen_obj('address-group', vsys)

    # structure group map: {'group_name':['member 1', 'member 2']}
    group_map={}
    
    if all_groups:    
        for group in all_groups:        
            if group.get('static',{}):
                members = pa_utils.ensure_list(group.get('static').get('member'))
                
            else: # must be dynamic group                 
                dyn_grp_raw = pa_utils.get_dyn_group(ip, group.get('@name'), api_key)
                
                if dyn_grp_raw:
                    member_list = pa_utils.ensure_list(dyn_grp_raw.get('dyn-addr-grp').get('entry').get('member-list').get('entry'))
                    members = [item.get('@name') for item in member_list]                    

            group_map[group['@name']] = members
        
    
    # get security rules

    all_rulesec = pa_utils.gen_rule_fw('security', vsys)

    # get NAT rules

    all_rulenat = pa_utils.gen_rule_fw('nat', vsys)

    # find used objects

    print("Processing object usage...")

    used_references = set()

    # identify objects in security rules source and destination
    if all_rulesec:
        for rule in all_rulesec:
            used_references.update(pa_utils.ensure_list(rule.get('source').get('member')))
            used_references.update(pa_utils.ensure_list(rule.get('destination').get('member')))

    # identify objects in nat rules source and destination, source-translation, destination-translation
    if all_rulenat:
        for rule in all_rulenat:
            used_references.update(pa_utils.ensure_list(rule.get('source').get('member')))
            used_references.update(pa_utils.ensure_list(rule.get('destination').get('member')))
            
            if rule.get('destination-translation'):
                used_references.update(pa_utils.ensure_list(rule.get('destination-translation').get('translated-address'))) 

            if rule.get('source-translation'):
                src_trans = rule.get('source-translation')
            
                if src_trans.get('static-ip',{}):
                    used_references.update(pa_utils.ensure_list(src_trans.get('static-ip').get('translated-address')))
                else:
                    for value in src_trans.values():
                        if isinstance(value, dict) and value.get('translated-address',{}):
                            used_references.update(pa_utils.ensure_list(value.get('translated-address').get('member')))    

    return defined_addr_names, defined_group_names, group_map, used_references

