# parse_pano.py

# parse objects and rules on Panorama

# modules
import pa_utils

def parse_section_obj (ip, section_root, api_key):
 
    section_addrs, section_addr_names = pa_utils.gen_obj('address', section_root)
    section_groups, section_group_names = pa_utils.gen_obj('address-group', section_root)

    # structure group map: {'group_name':['member 1', 'member 2']}
    section_group_map={}

    if section_groups:
        for group in section_groups:
            if group.get('static',{}):
                members = pa_utils.ensure_list(group.get('static').get('member'))
                
            else: # must be dynamic group                 
                dyn_grp_raw = pa_utils.get_dyn_group(ip, group.get('@name'), api_key)
                
                if dyn_grp_raw:
                    member_list = pa_utils.ensure_list(dyn_grp_raw.get('dyn-addr-grp').get('entry').get('member-list').get('entry'))
                    members = [item.get('@name') for item in member_list]                    

            section_group_map[group['@name']] = members

    return section_addr_names, section_group_names, section_group_map


def parse (ip, dg_root, shared_root, api_key):

    defined_addr_names = set()
    defined_group_names = set()    

    shared_addr_names, shared_group_names, shared_group_map = parse_section_obj(ip, shared_root, api_key)

    defined_addr_names.update(shared_addr_names)
    defined_group_names.update(shared_group_names)

    all_group_map = shared_group_map

    for dg in dg_root:
        dg_addr_names, dg_group_names, dg_group_map = parse_section_obj(ip, dg, api_key)

        defined_addr_names.update(dg_addr_names)
        defined_group_names.update(dg_group_names)

        if dg_group_map:
            for name, member in dg_group_map.items():
                all_group_map[name]=member
    
    # parse rules for all sections
    # make sure section contains key 'pre/post-rulebase'

    # combine shared and dg security rules
    pre_or_post = ['pre-rulebase', 'post-rulebase']
    all_rulesec =[]

    for base_tag in pre_or_post:
        if shared_root.get(base_tag,{}):
            all_rulesec = all_rulesec + pa_utils.gen_rule_pano(base_tag, 'security', shared_root)

    for dg in dg_root:
        for base_tag in pre_or_post:
            if dg.get(base_tag,{}):
                all_rulesec = all_rulesec + pa_utils.gen_rule_pano(base_tag,'security', dg)
    
    # combine shared and dg nat rules
    all_rulenat =[]

    for base_tag in pre_or_post:
        if shared_root.get(base_tag,{}):
            all_rulenat = all_rulenat + pa_utils.gen_rule_pano(base_tag, 'nat', shared_root)
    
    for dg in dg_root:
        for base_tag in pre_or_post:
            if dg.get(base_tag,{}):
                all_rulenat = all_rulenat + pa_utils.gen_rule_pano(base_tag,'nat', dg)

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

    return defined_addr_names, defined_group_names, all_group_map, used_references