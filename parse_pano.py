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
                grp_name=group.get('@name')
                dyn_grp_xpath=f"<show><object><dynamic-address-group><name>{grp_name}</name></dynamic-address-group></object></show>"    
                dyn_grp_resp = pa_utils.op_request(ip,api_key,dyn_grp_xpath) 
                
                if dyn_grp_raw:= dyn_grp_resp.get('response').get('result',{}):
                    member_list = pa_utils.ensure_list(dyn_grp_raw.get('dyn-addr-grp').get('entry').get('member-list').get('entry'))
                    members = [item.get('@name') for item in member_list]                    

            section_group_map[group['@name']] = members

    return section_addr_names, section_group_names, section_group_map


def pano_used (ip, dg_root, shared_root, api_key):

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

def pano_map(shared_root, dg_root):

    # update map from shared config
    all_address = pa_utils.ensure_list(shared_root.get('address',{}).get('entry'))
    all_addr_grp = pa_utils.ensure_list(shared_root.get('address-group',{}).get('entry'))
    all_secrule = []
    pre_or_post=['pre-rulebase', 'post-rulebase']

    for rulebase in pre_or_post:
        if sh_secrules:= shared_root.get(rulebase).get('security',{}).get('rules'):
            sh_secrules_list = pa_utils.ensure_list(sh_secrules.get('entry'))
            for rule in sh_secrules_list:
                rule['rule-location'] = 'shared'
            all_secrule = all_secrule + sh_secrules_list

    # update map from all dg config
    for dg in dg_root:
        dg_name = dg.get('@name')

        if dg.get('devices'):
            if dg_address := dg.get('address'):
                all_address = all_address + pa_utils.ensure_list(dg_address.get('entry'))
            if dg_addr_grp:= dg.get('address-group'):
                all_addr_grp = all_addr_grp + pa_utils.ensure_list(dg_addr_grp.get('entry'))
            
            for rulebase in pre_or_post:                
                if dg_secrules:= dg.get(rulebase,{}).get('security',{}).get('rules'):
                    dg_secrules_list = pa_utils.ensure_list(dg_secrules.get('entry'))
                    for rule in dg_secrules_list:
                        rule['rule-location'] = f"{dg_name}"
                    all_secrule = all_secrule + dg_secrules_list

    return all_address, all_addr_grp, all_secrule