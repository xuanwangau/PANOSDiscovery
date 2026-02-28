# parse_fw.py

# analyze each vsys config section

# modules
import pa_utils

def fw_used(ip, vsys, api_key):

    # vsys is a dictionary looks like 
    # {'@name': vsys_name, 'rulebase':{'security':{'rules':{'entry':[]}}}, 'address':{'entry':[]}, ...}

    # get all address objects 

    all_addrs =[]
    defined_addr_names = set()   
    if vsys.get('address',{}):
        all_addrs = pa_utils.ensure_list(vsys.get('address').get('entry'))
        defined_addr_names = { item.get('@name') for item in all_addrs}

    # get all address groups    
    all_groups=[]
    defined_group_names=set()
    if vsys.get('address-group',{}):
        all_groups = pa_utils.ensure_list(vsys.get('address-group').get('entry'))
        defined_group_names = { item.get('@name') for item in all_groups}

    # structure group map: {'group_name':['member 1', 'member 2']}
    group_map={}
    
    if all_groups:    
        group_map = pa_utils.group_address_mapping(ip, api_key, all_groups)
    
    # get security rules    
    if vsys_secrule:=vsys.get('rulebase',{}).get('security',{}).get('rules'):
            all_rulesec = pa_utils.ensure_list(vsys_secrule.get('entry'))

    # get NAT rules    
    if vsys_natrule:=vsys.get('rulebase',{}).get('nat',{}).get('rules'):
            all_rulenat = pa_utils.ensure_list(vsys_natrule.get('entry'))

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

def fw_map (vsys_root):

    all_address = []
    all_addr_grp = []
    all_secrule = []

    for vsys in vsys_root:
        vsys_name = vsys.get('@name')
        
        if vsys_address:= vsys.get('address',{}).get('entry'):            
            all_address = all_address + pa_utils.ensure_list(vsys_address)        

        # build address group map
        if vsys_addr_grp:=vsys.get('address-group'):            
            all_addr_grp = all_addr_grp + pa_utils.ensure_list(vsys_addr_grp.get('entry'))        

        #build security rule map
        if vsys_secrule:=vsys.get('rulebase',{}).get('security',{}).get('rules'):
            vsys_secrule_list = pa_utils.ensure_list(vsys_secrule.get('entry'))
            
            all_secrule = all_secrule + vsys_secrule_list

    return all_address, all_addr_grp, all_secrule
