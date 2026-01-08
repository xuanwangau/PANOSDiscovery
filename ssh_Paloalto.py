from netmiko import ConnectHandler

import getpass

palo_device={
    'device_type':'paloalto_panos',
    'host':input('Enter device IP: '),
    'username':input('Enter username: '),
    'password':getpass.getpass('Enter password: '),
   
}

print('Connecting to device...')

with ConnectHandler(**palo_device) as ssh:
    
    cli_output=ssh.send_command('show system info')

print(cli_output)