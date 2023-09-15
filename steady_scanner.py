import pyfiglet
import nmap
#from colorama import Fore, Style
from termcolor import colored


#CREATING A BANNER
def create_stylish_banner(text):
    banner = pyfiglet.figlet_format(text)
    return banner

# Example usage:
banner_text = "     SCANNER!\n"
banner = create_stylish_banner(banner_text)
print(colored(text=banner, color='green', attrs=['bold']))

#CREATING NMAP PROMPT

n_scanner = nmap.PortScanner()
iput_opt = colored('[+]', color='yellow')
iput_opt2 = colored('[-]', color='yellow')
target_addr = input(f'{iput_opt} Enter target IP Address to scanner: ')
print(f'The target entered is [ {target_addr} ]')
type(target_addr)

scan_type = int(input(f"""\n{iput_opt2} Select scan type:
                    
            0) Syn-Ack Scan
            1) UDP Scan
            2) Comprehensive Scan
            \n{iput_opt} """))
print(f'Selected Option: {scan_type}\n')

# scan_port = str(input('[+] Enter port/ports to scan: '))

if (scan_type == 0):
    scan_port = str(input(f'{iput_opt} Enter port/ports to scan: '))
    scn_protocol = 'tcp'
    print(colored(f'\nNMAP Version: {n_scanner.nmap_version()}\n',color='cyan', attrs=['bold']))
    n_scanner.scan(target_addr,scan_port, '-v -sS')
    # print(n_scanner.scaninfo())
    print(f'{iput_opt2} Target Status: {n_scanner[target_addr].state()}')
    print(f'{iput_opt2} Protocol: ',n_scanner[target_addr].all_protocols(),'\n')
    open_ports = n_scanner[target_addr]['tcp'].keys()

    print(colored('*'*10 +' [SCAN STARTED]  '+'*'*10 + '\n', color='red', attrs=['bold']))
    print(colored('Port         State           Service', attrs=['bold']))
    for port in open_ports:
        port_info = n_scanner[target_addr]['tcp'][port]
        if port_info['state'] == 'open':
            print(colored(f"    {port}            {port_info['state']}              {port_info['name']}",color='green'))


#SCANNING UDP
elif (scan_type == 1):
    scan_port = str(input(f'{iput_opt} Enter port/ports to scan: '))
    scn_protocol = 'udp'
    print(colored(f'NMAP Version: {n_scanner.nmap_version()} \n',color='cyan', attrs=['bold']))
    n_scanner.scan(target_addr,scan_port, '-v -sU')
    print(f'{iput_opt2} Target Status: {n_scanner[target_addr].state()}')
    print(f'{iput_opt2} Protocol: ',n_scanner[target_addr].all_protocols(),'\n')
    open_ports = n_scanner[target_addr][scn_protocol].keys()

    print(colored('*'*10 +' [SCAN STARTED]  '+'*'*10 + '\n', color='red', attrs=['bold']))
    print(colored('Port         State           Service', attrs=['bold']))
    for port in open_ports:
        port_info = n_scanner[target_addr][scn_protocol][port]
        if port_info['state'] == 'open':
            print(colored(f"    {port}            {port_info['state']}              {port_info['name']}",color='green'))


#COMPREHENSIVE SCAN
elif (scan_type == 2):
    scan_port = str(input(f'{iput_opt} Enter port/ports to scan: '))
    scn_protocol = 'tcp'
    print(colored(f'NMAP Version: {n_scanner.nmap_version()} \n',color='cyan', attrs=['bold']))
    n_scanner.scan(target_addr,scan_port, '-v -sS -sV -sC -A -O')
    print(f'{iput_opt2} Target Status: {n_scanner[target_addr].state()}')
    print(f'{iput_opt2} Protocol: ',n_scanner[target_addr].all_protocols(),'\n')
    open_ports = n_scanner[target_addr][scn_protocol].keys()

    print(colored('*'*10 +' [SCAN STARTED]  '+'*'*10 + '\n', color='red', attrs=['bold']))
    print(colored('Port         State           Service', attrs=['bold']))
    for port in open_ports:
        port_info = n_scanner[target_addr][scn_protocol][port]
        if port_info['state'] == 'open':
            print(colored(f"    {port}            {port_info['state']}              {port_info['name']}",color='green'))



elif (scan_type >= 3):
    print(colored('[*] Please enter a valid option!!!', color='red', attrs=['bold']))