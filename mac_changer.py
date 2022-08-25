import subprocess
import optparse
import re



def get_arguments():
	parser = optparse.OptionParser()

	parser.add_option('-i','--interface', dest="interface", help = "Interface to change it's MAC Address")
	parser.add_option('-m','--mac', dest="new_mac", help = "New MAC Address")
	(option,arguments) = parser.parse_args()
	if not option.interface:
		parser.error("Please specify an Interface.--help for more")
	
	elif not option.new_mac:
		parser.error("Please specify an New MAC.--help for more")
	
	return option
	

def change_mac(interface, new_mac):
	print("[+]Changing interface of " + interface + "to " + new_mac)
	subprocess.call(f'ifconfig {interface} down', shell=True)
	subprocess.call(f"ifconfig {interface} hw ether {new_mac}",shell=True)
	subprocess.call(f'ifconfig {interface} up ',shell=True)



def MAC_filter(interface):
	result = subprocess.check_output(["ifconfig", interface])	
	mac_filter = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", result.decode('utf-8'))
	if mac_filter:
		return mac_filter.group(0)
	else:
		print("[-] Could not read MAC address")	
	


option = get_arguments()
current_mac = MAC_filter(option.interface)
print(f"Current mac is = {current_mac}")


change_mac(option.interface, option.new_mac)

current_mac = MAC_filter(option.interface)
if current_mac == option.new_mac:
	print(f"[+] MAC address changed Successfully to {current_mac}")
else:
	print("[-] MAC address did not changed!.")	