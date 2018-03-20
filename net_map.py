import nmap, argparse, ipaddress, progress_bar, os
import networkx as nx
from multiprocessing import Process
from prettytable import PrettyTable
from time import sleep # for Progress Bar

ip_list = [] # list of all discovered IPs
ips_hostnames = PrettyTable(['IP','hostnames','OS']) # list of all discovered reverse DNS names
a = os.system # clear screen after every progress update

def ipnetwork(network): # interpret network

    ips = ipaddress.ip_network(unicode(network))
    for ip in ips:
	try:
            nmScan = nmap.PortScanner()
            nmScan.scan(str(ip),arguments='-n -sP -PE -T4')
	    state = nmScan[str(ip)].state()
            if state == 'up':
                ip_list.append(str(ip))
	    else:
		pass
        except Exception, e:
            continue
        
    
    print "%d Hosts are up." % len(ip_list)
    
    progress_bar.printProgressBar(0, len(ip_list), prefix='Scanning %d of %d...\nProgress:' % (1,len(ip_list)), suffix='Complete', length=50) # initialize progress bar
    iphostname(ip_list)

def iphostname(ip_list): # pull hostnames for list of IPs
	
	r = 1
	for i,ip in enumerate(ip_list):
		try:
			nmScan = nmap.PortScanner()
			results = nmScan.scan(str(ip),arguments='-A -T5')
			hostname = results['scan'][str(ip)]['hostnames'][0]['name']
			OS = results['scan'][str(ip)]['osmatch'][0]['name']
			if OS == None:
				ips_hostnames.add_row([ip, hostname, ''])
			else:
				ips_hostnames.add_row([ip, hostname, OS])
			a('clear')
		except Exception, e:
			print e
			continue
		progress_bar.printProgressBar(i + 1, len(ip_list), prefix='Scanning %d of %d...\nProgress:' % (r + 1,len(ip_list)), suffix='Complete', length=50)
		
def network_map(ip_list): # pump list of ips into function to map network

    G = nx.Graph()
    for ip in ip_list:
        G.add_node(ip)
    G.graph
    
def main():

    parser = argparse.ArgumentParser('usage%prog ' '-n <IP range>')
    parser.add_argument('-n', '--network', help='Please enter a network range')
    args = parser.parse_args()
    network = args.network

    if network == None:
        print usage
        exit(0)
    else:
        p = Process(target=ipnetwork,args=(network,))
        p.start()
        p.join()

    print ips_hostnames

main()
