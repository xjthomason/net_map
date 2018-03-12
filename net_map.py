import nmap, argparse, ipaddress
import networkx as nx
from multiprocessing import Process # TODO see how subprocess can assist with this

ip_list = [] # list of all discovered IPs
hostnames = [] # list of all discovered reverse DNS names

def ipnetwork(network): # interpret network

    nmScan = nmap.PortScanner()
    ips = ipaddress.ip_network(unicode(network))
    for ip in ips:
	try:
            nmScan.scan(str(ip),arguments='-n -sP -PE')
	    state = nmScan[str(ip)].state()
            if state == 'up':
                ip_list.append(str(ip))
	    else:
		pass
        except Exception, e:
            continue
    print "%d # of Hosts are up." % len(ip_list)
            
def network_map(ip_list): # pump list of ips into function to map network

    G = nx.Graph()
    for ip in ip_list:
        G.add_node(ip)
    G.graph
    
def main():
    global ip_list

    parser = argparse.ArgumentParser('usage%prog ' '-n <IP range>')
    parser.add_argument('-n', '--network', help='Please enter a network range')
    args = parser.parse_args()
    network = args.network

    if network == None:
        print usage
        exit(0)
    else:
        p = Process( target=ipnetwork,args=(network,))
        p.start()
        p.join()

    network_map(ip_list)

main()
