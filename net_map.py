import os, networkx, argparse, ipaddress

ip_list = [] # list of all discovered IPs
hostnames = [] # list of all discovered reverse DNS names

def ip_scan(address): # ping each ip

    a = os.system
    try:
        status = a('ping %s' % address)
        ip_list.append(address)
    except Exception, e:
    	print e
    print status

def ipnetwork(network): # interpret network or address

    ip = ipaddress.ip_network(network)
    print ip
    return

def network_map(ip_list): # pump list of ips into function to map network

    return

def main():

    parser = argparse.ArgumentParser('usage%prog ' % '-h <Host Address> OR -n <IP range>')
    parser.add_argument('-h', '--host', help='Please enter a host address')
    parser.add_argument('-n', '--network', help='Please enter a network range')
    args = parse.args()
    host = args.host
    network = args.network

    
