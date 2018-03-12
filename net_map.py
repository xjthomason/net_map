import os, networkx, argparse, ipaddress, subprocess # TODO see how subprocess can assist with this

ip_list = [] # list of all discovered IPs
hostnames = [] # list of all discovered reverse DNS names

def ip_scan(address): # ping each ip

    a = os.system
    try:
        status = a('ping -c 1 -W 2 %s' % address)
    except Exception, e:
    	print e
    print status

def ipnetwork(network): # interpret network

    ip = ipaddress.ip_network(unicode(network))
    for i in ip:
        try:
            ip_scan(i)
            ip_list.append(i)
        except Exception, e:
            print e
            
def network_map(ip_list): # pump list of ips into function to map network

    return

def main():

    parser = argparse.ArgumentParser('usage%prog ' '-h <Host Address> -n <IP range>')
    parser.add_argument('-H', '--host', help='Please enter a host address')
    parser.add_argument('-n', '--network', help='Please enter a network range')
    args = parser.parse_args()
    host = args.host
    network = args.network

    if host == None and network:
        ipnetwork(network)

    if network == None and host:
        ip_scan(host)

main()
