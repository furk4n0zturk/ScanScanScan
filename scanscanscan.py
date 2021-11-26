import wget
import requests
import socket
import json
import nmap

domain = input("Domain Girin: ")

print("\nTarama Başlatılıyor")

# githubtan subdomain taraması için wordlist çekilmesi
remote_url = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt'
local_file = "wordlist.txt"
wget.download(remote_url, local_file)

subfile = open("wordlist.txt")
content = subfile.read()
subdomain_list = content.splitlines()

network_scan = []
ip_details = []
subdomain_found = []

nmap = nmap.PortScanner()

for subdomain in subdomain_list:
    pure = f"{subdomain}.{domain}"
    url = f"https://" + pure
    try:
        requests.get(url)
    except requests.ConnectionError:
        # bağlantı hatası halinde pass
        pass
    else:

        # domainin IP adresine çözümlenmesi
        ip = socket.gethostbyname(pure)

        # bağlantı kurulan subdomainlerin ip adresleriyle birlikte yazılması
        print("-" * 20)
        print("\n")

        tam = pure + ' ' + ip
        print(tam)
        subdomain_found.append(tam)

        print("\n")

        # ip detaylarının alınması && yazdırılması
        request_url = 'http://ip-api.com/json/' + ip
        response = requests.get(request_url)
        result = response.content.decode()
        result = json.loads(result)
        print(result, "\n")
        ip_details.append(str(result))

        # port taraması
        nmap.scan(ip, '1-1025')

        for host in nmap.all_hosts():
            ipaddr = 'Host : %s ' % host
            print(ipaddr)
            network_scan.append(ipaddr)
            for protocol in nmap[host].all_protocols():
               lport = nmap[host][protocol].keys()
               for port in lport:
                    portscan_output = 'port: %s\tstate: %s\tservice & version: %s %s' % (port, nmap[host][protocol][port]['state'],nmap[host][protocol][port]['product'],nmap[host][protocol][port]['version'])
                    print(portscan_output)
                    network_scan.append(portscan_output)
            network_scan.append("\n")

# verilerin dosyalara yazdırılması
sub_output = open("subdomain_found.txt", "w")
for i in subdomain_found:
    sub_output.write(i + "\n")

ip_output = open("ip_details.txt", "w")
for i in ip_details:
    ip_output.write(i + "\n\n")

network_output = open("network_scan.txt", "w")
for i in network_scan:
    network_output.write(i + "\n")
