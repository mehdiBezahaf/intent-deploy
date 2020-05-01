import json, base64
import coloredlogs, logging
from compiler import config

coloredlogs.install(level='INFO')


  
class Hosts:
    def __init__(self):
        response = requests.get(hosts_url, auth=(login, password))
        data = response.json()

        hosts_mac = []
        hosts_id = []
        for host in data['hosts']:
            hosts_mac.append(host['mac']) 
            hosts_id.append(host['id'])

    
        self.__hosts = {'mac':hosts_mac, 'id':hosts_id}
    
    def get_host_id(self, hostname):
        hostname = hostname.strip("h")
        mac = "00:00:00:00:00:{:02x}".format(int(hostname))
        for host in self.__hosts:
            if host.get("mac") == mac:
                return host.get("id")  
        return ""
    
    def get_host_mac(self, hostname):
        hostname = hostname.strip("h")
        mac = "00:00:00:00:00:{:02x}".format(int(hostname))
        for host in self.__hosts:
            if host.get("mac") == mac:
                return host.get("mac")  
        return ""
