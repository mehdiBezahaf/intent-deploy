import json, base64
from compiler import config
import requests

  
class Hosts:
    def __init__(self):
        response = requests.get(config.hosts_url, auth=(config.login, config.password))
        data = response.json()

        hosts ={}
        for host in data['hosts']:
            hosts[host['mac']] = host['id']
    
        self.__hosts = hosts
    
    def get_host_id(self, hostname):
        hostname = hostname.strip("h")
        mac = "00:00:00:00:00:{:02x}".format(int(hostname))
        for host in self.__hosts:
            if host == mac:
                return self.__hosts[mac] #it should reutrn the id  
        return ""
    
    def get_host_mac(self, hostname):
        hostname = hostname.strip("h")
        mac = "00:00:00:00:00:{:02x}".format(int(hostname))
        for host in self.__hosts:
            if host == mac:
                return mac
        return ""
