import json, base64
from compiler import config
import requests

  
class Switches:
    def __init__(self):
        response = requests.get(config.switches_url, auth=(config.login, config.password))
        data = response.json()

        switches_id = []
        for switch in data['devices']:
            switches_id.append(switch['id'])
            
        self.__switches = switches_id
    
    def get_switch_id(self, switchname):
        switchname = switchname.strip("s")
        id = "of:00000000000000{:02x}".format(int(switchname))
        for switch in self.__switches:
            if switch == id:
                return id  
        return ""