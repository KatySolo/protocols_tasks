import json
import re
import sys
from subprocess import PIPE, Popen

import requests


def get_info_ip(line):
    ip_pattern = re.compile(r"[0-9]+(?:\.[0-9]+){3}")
    ip_addr = re.findall(ip_pattern, line)
    num = str(line)[:4]
    if ip_addr != []:
        response = requests.get("http://ip-api.com/json/" + ip_addr[0])
        answer = json.loads(response.content)
        if (answer['status'] == 'success'):
            as_num = re.findall(r'AS[0-9]+', answer['as'])[0]
            country = answer['country']
            city = answer['city']
            print(num, ip_addr[0], city + ',' + country, as_num)
        else:
            print(num, ip_addr[0], 'None')


def get_info(user_input):
    p = Popen(['traceroute', '-w', '5', user_input], stdout=PIPE)
    while True:
        line = p.stdout.readline()
        if line.endswith(b"* * *\n"):
            break
        get_info_ip(str(line))
        if not line:
            break


if __name__ == "__main__":
    user_input = sys.argv[1]
    get_info(user_input)
