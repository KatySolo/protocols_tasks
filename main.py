from subprocess import PIPE, STDOUT, Popen, run
import threading
import time
import re
import socket
import ipwhois
import sys

whois_databases = ["ripe","afrinic","apnic","arin","lacnic"]

#


def get_info(user_input):
    p = Popen(['traceroute', user_input], stdout=PIPE)
    while True:
        line = p.stdout.readline()
        if line.endswith(b"* * *\n"):
            break
        get_ripe_info(str(line))
        if not line:
            break

def get_ripe_info(line):
    num = re.findall('\d+',line)[0]
    ip_pattern = re.compile(r"[0-9]+(?:\.[0-9]+){3}")
    ip_addr = re.findall(ip_pattern, line)
    if ip_addr != []:
        ip_addr_bytes = bytes(ip_addr[0].encode())
        a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        a.connect(("whois.ripe.net",43))
        a.send(ip_addr_bytes+b'\n')
        page = b""
        while 1:
            data = a.recv(2048)
            if not data:
                break
            page = page + data
        final_str = num +' '+ip_addr[0]
        as_num = re.findall(r'AS[0-9]+',str(page))
        if as_num != []:
           final_str += ' '+as_num[0]
        else:
           final_str += ' ---'
        print (final_str)


if __name__ == "__main__":
    user_input = sys.argv[1]
    get_info(user_input)
