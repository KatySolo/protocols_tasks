from subprocess import PIPE, STDOUT, Popen, run
import threading
import time
import re
import socket
import ipwhois

whois_databases = ["ripe","afrinic","apnic","arin","lacnic"]

user_input = "urfu.ru"


def get_info():
    p = Popen(['traceroute', user_input], stdout=PIPE)
    while True:
        line = p.stdout.readline()
        get_ripe_info(str(line))
        if not line:
            break

    # with open('temp.txt','w',encoding='utf-8') as out:
    #     subprocess.run(["traceroute",user_input],stdout=out)



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
# read_info()
get_info()

