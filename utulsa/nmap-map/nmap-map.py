# Author: TNAR5
# Usage: python nmap-map.py scan.xml

import xml.etree.ElementTree as xparse
import sys
from PIL import Image, ImageDraw, ImageFont
import math
import textwrap

def parse_scan_xml(target_file):
    data = xparse.parse(target_file).getroot()
    hosts = []
    args = data.get('args')
    print(len(args))
    for host in data.findall('host'):
        h_addr = host.find('address').get('addr')
        h_ports = [] 
        h_services = []
        os = None
        if (host.find('os') != None) and host.find('os').find('osmatch') != None:
            os = host.find('os').find('osmatch').get('name')
        for port in host.find('ports').findall('port'):
            if port.find('state').get('state') == 'open':
                h_ports.append(port.get('portid'))
                h_services.append(port.find('service').get('name'))
        hosts.append( {
            "address": h_addr,
            "ports": h_ports,
            "services": h_services,
            "os": os,
            "args": args
        })
    return hosts

def create_map(hosts, output_file):
    num_hosts = len(hosts)
    host_w = 600
    host_h = 600
    buffer_space = 50    
    font_size = 25
    fontos_size = 20
    tile_space = 50
    hosts_per_line = math.ceil(math.sqrt(num_hosts))
    print("Hosts: " + str(num_hosts))
    width = (buffer_space * hosts_per_line) + (host_w*hosts_per_line) + buffer_space
    height = (buffer_space * hosts_per_line) + (host_h*hosts_per_line) + buffer_space + tile_space

    win_logo = Image.open("resources/win_logo.png")
    lin_logo = Image.open("resources/lin_logo.png").convert("RGBA")
    other_logo = Image.open("resources/other_logo.png")
    bsd_logo = Image.open("resources/bsd_logo.png")
    rwin_logo = win_logo.resize((math.ceil(host_w/3),math.ceil(host_h/3)))
    rlin_logo = lin_logo.resize((math.ceil(host_w/3),math.ceil(host_h/3)))
    rother_logo = other_logo.resize((math.ceil(host_w/3),math.ceil(host_h/3)))
    rbsd_logo = bsd_logo.resize((math.ceil(host_w/3),math.ceil(host_h/3)))
    font = ImageFont.truetype("arial.ttf", font_size)
    fontos = ImageFont.truetype("arial.ttf", fontos_size)
    img = Image.new(mode="RGB", size=(width, height))
    draw = ImageDraw.Draw(img)
    
    args = hosts[0]['args']
    draw.text(((width)/3, 10), "Command: " + str(args), fill=(255, 255, 255), font=font)
    
    root_x = buffer_space
    root_y = buffer_space + tile_space
    for h in hosts:
        tmp_y = root_y
        draw.rectangle([(root_x, root_y), (root_x+host_w, root_y+host_h)], fill ="gray", outline ="gray")
        draw.text((root_x+10, root_y+10), "IP: " + h['address'], fill=(255, 255, 255), font=font)
        tmp_y = root_y + 20
        tmp_y += font_size
        for i in range(0, len(h['ports'])):
            tmp_y +=font_size
            draw.text((root_x + 10, tmp_y), (h['services'][i] + ": " + h['ports'][i]), fill=(0, 255, 0), font=font)
        if h['os'] != None:
            if 'Windows' in h['os']:
                img.paste(rwin_logo, (root_x + host_w - round(host_w/3), root_y+10), rwin_logo)
            elif 'Linux' in h['os']:
                img.paste(rlin_logo, (root_x + host_w - round(host_w/3), root_y+10),rlin_logo)
            elif 'BSD' in h['os']:
                img.paste(rbsd_logo, (root_x + host_w - round(host_w/3) - 10, root_y+10), rbsd_logo)
            else:
                img.paste(rother_logo, (root_x + host_w - round(host_w/3)- 10, root_y+10), rother_logo)
            os_t = textwrap.wrap(h['os'], width=18)
            tmp_y = 0
            for t in os_t:
                tmp_y += fontos_size
                draw.text((root_x + host_w - round(host_w/3), root_y+tmp_y+math.ceil(host_h/3)), t, fill=(255, 255, 255), font=fontos)
        else:
            img.paste(rother_logo, (root_x + host_w - round(host_w/3)- 10, root_y+10), rother_logo)
            draw.text((root_x + host_w - round(host_w/3), root_y+20+math.ceil(host_h/3)), "Could Not Detect OS", fill=(255, 255, 255), font=fontos)

        if (root_x + host_w + buffer_space) >= width:
            root_x = buffer_space 
            root_y += host_h + buffer_space
        else:
            root_x += host_w + buffer_space
    # write to stdout
    img.save(output_file)


target_file = sys.argv[1]
if len(sys.argv) >=3:
    output_file = sys.argv[2]
else:
    output_file = "map.png"


create_map(parse_scan_xml(target_file), output_file)
