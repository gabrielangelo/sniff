from collections import Counter
from operator import itemgetter

from pyshark import FileCapture
from terminaltables import AsciiTable


def make_obj(packet):
    try:
        return {
            'ip_dst': packet.ip.dst, 
            'ip_src': packet.ip.src, 
            'port_src': packet.udp.dstport if 'UDP' in packet else packet.tcp.dstport, 
            'port_dst': packet.udp.srcport if 'UDP' in packet else packet.tcp.srcport, 
            'length': packet.length, 
            'type': packet.transport_layer,
            'type_high': packet.highest_layer 
        }   
    except:
        pass

def read_pcap_file(pcap_file):
    packs = filter(None, map(make_obj, FileCapture(pcap_file))) 
    return packs

def get_main_obj_ocurrences(_list, key):
    return Counter(map(itemgetter(key), _list)).most_common(1)[0][0]

def main_ip_src(packets):
    return get_main_obj_ocurrences(packets, 'ip_src')

def main_ip_dst(packets):
    return get_main_obj_ocurrences(packets, 'ip_dst')

def middle_and_total_length_packets(packets):
    total_length = sum([int(pkg['length']) for pkg in packets])
    return total_length, (total_length / len(packets))

def presentation(packets):
    print('\n#####FLOWS#####\n')
    table_data = [['type', 'from', 'to', 'size']]
    for packet in packets:
        table_data.append([
            '{0}/{1}'.format(packet['type'],packet['type_high']), 
            '{0}:{1}'.format(packet['ip_src'], packet['port_src']), 
            '{0}:{1}'.format(packet['ip_dst'],packet['port_dst']), 
            '{0} kb'.format(packet['length'])]
        )
    print(AsciiTable(table_data).table)

def statistics(packets):
    total_length, middle_len_packets = middle_and_total_length_packets(packets)
    table = [
        ['main ip transmitter', 'main ip receptor' , 
        'packet middle size', 'total size'], 
        [main_ip_src(packets), main_ip_dst(packets), '%.2f kb' % middle_len_packets, '%d kb' % total_length]
    ]
    print(AsciiTable(table).table)

if __name__ == '__main__':
    import sys
    import os

    timeout = sys.argv[1]
    interface = sys.argv[2]
    filename = sys.argv[3]
    os.system("sudo timeout {0} tcpdump -i {1} '((tcp) or (ip))' -w {2}".format(timeout, interface, filename))
    packets = list(read_pcap_file(filename))
    presentation(packets)
    statistics(packets)
    print("\033[92m {}\033[00m".format('OK'))