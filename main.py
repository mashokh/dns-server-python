import struct
import sys
from socket import *
from easyzone import easyzone
import sys
import ipaddress

ROOT_SERVER_ADDRESS = ("199.7.91.13", 53)
CACHE = {}


def run_dns_server(CONFIG, IP, PORT):
    # your code here
    open_socket(IP, PORT, CONFIG)
    pass


def open_socket(IP, PORT, CONFIG):
    server_address = (IP, int(PORT))
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(server_address)
    while True:
        message, addr = server_socket.recvfrom(2048)
        response, data = create_answer(message, CONFIG)
        CACHE[data] = response
        server_socket.sendto(response, addr)


def create_answer(message, CONFIG):
    domain_name = find_domain_name(message[12:])[0]
    path = CONFIG + domain_name + "conf"
    q_type = get_type(message[12:])
    if domain_name + q_type in CACHE:
        return CACHE[domain_name + q_type]
    try:
        zone = easyzone.zone_from_file(domain_name, path)
        headers, a_name, a_type, my_data, type_offset, tp = create_dns_header(message, CONFIG)
        body = create_dns_body(message, type_offset, a_type, my_data, tp)
        question = create_dns_question(type_offset, a_type, message)
        return headers + question + body, domain_name + q_type
    except:
        return do_recursion(message, ROOT_SERVER_ADDRESS), domain_name + q_type


def create_dns_body(message, type_offset, a_type, my_data, tp):
    resp = b''
    name = message[12:12 + type_offset]
    cur_tp = a_type
    my_class = (1).to_bytes(2, byteorder='big')
    ttl = (30).to_bytes(4, byteorder='big')
    r_data = b''
    rd_length = 0
    if tp == 'A':
        rd_length = 4
        for i in (0, len(my_data) - 1):
            for part in my_data[i].split('.'):
                r_data += bytes([int(part)])
        rd_length = rd_length.to_bytes(2, byteorder='big')
        resp = name + cur_tp + my_class + ttl + rd_length + r_data
    elif tp == 'NS':
        for data in my_data:
            r_data = get_link(data)[0]
            rd_length = get_link(data)[1]
            rd_length = rd_length.to_bytes(2, byteorder='big')
            resp += name + cur_tp + my_class + ttl + rd_length + r_data
    elif tp == 'TXT':
        for data in my_data:
            r_data = (len(data)).to_bytes(1, byteorder='big')
            r_data += bytes(data, 'utf-8')
            r_data += (0).to_bytes(1, byteorder='big')
            rd_length = len(data) + 1
            rd_length = rd_length.to_bytes(2, byteorder='big')
            resp += name + cur_tp + my_class + ttl + rd_length + r_data
    elif tp == 'AAAA':
        for data in my_data:
            curr = ipaddress.ip_address(data)
            r_data = curr.packed
            rd_length = (16).to_bytes(2, byteorder='big')
            resp += name + cur_tp + my_class + ttl + rd_length + r_data
    elif tp == 'MX':
        for data in my_data:
            preference = int(data[0]).to_bytes(2, byteorder='big')
            exchange = get_link(data[1])[0]
            r_data = preference + exchange
            rd_length = get_link(data[1])[1] + 2
            rd_length = rd_length.to_bytes(2, byteorder='big')
            resp += name + cur_tp + my_class + ttl + rd_length + r_data
    elif tp == 'SOA':
        count = 0
        for part in my_data[0].split(' '):
            if count < 2:
                r_data += get_link(part)[0]
                rd_length += get_link(part)[1]
                count += 1
            else:
                r_data += (int(part)).to_bytes(4, byteorder='big')
                rd_length += 4
        rd_length = rd_length.to_bytes(2, byteorder='big')
        resp += name + cur_tp + my_class + ttl + rd_length + r_data
    return resp


def get_link(link):
    link = link[:len(link) - 1]
    res = b''
    count = 0
    dot_list = []
    for ch in link:
        if ch == '.':
            dot_list.append(count)
            count = 0
        else:
            count += 1
    dot_list.append(count)
    full_count = 0
    for i in dot_list:
        full_count += i
    full_count += len(dot_list)
    full_count += 1
    res += int(dot_list[0]).to_bytes(1, byteorder='big')
    dot_list.pop(0)
    for ch in link:
        if ch == '.':
            res += int(dot_list[0]).to_bytes(1, byteorder='big')
            dot_list.pop(0)
        else:
            res += bytes(ch, 'utf-8')
    res += (0).to_bytes(1, byteorder='big')
    return res, full_count


def create_dns_question(type_offset, q_type, message):
    q_bytes = b''
    name = message[12:12 + type_offset]
    q_bytes += name
    q_bytes += q_type
    q_bytes += (1).to_bytes(2, byteorder='big')
    return q_bytes


def create_dns_header(message, CONFIG):
    resp_id = message[:2]
    qr = '1'
    opcode = '1111'
    aa = '1'
    tc = '0'
    rd = '0'
    ra = '1'
    z = '000'
    r_code = '0000'
    my_data, domain_name, q_type, type_offset, tp = resource_records(message[12:], CONFIG)
    an_count = len(my_data).to_bytes(2, byteorder='big')
    ns_count = (0).to_bytes(2, byteorder='big')
    qd_count = b'\x00\x01'
    ar_count = (0).to_bytes(2, byteorder='big')
    first = int(qr + opcode + aa + tc + rd, 2).to_bytes(1, byteorder='big')
    second = int(ra + z + r_code, 2).to_bytes(1, byteorder='big')
    return resp_id + first + second + qd_count + an_count + ns_count + ar_count, domain_name, q_type, my_data, type_offset, tp


def resource_records(message, CONFIG):
    domain_name, q_type, type_offset = find_domain_name(message)
    tp = get_type(message)
    path = CONFIG + domain_name + "conf"
    zone = easyzone.zone_from_file(domain_name, path)
    resp = zone.names[domain_name].records(tp).items
    return resp, domain_name, q_type, type_offset, tp


def get_type(message):
    domain_name, q_type, type_offset = find_domain_name(message)
    tp = ''
    if q_type == b'\x00\x01':
        tp = 'A'
    elif q_type == b'\x00\x02':
        tp = 'NS'
    elif q_type == b'\x00\x0f':
        tp = 'MX'
    elif q_type == b'\x00\x05':
        tp = 'CNAME'
    elif q_type == b'\x00\x1c':
        tp = 'AAAA'
    elif q_type == b'\x00\x10':
        tp = 'TXT'
    elif q_type == b'\x00\x06':
        tp = 'SOA'
    return tp


def find_domain_name(message):
    counter = 0
    string_length = 0
    current_string = ''
    domain = ""
    i = 0
    j = 0
    for byte in message:
        if counter == 1:
            if byte != 0:
                current_string += chr(byte)
            i += 1
            if i == string_length:
                domain += current_string
                domain += "."
                current_string = ''
                counter = 0
                i = 0
            if byte == 0:
                domain += current_string
                break
        else:
            counter = 1
            string_length = byte
        j += 1
    q_type = message[j:j + 2]
    return domain, q_type, j


def do_recursion(message, server_address):
    client_socket = socket(AF_INET, SOCK_DGRAM)
    client_socket.sendto(message, server_address)
    response, addr = client_socket.recvfrom(2048)
    an_count = int.from_bytes(response[6:9], "big")
    while an_count == 0:
        start = 12 + len(find_domain_name(response[12:])[0]) + 4 + 13
        domain_name = get_rec_domain_name(response, start)
        name = ""
        for str in domain_name:
            name += str.decode('utf-8')
            name += '.'
        new_server_address = (name, 53)
        return do_recursion(message, new_server_address)
    return response


def get_rec_domain_name(message, start):
    response = []

    while True:
        length, = struct.unpack_from("!B", message, start)

        if length == 192:
            new_start, = struct.unpack_from("!H", message, start)
            start += 2
            return response + get_rec_domain_name(message, new_start & 0x3FFF)
        start += 1
        if length == 0:
            return response
        response.append(*struct.unpack_from("!%ds" % length, message, start))
        start += length


# do not change!
if __name__ == '__main__':
    CONFIG = sys.argv[1]
    IP = sys.argv[2]
    PORT = sys.argv[3]
    run_dns_server(CONFIG, IP, PORT)
