import configparser

import scapy.all as scapy


class Frame:
    index = None
    hex_value = None

    eth_type = None
    dest_mac = None
    src_mac = None
    length_api = None
    length_med = None
    nested_mac = None

    sap = None

    src_ip = None
    dest_ip = None
    nested_ip = None
    size_ip = None

    src_port = None
    dest_port = None
    nested_port = None

    urg_flag = None
    ack_flag = None
    push_flag = None
    reset_flag = None
    syn_flag = None
    fin_flag = None

    icmp_type = None

    arp_opcode = None
    arp_src_ip = None
    arp_dest_ip = None

def get_length_medium(len_api):
    if len_api < 60:
        len_med = 64
    else:
        len_med = len_api + 4
    return len_med


def get_eth_type(hex_value):
    eth_type_dec = int(hex_value[24:28], 16)
    if eth_type_dec > 1500:
        eth = "Ethernet II"
    else:
        eth_type_hex = hex_value[28:30]
        if eth_type_hex == "aa":
            eth = "802.3 LLC + SNAP"
        elif eth_type_hex == "ff":
            eth = "802.3 - raw"
        else:
            eth = "802.3 LLC"
    return eth


def get_mac(hex_v):
    dest = hex_v[0:12]
    src = hex_v[12:24]
    return dest, src


def print_frame(p):
    file.write("\n")
    for u in range(1, len(p.hex_value) + 1):
        if u % 2 == 0:
            file.write(p.hex_value[u - 1] + " ")
            if u % 64 == 0:
                file.write("\n")
            elif u % 32 == 0:
                file.write("  ")
        else:
            file.write(p.hex_value[u - 1])


def start(f):
    f.length_api = len(f.hex_value) // 2
    f.length_med = get_length_medium(f.length_api)

    f.eth_type = get_eth_type(f.hex_value)

    f.dest_mac, frame.src_mac = get_mac(f.hex_value)

    nested_protocols(f)


def read_cfg():
    cfg = configparser.ConfigParser()
    cfg.read('config.cfg')
    return cfg


def ip(ip_hex):
    size = int(ip_hex[1], 16) * 4
    try:
        nested_ip = config.get('IpProtocols', str(int(ip_hex[18: 20], 16)))
    except configparser.NoOptionError:
        nested_ip = None
    src_ip = str(int(ip_hex[24: 26], 16)) + "." + str(int(ip_hex[26: 28], 16)) + "." + str(
        int(ip_hex[28: 30], 16)) + "." + str(int(ip_hex[30: 32], 16))
    ips.append(src_ip)
    dest_ip = str(int(ip_hex[32: 34], 16)) + "." + str(int(ip_hex[34: 36], 16)) + "." + str(
        int(ip_hex[36: 38], 16)) + "." + str(int(ip_hex[38: 40], 16))

    return src_ip, dest_ip, nested_ip, size


def nested_mac(nested_protocol_dec, section):
    try:
        nested = config.get(section, str(nested_protocol_dec))
    except configparser.NoOptionError:
        nested = None
    return nested


def nested_protocols(f):
    if f.eth_type == "Ethernet II":
        f.nested_mac = nested_mac(int(f.hex_value[24:28], 16), 'EtherTypes')
        if int(f.hex_value[24:28], 16) == 2048:
            f.src_ip, f.dest_ip, f.nested_ip, f.size_ip = ip(f.hex_value[28::])
            if f.nested_ip is not None:
                nested_internet(f)

    elif "802.3 LLC" == f.eth_type:
        f.nested_mac = nested_mac(int(f.hex_value[28:30], 16), 'SAPs')

    elif "802.3 - raw" == f.eth_type:
        f.nested_mac = "IPX"

    elif "802.3 LLC + SNAP" == f.eth_type:
        f.nested_mac = nested_mac(int(f.hex_value[40:44], 16), 'EtherTypes')


def nested_internet(f):
    try:
        if f.nested_ip == "TCP":
            f.src_port = int(f.hex_value[(28 + (f.size_ip * 2)): (32 + (f.size_ip * 2))], 16)
            f.dest_port = int(f.hex_value[(32 + (f.size_ip * 2)): (36 + (f.size_ip * 2))], 16)
            tcp_analyze(f)
            f.nested_port = config.get('TCP_ports', str(f.dest_port))
        elif f.nested_ip == "UDP":
            f.src_port = int(f.hex_value[(28 + (f.size_ip * 2)): (32 + (f.size_ip * 2))], 16)
            f.dest_port = int(f.hex_value[(32 + (f.size_ip * 2)): (36 + (f.size_ip * 2))], 16)
            f.nested_port = config.get('UDP_ports', str(f.dest_port))
        elif f.nested_ip == "ICMP":
            icmp_analyze(f)
    except configparser.NoOptionError:
        f.nested_port = None


def three():
    unique, count = [], []

    for ip_ in ips:
        if ip_ not in unique:
            unique.append(ip_)
    count = [0] * len(unique)
    for u in range(len(unique)):
        for ip_old in ips:
            if unique[u] == ip_old:
                count[u] += 1
    file.write("IP adresy vysielajúcich uzlov:")
    for u in unique:
        file.write("\n" + u)
    maximum = max(count)

    file.write("\nAdresa uzla s najväčším počtom odoslaných paketov:\n" + unique[count.index(maximum)] + "\t" + str(maximum))


def tcp_analyze(f):
    flags = str(bin(int(f.hex_value[(53 + (f.size_ip * 2)): (56 + (f.size_ip * 2))], 16)))[2::]
    flags = flags[::-1]
    while len(flags) < 6:
        flags += "0"
    flags = flags[::-1]

    if flags[0] == "1":
        f.urg_flag = True
    if flags[1] == "1":
        f.ack_flag = True
    if flags[2] == "1":
        f.push_flag = True
    if flags[3] == "1":
        f.reset_flag = True
    if flags[4] == "1":
        f.syn_flag = True
        if f.ack_flag is None:
            syns.append(f.index)
    if flags[5] == "1":
        f.fin_flag = True


def icmp_analyze(f):
    icmp_type = str(int(f.hex_value[(28 + (f.size_ip * 2)): (30 + (f.size_ip * 2))], 16))
    try:
        f.icmp_type = config.get('ICMP_types', icmp_type)
    except configparser.NoOptionError:
        f.icmp_type = None


def get_tcp_comms(frms, port):
    syn, sync_ack, ack, datas, socket, out = None, None, None, [], [], []
    for x in syns:
        if frms[x].dest_port == port or frms[x].src_port == port:
            syn = frms[x]

            for u in range(x, len(frms)):
                if (syn.src_ip == frms[u].dest_ip) and (syn.dest_ip == frms[u].src_ip) and (
                        syn.src_port == frms[u].dest_port) and (syn.dest_port == frms[u].src_port):
                    if (frms[u].syn_flag == True) and (frms[u].ack_flag == True):
                        sync_ack = frms[u]

                        break
            for u in range(sync_ack.index + 1, len(frms)):
                if (syn.src_ip == frms[u].src_ip) and (syn.dest_ip == frms[u].dest_ip) and (
                        syn.src_port == frms[u].src_port) and (syn.dest_port == frms[u].dest_port):
                    if frms[u].ack_flag:
                        ack = frms[u]

                        break
            if (syn is not None) and (sync_ack is not None) and (ack is not None):
                socket.append(syn.src_ip)
                socket.append(syn.src_port)
                socket.append(syn.dest_ip)
                socket.append(syn.dest_port)
                for u in range(ack.index + 1, len(frms)):
                    if (frms[u].src_ip in socket) and (frms[u].src_port in socket) and (frms[u].dest_ip in socket) and (
                            frms[u].dest_port in socket):
                        datas.append(frms[u])
                datas = [syn, sync_ack, ack] + datas
                out.append(datas)
                datas = []
                socket = []

    finished, unfinished = None, None
    for m in range(len(out)):
        k = 0
        for n in range(len(out[m])):
            frm = out[m][n]
            if frm.reset_flag == True:
                if finished == None:
                    finished = m
                k = 1
                break
            elif frm.fin_flag == True:
                try:
                    frm2 = out[m][n + 1]
                except IndexError:
                    break
                if frm2.fin_flag == True:
                    try:
                        frm3 = out[m][n + 2]
                    except IndexError:
                        break
                    if frm3.ack_flag == True:  # FIN FIN ACK
                        if finished == None:
                            finished = m
                        k = 1
                        break
                    elif frm3.reset_flag == True:  # FIN FIN RST
                        if finished == None:
                            finished = m
                        k = 1
                        break
                    else:
                        if unfinished == None:
                            unfinished = m
                elif frm2.ack_flag == True:
                    try:
                        frm3 = out[m][n + 2]
                    except IndexError:
                        break
                    if frm3.fin_flag == True:
                        try:
                            frm4 = out[m][n + 3]
                        except IndexError:
                            break
                        if frm4.ack_flag == True:  # FIN ACK FIN ACK
                            if finished == None:
                                finished = m
                            k = 1
                            break
                        elif frm4.reset_flag == True:  # FIN ACK FIN RST
                            if finished == None:
                                finished = m
                            k = 1
                            break
                        else:
                            if unfinished == None:
                                unfinished = m
                    elif frm3.reset_flag == True:  # FIN ACK RST
                        if finished == None:
                            finished = m
                        k = 1
                        break
                    else:
                        if unfinished == None:
                            unfinished = m
                elif frm2.reset_flag == True:  # FIN RST
                    if finished == None:
                        finished = m
                    k = 1
                    break
            if n + 1 == len(out[m]) and k == 0 and unfinished == None:
                unfinished = m
        if unfinished != None and finished != None:
            break

    return out, unfinished, finished


def get_udp_comms(frams):
    start_, response, datas, socket, out = None, None, [], [], []

    for fram in frams:
        if fram.dest_port == 69:
            start_ = fram

            if start_ is not None:
                for u in range(start_.index + 1, len(frams)):
                    if (frams[u].src_ip == start_.dest_ip) and (frams[u].dest_ip == start_.src_ip) and (
                            frams[u].dest_port == start_.src_port):
                        response = frams[u]

                        break
            if response is not None:
                socket.append(start_.src_ip)
                socket.append(start_.src_port)
                socket.append(start_.dest_ip)
                socket.append(response.src_port)
                for u in range(response.index + 1, len(frams)):
                    if (frams[u].src_ip in socket) and (frams[u].src_port in socket) and (
                            frams[u].dest_ip in socket) and (frams[u].dest_port in socket):
                        datas.append(frams[u])

                if len(datas) != 0:
                    datas = [start_, response] + datas

                    out.append(datas)
                    start_, response, datas, socket = None, None, [], []
    return out


def print_tcp(datas, unfin, fin, size):
    if unfin != None:
        file.write("\nUnfinished:")
        if size == "2":
            if len(datas[unfin] > 20):
                datas[unfin] = datas[unfin][0:10] + datas[unfin][-10::]
        for frm in datas[unfin]:
            file.write("\n\n\n" + str(frm.index + 1) + ".: ")
            file.write("\n"+frm.eth_type + ": \n" + "Length API: " + str(
                frm.length_api) + "  Length medium: " + str(
                frm.length_med) + " " + " \nDestination: " +
                  frm.dest_mac[0:2] + ":" + frm.dest_mac[2:4] + ":" + frm.dest_mac[4:6] + ":" +
                  frm.dest_mac[6:8] + ":" +
                  frm.dest_mac[8:10] + ":" + frm.dest_mac[10:12] + "  Source: " +
                  frm.src_mac[0:2] + ":" + frm.src_mac[2:4] + ":" + frm.src_mac[4:6] + ":" +
                  frm.src_mac[6:8] + ":" +
                  frm.src_mac[8:10] + ":" + frm.src_mac[10:12])
            file.write("\n"+frm.nested_mac)
            if frm.src_ip is not None:
                file.write("\nZdrojová IP: " + frm.src_ip + "\nCieľová IP: " + frm.dest_ip)
                if frm.nested_ip is not None:
                    file.write("\n"+frm.nested_ip + "\nZdrojový port: " + str(
                        frm.src_port) + "\nCieľový port: " + str(frm.dest_port))
                    if frm.nested_port is not None:
                        file.write("\n"+frm.nested_port+"\n")

            if frm.ack_flag == True:
                file.write("ACK ")
            if frm.push_flag == True:
                file.write("PUSH ")
            if frm.reset_flag == True:
                file.write("RESET ")
            if frm.syn_flag == True:
                file.write("SYN ")
            if frm.fin_flag == True:
                file.write("FIN ")
            file.write("\n")
            print_frame(frm)

    if fin != None:
        if size == "2":
            if len(datas[fin] > 20):
                datas[fin] = datas[fin][0:10] + datas[fin][-10::]
        file.write("\nFinished:")
        for frm in datas[fin]:
            file.write("\n\n\n" + str(frm.index + 1) + ".: ")
            file.write("\n"+frm.eth_type + ": \n" + "Length API: " + str(
                frm.length_api) + "  Length medium: " + str(
                frm.length_med) + " " + " \nDestination: " +
                  frm.dest_mac[0:2] + ":" + frm.dest_mac[2:4] + ":" + frm.dest_mac[4:6] + ":" +
                  frm.dest_mac[6:8] + ":" +
                  frm.dest_mac[8:10] + ":" + frm.dest_mac[10:12] + "  Source: " +
                  frm.src_mac[0:2] + ":" + frm.src_mac[2:4] + ":" + frm.src_mac[4:6] + ":" +
                  frm.src_mac[6:8] + ":" +
                  frm.src_mac[8:10] + ":" + frm.src_mac[10:12])
            file.write("\n"+frm.nested_mac)
            if frm.src_ip is not None:
                file.write("\nZdrojová IP: " + frm.src_ip + "\nCieľová IP: " + frm.dest_ip)
                if frm.nested_ip is not None:
                    file.write("\n"+frm.nested_ip + "\nZdrojový port: " + str(
                        frm.src_port) + "\nCieľový port: " + str(frm.dest_port)+"\n")
                    if frm.nested_port is not None:
                        file.write(frm.nested_port+"\n")

            if frm.ack_flag == True:
                file.write("ACK ")
            if frm.push_flag == True:
                file.write("PUSH ")
            if frm.reset_flag == True:
                file.write("RESET ")
            if frm.syn_flag == True:
                file.write("SYN ")
            if frm.fin_flag == True:
                file.write("FIN ")
            print("\n")
            print_frame(frm)


def get_icmp(frms, siz):
    k = 0
    icmp = []
    sockets = []
    if len(frms) != 0:
        for frm in frms:
            if frm.nested_ip == "ICMP":
                if [frm.src_ip, frm.dest_ip] not in sockets and [frm.dest_ip, frm.src_ip] not in sockets:
                    sockets.append([frm.src_ip, frm.dest_ip])

        for socket in sockets:
            data_ = []
            for frm in frms:
                if frm.nested_ip == "ICMP":
                    if frm.src_ip in socket and frm.dest_ip in socket:
                        data_.append(frm)
            icmp.append(data_)

        for dat in icmp:
            file.write("\n\n\nKomunikácia " + str(icmp.index(dat) + 1))
            if siz == "2" and len(dat) > 20:
                dat = dat[0:10] + ["None"] + dat[-10::]
            for frm in dat:

                if frm == "None":
                    file.write("\n...\n")
                file.write("\n\n\n\n\n" + str(frm.index + 1) + ":\n" + frm.eth_type + ": \n" + "Length API: " + str(
                    frm.length_api) + "  Length medium: " + str(
                    frm.length_med) + " " + " \nDestination: " +
                      frm.dest_mac[0:2] + ":" + frm.dest_mac[2:4] + ":" + frm.dest_mac[4:6] + ":" +
                      frm.dest_mac[6:8] + ":" +
                      frm.dest_mac[8:10] + ":" + frm.dest_mac[10:12] + "  Source: " +
                      frm.src_mac[0:2] + ":" + frm.src_mac[2:4] + ":" + frm.src_mac[4:6] + ":" +
                      frm.src_mac[6:8] + ":" +
                      frm.src_mac[8:10] + ":" + frm.src_mac[10:12])
                file.write("\n"+frm.nested_mac)

                if frm.icmp_type is not None:
                    file.write(
                        "\nZdrojová IP adresa: " + frm.src_ip + "\nCieľová IP adresa: " + frm.dest_ip + "\nICMP\nICMP typ: " + frm.icmp_type)
                    if len(frm.hex_value) > 1500:
                        k = 1
                elif k == 1:
                    k = 0
                    file.write(
                        "\nZdrojová IP adresa: " + frm.src_ip + "\nCieľová IP adresa: " + frm.dest_ip + "\nICMP\nICMP typ: Fragmentovane data ku predošlému ICMP")
                print_frame(frm)
            file.write("\n\n\nKoniec komunikácie " + str(icmp.index(dat) + 1))


def print_udp(datas, all_, siz):
    if len(datas) != 0:
        if all_ == "0":
            if siz == "2" and len(datas[0]) > 20:
                datas[0] = datas[0][0:10] + ["None"] + datas[0][-10::]
            for frm in datas[0]:
                if frm == "None":
                    file.write("\n...\n")
                else:
                    file.write("\n\n" + str(frm.index + 1) + ".: ")
                    file.write("\n"+frm.eth_type + ": \n" + "Length API: " + str(
                        frm.length_api) + "  Length medium: " + str(
                        frm.length_med) + " " + " \nDestination: " +
                          frm.dest_mac[0:2] + ":" + frm.dest_mac[2:4] + ":" + frm.dest_mac[4:6] + ":" +
                          frm.dest_mac[6:8] + ":" +
                          frm.dest_mac[8:10] + ":" + frm.dest_mac[10:12] + "  Source: " +
                          frm.src_mac[0:2] + ":" + frm.src_mac[2:4] + ":" + frm.src_mac[4:6] + ":" +
                          frm.src_mac[6:8] + ":" +
                          frm.src_mac[8:10] + ":" + frm.src_mac[10:12])
                    file.write("\n"+frm.nested_mac)
                    if frm.src_ip is not None:
                        file.write("\nZdrojová IP: " + frm.src_ip + "\nCieľová IP: " + frm.dest_ip)
                        if frm.nested_ip is not None:
                            file.write("\n"+frm.nested_ip + "\nZdrojový port: " + str(
                                frm.src_port) + "\nCieľový port: " + str(frm.dest_port))
                            if frm.nested_port is not None:
                                file.write("\n"+frm.nested_port)
        elif all_ == "1":
            t = 0
            for dat in datas:
                if siz == "2" and len(dat) > 20:
                    dat = dat[0:10] + ["None"] + dat[-10::]
                t += 1
                file.write("\n\n" + str(t) + "komunikácia:")
                for frm in dat:
                    if frm == "None":
                        file.write("\n...\n")
                    else:
                        file.write("\n\n" + str(frm.index + 1) + ".: ")
                        file.write("\n"+frm.eth_type + ": \n" + "Length API: " + str(
                            frm.length_api) + "  Length medium: " + str(
                            frm.length_med) + " " + " \nDestination: " +
                              frm.dest_mac[0:2] + ":" + frm.dest_mac[2:4] + ":" + frm.dest_mac[4:6] + ":" +
                              frm.dest_mac[6:8] + ":" +
                              frm.dest_mac[8:10] + ":" + frm.dest_mac[10:12] + "  Source: " +
                              frm.src_mac[0:2] + ":" + frm.src_mac[2:4] + ":" + frm.src_mac[4:6] + ":" +
                              frm.src_mac[6:8] + ":" +
                              frm.src_mac[8:10] + ":" + frm.src_mac[10:12])
                        file.write("\n"+frm.nested_mac)
                        if frm.src_ip is not None:
                            file.write("\nZdrojová IP: " + frm.src_ip + "\nCieľová IP: " + frm.dest_ip)
                            if frm.nested_ip is not None:
                                file.write("\n"+frm.nested_ip + "\nZdrojový port: " + str(
                                    frm.src_port) + "\nCieľový port: " + str(frm.dest_port))
                                if frm.nested_port is not None:
                                    file.write("\n"+frm.nested_port)
                        print_frame(frm)
                file.write("\n\nKoniec komunikácie" + str(t))


def analyze_arp(frams, siz):
    arps = []
    pairs = []
    unpaired = []

    for r in range(len(frams)):
        frm = frams[r]
        if frm.nested_mac == "ARP":
            arps.append(frm)

    while len(arps) > 0:
        z = 0
        frm = arps[0]
        socket = []
        pair = []
        frm.arp_src_ip = str(int(frm.hex_value[56: 58], 16)) + "." + str(int(frm.hex_value[58: 60], 16)) + "." + str(
            int(frm.hex_value[60: 62], 16)) + "." + str(int(frm.hex_value[62: 64], 16))
        frm.arp_dest_ip = str(int(frm.hex_value[76: 78], 16)) + "." + str(int(frm.hex_value[78: 80], 16)) + "." + str(
                int(frm.hex_value[80: 82], 16)) + "." + str(int(frm.hex_value[82: 84], 16))
        frm.arp_opcode = int(frm.hex_value[40:44], 16)


        for t in range(len(pairs)):
            if frm.hex_value == pairs[t][0].hex_value:
                pairs[t] = [frm] + pairs[t]
                arps.remove(frm)
                z = 1
            elif frm.hex_value == pairs[t][-
            1].hex_value:
                pairs[t].append(frm)
                arps.remove(frm)
                z = 1
        if z == 0:
            if len(arps) == 1:
                unpaired.append(frm)
                arps.remove(frm)
            elif frm.arp_opcode == 1:
                socket.append(frm.src_mac)
                socket.append(frm.arp_src_ip)
                socket.append(frm.arp_dest_ip)
                for t in range(1, len(arps)):
                    next = arps[t]
                    response = int(next.hex_value[40:44], 16)
                    next_src_ip = str(int(next.hex_value[56: 58], 16)) + "." + str(
                        int(next.hex_value[58: 60], 16)) + "." + str(
                        int(next.hex_value[60: 62], 16)) + "." + str(int(next.hex_value[62: 64], 16))
                    next_dest_ip = str(int(next.hex_value[76: 78], 16)) + "." + str(
                        int(next.hex_value[78: 80], 16)) + "." + str(
                        int(next.hex_value[80: 82], 16)) + "." + str(int(next.hex_value[82: 84], 16))
                    if response == 2 and next.dest_mac in socket and next_src_ip in socket and next_dest_ip in socket:
                        pair = [frm, next]
                        next.arp_src_ip = next_src_ip
                        next.arp_dest_ip = next_dest_ip
                        next.arp_opcode = response
                        arps.remove(frm)
                        arps.remove(next)
                        pairs.append(pair)
                        break
                    elif t + 1 == len(arps):
                        unpaired.append(frm)
                        arps.remove(frm)
                        continue
                    else:
                        continue
                if len(arps) == 0:
                    break
            elif frm.arp_opcode == 2:
                socket.append(frm.dest_mac)
                socket.append(frm.arp_src_ip)
                socket.append(frm.arp_dest_ip)
                for t in range(1, len(arps)):
                    next = arps[t]
                    response = int(next.hex_value[40:44], 16)
                    next_src_ip = str(int(next.hex_value[56: 58], 16)) + "." + str(
                        int(next.hex_value[58: 60], 16)) + "." + str(
                        int(next.hex_value[60: 62], 16)) + "." + str(int(next.hex_value[62: 64], 16))
                    next_dest_ip = str(int(next.hex_value[76: 78], 16)) + "." + str(
                        int(next.hex_value[78: 80], 16)) + "." + str(
                        int(next.hex_value[80: 82], 16)) + "." + str(int(next.hex_value[82: 84], 16))
                    if response == 1 and next.src_mac in socket and next_src_ip in socket and next_dest_ip in socket:
                        pair = [next, frm]
                        next.arp_src_ip = next_src_ip
                        next.arp_dest_ip = next_dest_ip
                        next.arp_opcode = response
                        arps.remove(frm)
                        arps.remove(next)
                        pairs.append(pair)
                        break
                    elif t + 1 == len(arps):
                        unpaired.append(frm)
                        arps.remove(frm)
                        continue
                    else:
                        continue
                if len(arps) == 0:
                    break


    for t in range(len(pairs)):
        g = 0
        file.write("\nPár " + str(t + 1))
        file.write("\n\nARP-Request, Cieľová IP Adresa: " + pairs[t][g].arp_dest_ip + " MAC Adresa: ??\nZdrojová IP: " + pairs[t][g].arp_src_ip)

        while pairs[t][g].arp_opcode == 1:
            file.write("\n\n\n" + str(pairs[t][g].index + 1) + ".: ")
            file.write("\n"+pairs[t][g].eth_type + ": \n" + "Length API: " + str(
                pairs[t][g].length_api) + "  Length medium: " + str(
                pairs[t][g].length_med) + " " + " \nDestination: " +
                  pairs[t][g].dest_mac[0:2] + ":" + pairs[t][g].dest_mac[2:4] + ":" + pairs[t][g].dest_mac[4:6] + ":" +
                  pairs[t][g].dest_mac[6:8] + ":" +
                  pairs[t][g].dest_mac[8:10] + ":" + pairs[t][g].dest_mac[10:12] + "  Source: " +
                  pairs[t][g].src_mac[0:2] + ":" + pairs[t][g].src_mac[2:4] + ":" + pairs[t][g].src_mac[4:6] + ":" +
                  pairs[t][g].src_mac[6:8] + ":" +
                  pairs[t][g].src_mac[8:10] + ":" + pairs[t][g].src_mac[10:12])
            file.write("\n"+pairs[t][g].nested_mac)
            file.write("\nZdrojová IP: "+pairs[t][g].arp_src_ip+" Cieľová IP: "+pairs[t][g].arp_dest_ip)
            print_frame(pairs[t][g])
            g += 1
        file.write("\n\n\nARP-Reply, Cieľová IP Adresa: " + pairs[t][g].arp_dest_ip + "MAC Adresa: " + pairs[t][g].src_mac+"\nZdrojová IP: " + pairs[t][
            g].arp_src_ip)
        while pairs[t][g].arp_opcode == 2:
            file.write("\n\n\n" + str(pairs[t][g].index + 1) + ".: ")
            file.write("\n"+pairs[t][g].eth_type + ": \n" + "Length API: " + str(
                pairs[t][g].length_api) + "  Length medium: " + str(
                pairs[t][g].length_med) + " " + " \nDestination: " +
                  pairs[t][g].dest_mac[0:2] + ":" + pairs[t][g].dest_mac[2:4] + ":" + pairs[t][g].dest_mac[4:6] + ":" +
                  pairs[t][g].dest_mac[6:8] + ":" +
                  pairs[t][g].dest_mac[8:10] + ":" + pairs[t][g].dest_mac[10:12] + "  Source: " +
                  pairs[t][g].src_mac[0:2] + ":" + pairs[t][g].src_mac[2:4] + ":" + pairs[t][g].src_mac[4:6] + ":" +
                  pairs[t][g].src_mac[6:8] + ":" +
                  pairs[t][g].src_mac[8:10] + ":" + pairs[t][g].src_mac[10:12])
            file.write("\n"+pairs[t][g].nested_mac)
            file.write("\nZdrojová IP: " + pairs[t][g].arp_src_ip + " Cieľová IP: " + pairs[t][g].arp_dest_ip)
            print_frame(pairs[t][g])
            if g + 1 == len(pairs[t]):
                break
            else:
                g += 1
        file.write("\n\n\nKoniec páru " + str(t + 1))

    if siz == "2" and len(unpaired) > 20:
        unpaired = unpaired[0:10] + ["None"] + unpaired[-10::]
    if len(unpaired) != 0:
        file.write("\n\n\nNespárované ARP pakety:")
        for frm in unpaired:
            if frm == "None":
                file.write("\n...\n")
            else:
                file.write("\n\n\n" + str(frm.index + 1) + ".: ")
                file.write("\n"+frm.eth_type + ": \n" + "Length API: " + str(
                    frm.length_api) + "  Length medium: " + str(
                    frm.length_med) + " " + " \nDestination: " +
                      frm.dest_mac[0:2] + ":" + frm.dest_mac[2:4] + ":" + frm.dest_mac[4:6] + ":" +
                      frm.dest_mac[6:8] + ":" +
                      frm.dest_mac[8:10] + ":" + frm.dest_mac[10:12] + "  Source: " +
                      frm.src_mac[0:2] + ":" + frm.src_mac[2:4] + ":" + frm.src_mac[4:6] + ":" +
                      frm.src_mac[6:8] + ":" +
                      frm.src_mac[8:10] + ":" + frm.src_mac[10:12] + "\n")
                file.write(frm.nested_mac)
                file.write("\nZdrojová IP: " + frm.arp_src_ip + " Cieľová IP: " + frm.arp_dest_ip)
                if frm.arp_opcode == 1:
                    file.write("\nARP-Request")
                elif frm.arp_opcode == 2:
                    file.write("\nARP-Reply")
                print_frame(frm)



if __name__ == '__main__':
    y = 0
    global pcap, config, ips, syns, file
    inp = input("Zadaj meno súboru (bez prípony): ")
    pcap = scapy.rdpcap(inp+".pcap")
    config = read_cfg()
    ips = []
    frames = []
    syns = []

    for pkt in pcap:
        frame = Frame()

        frame.hex_value = scapy.raw(pkt).hex()
        frame.index = y
        y += 1

        start(frame)
        frames.append(frame)

    print("Subor je kompletne analyzovany. Aku moznost si prajes zvolit?")
    menu = None
    while menu != "-1":

        menu = input(
            "\n\n1 - vypis celeho bodu 1 (dlzky, MAC adresy)\n2 - vypis celeho bodu 2 (vsetky vnutorne protokoly a ich detaily)"
            "\n3 - tabulka IP vysielajuch IP adries\n4 - jednotlive vypisy pre bod 4\n5 - zadaj cislo ramcu a vypis vsetko o nom\n-1 - koniec\nZvol si moznost:")
        file = open("output.txt", "w")
        if menu == "1":
            for i in range(len(frames)):
                file.write("\n\n\n" + str(i + 1) + ".: ")
                file.write(frames[i].eth_type + ": \n" + "Length API: " + str(
                    frames[i].length_api) + "  Length medium: " + str(
                    frames[i].length_med) + " " + " \nDestination: " +
                           frames[i].dest_mac[0:2] + ":" + frames[i].dest_mac[2:4] + ":" + frames[i].dest_mac[4:6] + ":" +
                           frames[i].dest_mac[6:8] + ":" +
                           frames[i].dest_mac[8:10] + ":" + frames[i].dest_mac[10:12] + "  Source: " +
                           frames[i].src_mac[0:2] + ":" + frames[i].src_mac[2:4] + ":" + frames[i].src_mac[4:6] + ":" +
                           frames[i].src_mac[6:8] + ":" +
                           frames[i].src_mac[8:10] + ":" + frames[i].src_mac[10:12])
                print_frame(frames[i])

        elif menu == "2":
            for i in range(len(frames)):
                file.write("\n\n\n" + str(i + 1) + ".: ")
                file.write(frames[i].eth_type + ": \n" + "Length API: " + str(
                    frames[i].length_api) + "  Length medium: " + str(
                    frames[i].length_med) + " " + " \nDestination: " +
                           frames[i].dest_mac[0:2] + ":" + frames[i].dest_mac[2:4] + ":" + frames[i].dest_mac[
                                                                                           4:6] + ":" +
                           frames[i].dest_mac[6:8] + ":" +
                           frames[i].dest_mac[8:10] + ":" + frames[i].dest_mac[10:12] + "  Source: " +
                           frames[i].src_mac[0:2] + ":" + frames[i].src_mac[2:4] + ":" + frames[i].src_mac[4:6] + ":" +
                           frames[i].src_mac[6:8] + ":" +
                           frames[i].src_mac[8:10] + ":" + frames[i].src_mac[10:12])
                file.write("\n" + frames[i].nested_mac)
                if frames[i].src_ip is not None:
                    file.write("\n" + "Zdrojová IP: " + frames[i].src_ip + "\nCieľová IP: " + frames[i].dest_ip)
                    if frames[i].nested_ip is not None:
                        file.write("\n" + frames[i].nested_ip + "\nZdrojový port: " + str(
                            frames[i].src_port) + "\nCieľový port: " + str(frames[i].dest_port))
                        if frames[i].nested_port is not None:
                            file.write("\n" + frames[i].nested_port)
                print_frame(frames[i])

        elif menu == "3":
            if len(ips) != 0:
                three()

        elif menu == "4":
            prot = input("Bod (a-i): ")
            size = input("Celá/skrátená? (1/2)")
            if prot == "a":
                if len(syns) != 0:
                    prot = 80
                    data, finished, unfinished = get_tcp_comms(frames, prot)
                    print_tcp(data, finished, unfinished, size)
            elif prot == "b":
                if len(syns) != 0:
                    prot = 443
                    data, finished, unfinished = get_tcp_comms(frames, prot)
                    print_tcp(data, finished, unfinished, size)
            elif prot == "c":
                if len(syns) != 0:
                    prot = 23
                    data, finished, unfinished = get_tcp_comms(frames, prot)
                    print_tcp(data, finished, unfinished, size)
            elif prot == "d":
                if len(syns) != 0:
                    prot = 22
                    data, finished, unfinished = get_tcp_comms(frames, prot)
                    print_tcp(data, finished, unfinished, size)
            elif prot == "e":
                if len(syns) != 0:
                    prot = 21
                    data, finished, unfinished = get_tcp_comms(frames, prot)
                    print_tcp(data, finished, unfinished, size)
            elif prot == "f":
                if len(syns) != 0:
                    prot = 20
                    data, finished, unfinished = get_tcp_comms(frames, prot)
                    print_tcp(data, finished, unfinished, size)
            elif prot == "g":
                all = input("Len prvú alebo všetky? (0/1)")
                data = get_udp_comms(frames)
                print_udp(data, all, size)
            elif prot == "h":
                get_icmp(frames, size)
            elif prot == "i":
                analyze_arp(frames, size)
        elif menu == "5":
            i = int(input("Zadaj cislo: ")) - 1
            file.write("\n\n\n" + str(i + 1) + ".: ")
            file.write(frames[i].eth_type + ": \n" + "Length API: " + str(
                frames[i].length_api) + "  Length medium: " + str(
                frames[i].length_med) + " " + " \nDestination: " +
                       frames[i].dest_mac[0:2] + ":" + frames[i].dest_mac[2:4] + ":" + frames[i].dest_mac[4:6] + ":" +
                       frames[i].dest_mac[6:8] + ":" +
                       frames[i].dest_mac[8:10] + ":" + frames[i].dest_mac[10:12] + "  Source: " +
                       frames[i].src_mac[0:2] + ":" + frames[i].src_mac[2:4] + ":" + frames[i].src_mac[4:6] + ":" +
                       frames[i].src_mac[6:8] + ":" +
                       frames[i].src_mac[8:10] + ":" + frames[i].src_mac[10:12])
            file.write("\n"+frames[i].nested_mac)
            if frames[i].src_ip is not None:
                file.write("\n" +"Zdrojová IP: " + frames[i].src_ip + "\nCieľová IP: " + frames[i].dest_ip)
                if frames[i].nested_ip is not None:
                    file.write("\n" + frames[i].nested_ip + "\nZdrojový port: " + str(
                        frames[i].src_port) + "\nCieľový port: " + str(frames[i].dest_port))
                    if frames[i].nested_port is not None:
                        file.write("\n" + frames[i].nested_port)
            print_frame(frames[i])

        file.close()
