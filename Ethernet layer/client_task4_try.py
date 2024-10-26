#client_IP_file.py
import os
import time
import random 

DNS_channel = 'DNS4.txt'
client_log = 'client_task4_log.txt'
server_log = 'server_task4_log.txt'
client_ip = "192.168.1.5"
server_ip =" "
client_mac = "02:1A:2B:3C:4D:5E"
server_mac =" "
DNS_ip = "1.1.1.1"
last_seq_no=0
last_ack_no=0
open(client_log,'w')
open(DNS_channel,'a').close()

# DNS simulation function, it defines fields of DNS segment and send DNS lookup to DNS and receives the response.
def DNS_lookup(domain_name,request_number):
    template = (
    " Identification: {identification} |"
    " Flags: {flag} |"
    " Question count: {question_count} |"
    " Answer count: {answer_count} |"
    " Authority record count: {auth_count} |" 
    " Additional record count: {addition_count} |"
    " Name: {name} |"
    " Type : {request_type} |"
    " Class : {classs}"
    )
    iden = random.randint(0, 65535)
    formatted_string = template.format(
    identification = iden,
    flag = "DNS lookup request",
    question_count = 1,
    answer_count = 0,
    auth_count = 0,
    addition_count = 0,
    name = domain_name,
    request_type = "IPv4",
    classs = "Internet"
    )
    IP_DNS = log_tcp_to_IP("DNS",formatted_string,DNS_ip,random.randint(0, 65535),0,"000")
    with open(client_log, 'a') as log:
        log.write("Event: sent a " + (request_number) + " DNS lookup request\n")
        log.write(IP_DNS)
        log.write("\n")
        log.write("\n")
        log.flush()
    print("Sent a DNS lookup request")
    time.sleep(3)
    # reads the response from the DNS of the requested IP
    with open(server_log,'r') as log:
        lines =log.readlines()
        global server_ip
        server_ip = lines[-2].split("Address :")[1].strip()
    print("Received the requested IP")
    

# defines the ARP segment with all its fields and returns the formatted ARP segment
def ARP_packet(IP_target,target_mac): 
    template = (
    " Hardware type: {hardware_type} |"
    " Protocol type: {protocol_type} |"
    " Hardware size: {hardware_size} |"
    " Protocol size: {protocol_size} |"
    " Opcode: {opcode} |"
    " Sender Mac: {sender_mac} |"
    " Sender IP: {sender_IP} |"
    " Target Mac: {target_mac} |"
    " Target IP: {target_IP}"
    )
    formatted_string = template.format(
    hardware_type = "Ethernet (1)",
    protocol_type = "IPv4",
    hardware_size = 6,
    protocol_size = 4,
    opcode = "Request (1)",
    sender_mac = client_mac,
    sender_IP = client_ip,
    target_mac = target_mac,
    target_IP = IP_target
    )
    return formatted_string

# encapsulates the ARP segment in ethernet and sends it and waits for the response that contain the requested MAC address
def ARP_broadcast(ip):
    ARP_request = ARP_packet(ip,"00:00:00:00:00:00")
    ether_ARP = log_IP_to_ethernet("ARP",ARP_request,"ff:ff:ff:ff:ff:ff")
    with open(client_log,'a') as log:
        log.write("Event: Sent an ARP request to get the Server Mac address\n")
        log.write(ether_ARP)
        log.write("\n")
        log.write("\n")
        log.flush()
        print("Rent an ARP broadcast")

    # reads the response from the server of the requested MAC address
    time.sleep(5)
    with open(server_log,'r') as log:
        lines = log.readlines()
        global server_mac
        server_mac = lines[-2].split("Sender Mac:")[1].split("|")[0].strip()
        print("Recieved the server MAC address")

# defines the Ethernet frame with all its fields and return the formatted Ethernet frame with the IP encapsulated inside its payload 
def log_IP_to_ethernet(type_ether,IP_log,destination_mac):
    template = (
    "Destination MAC: {Mac_destination} |"
    " Source Mac: {MAC_source} |"
    " EtherType: {ether_type} |"
    " {data} |"
    " CRC: {CRC}"
    )  
    if type_ether == "IPv4":
        prot = "  IP DATAGRAM //"
    else:
        prot = "  ARP REQUEST //"
    formatted_string = template.format(
        Mac_destination = destination_mac,
        MAC_source = client_mac,
        ether_type = type_ether,
        data= prot + IP_log + "//",
        CRC = str(random.randint(0,4294967295))
    )
    return formatted_string

# defines the IP datagram with all its fields and return the formatted IP datagram
def log_tcp_to_IP(protocol,tcp_log,destination_IP,identification,frag_offset,flag):
    template = (
    " Version: {version} |"
    " Length: {header_len} |"
    " Type of service: {type_of_service} |"
    " Total length: {total_len} |"
    " Identifier: {identifier} |"
    " Flags: {flag} |"
    " Fragmented offset: {fragmentation_offset} |"
    " TTL: {TTL} |"
    " Protocol: {protocol} |"
    " Checksum: {checksum} |"
    " Source IP: {source_IP} |"
    " Destination IP: {IP_destination} |"
    " Options: {options} |"
    " {data} "
    )
    if protocol == "TCP":
        prot = "  TCP SEGMENT // "
    else:
        prot = "  DNS REQUEST // "
    formatted_string = template.format(
    version="IPv4",
    type_of_service="0",
    identifier=str(identification),
    flag=flag,
    fragmentation_offset=frag_offset,
    TTL="255",
    protocol=protocol,
    checksum=str(random.randint(0, 65535)),
    source_IP=client_ip,
    IP_destination=destination_IP,
    options="0",
    data=prot + tcp_log,
    header_len=int(20 / 4), #the header length is 20 bytes because it doesnt use the options field, it is divided by 4 because it is measured in 32 bit words
    total_len= int(20 + len(tcp_log)) # header lengthis 20 because options are not used and is added to len of data
    )
    return formatted_string

# given a tcp segment, it divides it to be carried as a payload on multiple IP datagrams. it returns the IP datagrams that is carrying the payload
def fragment_IP(tcp_segment,client_ip,identification,IP_header_len):
    IP_datagrams = []
    datagram_size = 750 - IP_header_len
    tcp = [tcp_segment[i:i + datagram_size] for i in range(0 , len(tcp_segment) , datagram_size)]
    cumulative_frag = 0
    for i, tcp_data in enumerate(tcp):
        if (len(tcp_data) < datagram_size):
            IP_datagram = log_tcp_to_IP("TCP",tcp_data,client_ip,identification,cumulative_frag,"000")
            IP_datagrams.append(IP_datagram)
        if (len(tcp_data) == datagram_size):
            IP_datagram = log_tcp_to_IP("TCP",tcp_data,client_ip,identification,cumulative_frag,"001")
            IP_datagrams.append(IP_datagram)
        cumulative_frag += int(len(tcp_data)/8) #measured in 8 bytes
    return IP_datagrams

# used in simulating the 3 way connection handshake, it sends an Ethernet frame with the syn flag, then receives an Ethernet frame with the SYN-ACK flag from the server and acknowledges it by an Ethernet frame.
def simulate_handshake():
    initial_seq= random.randint(0, 4294967296)
    identification = random.randint(0, 65535)
    log_request = log_tcp_segment(initial_seq,0,"SYN","NONE")
    trial_log_IP_datagram = log_tcp_to_IP("TCP",log_request,server_ip,identification,0,"000")
    with open(client_log,'a') as log:
        log.write("Event: Sent a Ethernet frame With SYN flag on\n")
        log.flush()
    if (len(trial_log_IP_datagram) > 750):
        IP_header_len = len(trial_log_IP_datagram) - len(log_request)
        IP_datagrams = fragment_IP(log_request,server_ip,identification,IP_header_len)
        for datagram in IP_datagrams:
            log_Eth_datagram= log_IP_to_ethernet("IPv4",datagram,server_mac)
            with open(client_log,'a') as log:
                log.write(log_Eth_datagram)
                log.write("\n")
                log.flush()
    else:
        log_Eth_datagram= log_IP_to_ethernet("IPv4",trial_log_IP_datagram,server_mac)
        with open(client_log,'a') as log:
            log.write(log_Eth_datagram)
            log.write("\n")
            log.flush()
    print("Sent a Ethernet frame containing a SYN")

    time.sleep(6)
    # reads the Ethernet frame containing the SYN-ACK flag received from the server and send an Ethernet frame to acknowledge and start the connection
    with open(server_log, 'r') as file:
        lines = file.readlines()
        if lines:
            flag = lines[-1].split("|")[-7].split(":")[1].strip()
            if flag == "SYN-ACK":
                seq_no = lines[-1].split("|")[-9].split(":")[1].strip()
                ack_no=int(lines[-1].split("|")[-10].split(":")[1].strip()) +1
                identification=random.randint(0, 65535)
                log_request= log_tcp_segment(seq_no ,ack_no,"ACK","NONE")
                trial_log_IP_datagram = log_tcp_to_IP("TCP",log_request,server_ip,identification,0,"000")
                with open(client_log,'a') as log:
                    log.write("\n")
                    log.write("Event: Recieved an Ethernet frame with SYN-ACK flag on and sent an Ethernet frame with ACK flag on to acknowledge it\n")
                    log.flush()
                if (len(trial_log_IP_datagram)>750):
                    IP_header_len = len(trial_log_IP_datagram) - len(log_request)
                    IP_datagrams = fragment_IP(log_request,server_ip,identification,IP_header_len)
                    for datagrams in IP_datagrams:
                        log_Eth_datagram= log_IP_to_ethernet("IPv4",datagram,server_mac)
                        with open(client_log,'a') as log:
                            log.write(log_Eth_datagram)
                            log.write("\n")
                            log.flush()
                else:
                    log_Eth_datagram= log_IP_to_ethernet("IPv4",trial_log_IP_datagram,server_mac)
                    with open(client_log,'a') as log:
                        log.write(log_Eth_datagram)
                        log.write("\n")
                        log.flush()
                print("Received an Ethernet frame including SYN-ACK and sent an Ethernet frame including ACK")
                global last_seq_no
                global last_ack_no
                last_seq_no = seq_no
                last_ack_no = ack_no
                

# defines the tcp segment with all its fields and return the formatted tcp segment
def log_tcp_segment(sequence_no,acknowledgment_no,wanted_flag,payload):
    template = (
    " Source Port: {source_port} |"
    " Destination Port: {dest_port} |"
    " Sequence number: {seq_no} |"
    " Acknowledgement number: {ack_no} |"
    " Dataoffset: {data_offset} |"
    " Control Flags: {flag} |"
    " Window size: {window_size} |"
    " Checksum: {checksum} |"
    " Urg pointer: {urg_pointer} |"
    " Options: {options} |"
    " {data} "
    )
    formatted_string = template.format(
    source_port = 8080,
    dest_port = 80,
    seq_no = sequence_no,
    ack_no = acknowledgment_no,
    flag = wanted_flag,
    window_size = 65535,
    checksum = random.randint(0, 65535),
    urg_pointer = 0,
    options = 0,
    data = payload,
    data_offset=int(20 / 4 )# header length is equal 20 bytes because options field is not used, and divided by 4 because it is measured in 32 bit words
    )
    return formatted_string

# sends an Ethernet frame carrying the http request, receives the http response from server, reassembles the Ethernet frames back if response is sent on multiple fragments, and send an acknowledgment to the server
def send_request(method,path,previous_seq_no,previous_ack_no,request_number):
    data = f"{method} {path.split('/')[1]} HTTP/1.1 Host: {path.split('/')[0]}"
    identification = random.randint(0, 65535)
    log_request = log_tcp_segment(previous_seq_no,previous_ack_no -1 + len(data),"PSH-ACK",data)
    trial_log_IP_datagram = log_tcp_to_IP("TCP",log_request,server_ip,identification,0,"000")
    with open(client_log,'a') as log: 
        log.write("\n")
        log.write("Event: Sent a " + (request_number) +" Ethernet frame that has the HTTP request\n")
        log.flush()
    if (len(trial_log_IP_datagram) > 750):
        IP_header_len = len(trial_log_IP_datagram) - len(log_request)
        IP_datagrams = fragment_IP(log_request,server_ip,identification,IP_header_len)
        for datagrams in IP_datagrams:
            log_Eth_datagram= log_IP_to_ethernet("IPv4",datagram,server_mac)
            with open(client_log,'a') as log:
                log.write(log_Eth_datagram)
                log.write("\n")
                log.flush()
    else:    
        log_Eth_datagram= log_IP_to_ethernet("IPv4",trial_log_IP_datagram,server_mac)
        with open(client_log,'a') as log: 
            log.write(log_Eth_datagram)
            log.write("\n")
            log.flush()
    print("Sent an Ethernet datagram including an HTTP request")

    time.sleep(6)
    #read the HTTP response sent by the server, reassembles it back if fragmented, and sends an Ethernet frame with ACK flag to confirm it
    with open(server_log,'r') as file:
        lines = file.readlines()
        if lines:
            lines_string = ' '.join(lines)
            reassembled_tcp =[]
            fragments_list=lines_string.split("Event: Ethernet frame holding " + (request_number) +" data")[1:]
            for datagram in fragments_list:
                reassembled_tcp.append((datagram.split("  TCP SEGMENT // ")[1].split("///")[0]).strip())          
            flag = reassembled_tcp[0].split("|")[5].split(":")[1].strip()
            if flag == "PSH-ACK":
                seq_no = reassembled_tcp[0].split("|")[3].split(":")[1].strip()
                ack_no = int(reassembled_tcp[0].split("|")[2].split(":")[1].strip()) + 1
                identification = random.randint(0, 65535)
                log_request = log_tcp_segment(seq_no,ack_no,"ACK","NONE")
                trial_log_IP_datagram= log_tcp_to_IP("TCP",log_request,server_ip,identification,0,"000")
                with open(client_log ,'a') as log:
                    log.write("\n")
                    log.write("Event: Recieved a response for " + (request_number) + " and sent an Ethernet frame with the ACK flag on to acknowledge it\n")
                    log.flush()
                if (len(trial_log_IP_datagram) > 750):
                    IP_header_len = len(trial_log_IP_datagram) - len(log_request)
                    IP_datagrams = fragment_IP(log_request,server_ip,identification,IP_header_len)
                    for datagrams in IP_datagrams:
                        log_Eth_datagram= log_IP_to_ethernet("IPv4",datagram,server_mac)
                        with open(client_log,'a') as log:
                            log.write(log_Eth_datagram)
                            log.write("\n")
                            log.flush()
                else:
                    log_Eth_datagram = log_IP_to_ethernet("IPv4",trial_log_IP_datagram,server_mac)
                    with open(client_log ,'a') as log:
                        log.write(log_Eth_datagram)
                        log.write("\n")
                        log.flush()
                print("Received a response and sent an ACK")
                global last_seq_no
                global last_ack_no
                last_seq_no = seq_no
                last_ack_no = ack_no             
                
# used in simulating the 3 way connection termination handshake, it sends an Ethernet frame with the FIN flag, then receives an Ethernet frame with the FIN-ACK flag from the server and acknowledges it by an Ethernet frame.                    
def simulate_closing_handshake(previous_seq_no,previous_ack_no):
    identification=random.randint(0, 65535)
    log_request = log_tcp_segment(previous_seq_no,int(previous_ack_no)+1,"FIN","NONE")
    trial_log_IP_datagram = log_tcp_to_IP("TCP",log_request,server_ip,identification,0,"000")
    with open(client_log ,'a') as log:
        log.write("\n")
        log.write("Event: Sent an Ethernet frame with the FIN flag on  to close the connection\n")
        log.flush()
    if (len(trial_log_IP_datagram)>750):
        IP_header_len = len(trial_log_IP_datagram) - len(log_request)
        IP_datagrams = fragment_IP(log_request,server_ip,identification,IP_header_len)
        for datagrams in IP_datagrams:
            log_Eth_datagram= log_IP_to_ethernet("IPv4",datagram,server_mac)
            with open(client_log,'a') as log:
                log.write(log_Eth_datagram)
                log.write("\n")
                log.flush()
    else:
        log_Eth_datagram = log_IP_to_ethernet("IPv4",trial_log_IP_datagram,server_mac)
        with open(client_log ,'a') as log:
            log.write(log_Eth_datagram)
            log.write("\n")
            log.flush()
    print("Sent a FIN segment to close the connection")
        
    time.sleep(6)
    # read the Ethernet frame contating FIN-ACK sent by the server and acknowledges it to close the connection
    with open(server_log,'r') as file:
        lines = file.readlines()
        if lines:
            flag = lines[-1].split("|")[-7].split(":")[1].strip()
            if flag == "FIN-ACK":
                identification=random.randint(0, 65535)
                seq_no = lines[-1].split("|")[-9].split(":")[1].strip()
                ack_no=int(lines[-1].split("|")[-10].split(":")[1].strip()) +1
                log_request = log_tcp_segment(seq_no,ack_no,"ACK","NONE")
                trial_log_IP_datagram =log_tcp_to_IP("TCP",log_request,server_ip,identification,0,"000")
                with open(client_log ,'a') as log:
                    log.write("\n")
                    log.write("Event: Recieved an Ethernet frame with the FIN-ACK flag on and sent an Ethernet frame with the ACK flag to acknowledge it and close the connection\n")
                if (len(trial_log_IP_datagram)>750):
                    IP_header_len = len(trial_log_IP_datagram) - len(log_request)
                    IP_datagrams = fragment_IP(log_request,server_ip,identification,IP_header_len)
                    for datagrams in IP_datagrams:
                        log_Eth_datagram= log_IP_to_ethernet("IPv4",datagram,server_mac)
                        with open(client_log,'a') as log:
                            log.write(log_Eth_datagram)
                            log.write("\n")
                            log.flush()
                else:
                    log_Eth_datagram= log_IP_to_ethernet("IPv4",trial_log_IP_datagram,server_mac)
                    with open(client_log ,'a') as log:
                        log.write(log_Eth_datagram)
                        log.write("\n")
                        log.flush()
                print("Received a FIN-ACK and sent an Ethernet datagram containing ACK to close the connection")


DNS_lookup("http://www.gollum.mordor","1st")
time.sleep(2)
DNS_lookup("http://rincewind.fourex.disc.atuin","2nd")
time.sleep(2)
ARP_broadcast(server_ip)
time.sleep(3)
simulate_handshake()

time.sleep(6)
send_request('HEAD',"www.gollum.mordor" +'/ring.txt',last_seq_no,last_ack_no,"1st request")
time.sleep(4)
send_request('GET',"rincewind.fourex.disc.atuin" +'/wizzard.jpg',last_seq_no,last_ack_no,"2nd request")
time.sleep(4)

simulate_closing_handshake(last_seq_no,last_ack_no)

time.sleep(1)
os.remove(DNS_channel)