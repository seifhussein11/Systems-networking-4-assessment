# server_IP_file.py
import os
import time
import random
from datetime import datetime
import mimetypes 

DNS_channel = 'DNS4.txt'
server_log = "server_task4_log.txt"
client_log = "client_task4_log.txt"
server_ip = "192.168.1.1"
client_ip =" "
server_mac = "02:BA:CE:FA:CE:12"
client_mac =" "
DNS_ip = "1.1.1.1"
open(server_log,'w')

# DNS simulation function, it defines fields of DNS segment and receives DNS lookup from the client and send a response.
def DNS_reply(request_number):
    while not os.path.exists(DNS_channel):
        time.sleep(0.1)
    time.sleep(2)
    with open(client_log,'r') as log:
        lines = log.readlines()
        global client_ip
        client_ip = lines[-2].split("Source IP:")[1].split("|")[0].strip()
        iden = lines[-2].split("Identification:")[1].split("|")[0].strip()
        domain_name = lines[-2].split("Name:")[1].split("|")[0].strip()

    template = (
    " Identification: {identification} |"
    " Flags: {flag} |"
    " Question count: {question_count} |"
    " Answer count: {answer_count} |"
    " Authority record count: {auth_count} |" 
    " Additional record count: {addition_count} |"
    " Requested Name: {name} |"
    " Type : {request_type} |"
    " Class : {classs} |"
    " Answer Name : {name} |"
    " Type : {request_type} |"
    " Class : {classs} |"
    " TTL : {TTL} |"
    " Data Length : {length} |"
    " Address : {requested_ip}"
    )
    formatted_string = template.format(
    identification = iden,
    flag = "DNS reply",
    question_count = 1,
    answer_count = 1,
    auth_count = 0,
    addition_count = 0,
    name = domain_name,
    request_type = "IPv4",
    classs = "Internet",
    TTL = 255,
    length = 4,
    requested_ip = server_ip
    )
    IP_DNS = log_tcp_to_IP("DNS",formatted_string,DNS_ip,client_ip,random.randint(0, 65535),0,"000")
    with open(server_log, 'a') as log:
        log.write("Event: Received a DNS lookup request and sent a reply with The IP of the " +(request_number) +" request \n")
        log.write(IP_DNS)
        log.write("\n")
        log.write("\n")
        log.flush()
    print("Response to the DNS lookup request")

# defines the ARP segment with all its fields and returns the formatted ARP segment    
def ARP_packet(IP_target,client_mac): 
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
    opcode = "Reply (2)",
    sender_mac = server_mac,
    sender_IP = server_ip,
    target_mac = client_mac,
    target_IP = IP_target
    )
    return formatted_string

# encapsulates the ARP segment in ethernet, receives an ARP requests and respond to it with the MAC address
def ARP_reply():
    with open(client_log,'r') as log:
        lines = log.readlines()
        if (lines[-2].split("Target IP:")[1].split("//")[0].strip() == server_ip) :
            global client_mac
            client_mac = lines[-2].split("Sender Mac:")[1].split("|")[0].strip()
            ARP_response = ARP_packet(client_ip,client_mac)
            ether_ARP = log_IP_to_ethernet("ARP",ARP_response,client_mac)
            with open(server_log,'a') as log:
                log.write("Event: Sent an ARP reply to the client\n")
                log.write(ether_ARP)
                log.write("\n")
                log.write("\n")
                log.flush()
                print("Sent the server MAC address")
        
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
        prot = "  ARP REPLY //"
    formatted_string = template.format(
        Mac_destination = destination_mac,
        MAC_source = server_mac,
        ether_type = "IPv4",
        data= prot + IP_log + "///",
        CRC = str(random.randint(0,4294967295))
    )
    return formatted_string

# defines the IP datagram with all its fields and return the formatted IP datagram    
def log_tcp_to_IP(protocol,tcp_log,source_IP,destination_IP,identification,frag_offsett,flags):
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
    " Source IP: {IP_source} |"
    " Destination IP: {IP_destination} |"
    " Options: {options} |"
    " {data} "
    )
    if protocol == "TCP":
        prot = "  TCP SEGMENT // "
    else:
        prot = "  DNS REPLY // "
    formatted_string = template.format(
    version="IPv4",
    type_of_service="0",
    identifier=str(identification),
    flag=flags,
    fragmentation_offset=frag_offsett,
    TTL="255",
    protocol=protocol,
    checksum=str(random.randint(0, 65535)),
    IP_source=source_IP,
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
            IP_datagram = log_tcp_to_IP("TCP",tcp_data,server_ip,client_ip,identification,cumulative_frag,"000")
            IP_datagrams.append(IP_datagram)
        if (len(tcp_data) == datagram_size):
            IP_datagram = log_tcp_to_IP("TCP",tcp_data,server_ip,client_ip,identification,cumulative_frag,"001")
            IP_datagrams.append(IP_datagram)
        cumulative_frag += int(len(tcp_data)/8) #measured in 8 bytes
    return IP_datagrams

# used in simulating the 3 way connection handshake, it receives an Ethernet frame with the syn flag from the client , then sends an Ethernet frame with the SYN-ACK flag to the client and wait for the acknowledgment to start the connection .
def simulate_handshake():
    with open(client_log, 'r') as file:
        lines = file.readlines()
        
        if lines:
            flag = lines[-1].split("|")[-7].split(":")[1].strip()
            if flag == "SYN":
                initial_seq = random.randint(0, 4294967296)
                ack_no = int(lines[-1].split("|")[-10].split(":")[1].strip()) +1
                identification = random.randint(0, 65535)
                log_request = log_tcp_segment(initial_seq,ack_no,"SYN-ACK","NONE")
                trial_log_IP_datagram = log_tcp_to_IP("TCP",log_request,server_ip,client_ip,identification,0,"000")
                with open(server_log,'a') as log:
                    log.write("Event: Recieved an Ethernet frame with the SYN flag on and sent an Ethernet frame with the SYN-ACK flag on\n")
                    log.flush()
                if (len(trial_log_IP_datagram) > 750):
                    IP_header_len = len(trial_log_IP_datagram) - len(log_request)
                    IP_datagrams = fragment_IP(log_request,client_ip,identification,IP_header_len)
                    for datagram in IP_datagrams:
                        log_Eth_datagram = log_IP_to_ethernet("IPv4",datagram,client_mac)
                        with open(server_log,'a') as log:
                            log.write(log_Eth_datagram)
                            log.write("\n")
                            log.flush()
                else:
                    log_Eth_datagram = log_IP_to_ethernet("IPv4",trial_log_IP_datagram,client_mac)
                    with open(server_log,'a') as log:
                        log.write(log_Eth_datagram)
                        log.write("\n")
                        log.flush()
                print("Received an Ethernet datagram including SYN and sent an Ethernet datagram including SYN-ACK")   

    time.sleep(7)  
    # reads the Ethernet frame containing the ACK flag received from the client and start the connection
    with open(client_log, 'r') as file:
        lines = file.readlines()
        if lines:
            flag = lines[-1].split("|")[-7].split(":")[1].strip()
            if flag == "ACK":
                print("Received an ACK")
                print("Connection established")

# receive the Ethernet frame carrying the HTTP request and return an Ethernet frame with the HTTP respond to the HTTP request from the client   
def recieve_request_and_handle(request_number):
    with open(client_log,'r') as file:
        lines = file.readlines()
        if lines:
            flag = lines[-1].split("|")[-7].split(":")[1].strip()
            if (flag == "PSH-ACK"):
                request = lines[-1].split("|")[-2].strip(" //")
                last_client_seq_no=lines[-1].split("|")[-10].split(":")[1].strip()
                last_client_ack_no = lines[-1].split("|")[-9].split(":")[1].strip()
                log_packets = handle_client_request(request,last_client_seq_no,last_client_ack_no)
                for log_packet in log_packets:
                    with open(server_log,'a') as log:
                        log.write("\n")
                        log.write("Event: Ethernet frame holding " + (request_number)  + " data\n")
                        log.write(log_packet)
                        log.write("\n")
                        log.flush()
                print("Handeled HTTP request")

# used in simulating the 3 way connection termination handshake, it receives an Ethernet frame with the FIN flag from the client, then sends an Ethernet frame with the FIN-ACK flag to the client and close the connection.
def simulate_closing_handshake():
    with open(client_log,'r') as file:
        lines = file.readlines()
        if lines:
            flag = lines[-1].split("|")[-7].split(":")[1].strip()
            if flag =="FIN":
                identification = random.randint(0, 65535)
                seq_no = lines[-1].split("|")[-9].split(":")[1].strip()
                ack_no=int(lines[-1].split("|")[-10].split(":")[1].strip()) +1
                log_request = log_tcp_segment(seq_no,ack_no,"FIN-ACK","NONE")
                trial_log_IP_datagram = log_tcp_to_IP("TCP",log_request,server_ip,client_ip,identification,0,"000")   
                with open(server_log,'a') as log:
                    log.write("\n")
                    log.write("Event: Received an Ethernet frame with the FIN flag on  and sent Ethernet frame with the FIN-ACK flag on to close the connection\n")
                    log.flush()
                if (len(trial_log_IP_datagram) > 750):
                    IP_header_len = len(trial_log_IP_datagram) - len(log_request)
                    IP_datagrams = fragment_IP(log_request,client_ip,identification,IP_header_len)
                    for datagram in IP_datagrams:
                        log_Eth_datagram = log_IP_to_ethernet("IPv4",datagram,client_mac)
                        with open(server_log,'a') as log:
                            log.write(log_Eth_datagram)
                            log.write("\n")
                            log.flush()
                else:
                    log_Eth_datagram = log_IP_to_ethernet("IPv4",trial_log_IP_datagram,client_mac)        
                    with open(server_log,'a') as log:
                        log.write(log_Eth_datagram)
                        log.write("\n")
                        log.flush()
                print("Received FIN flag and sent an ethernet frame with FIN-ACK and will close connection")

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
    source_port = 80,
    dest_port = 8080,
    seq_no = sequence_no,
    ack_no = acknowledgment_no,
    flag = wanted_flag,
    window_size = 65535,
    checksum = random.randint(0, 65535),
    urg_pointer = 0,
    options = 0,
    data = payload,
    data_offset=int(20/4)
    )
    return formatted_string

# supporting method used in receive_request_and_handle function, it returns the HTTP response encapsulated inside an Ethernet frame
def handle_client_request(request,last_seq_no,last_ack_no):
    request_lines = request.split('\r\n')
    first_line_components = request_lines[0].split()
    method = first_line_components[0]
    path = first_line_components[1]
    server = first_line_components[4]
    status_code = random.choice([ 300, 301, 302, 303, 304, 307, 308])
    log_Eth_packets=[]
    seq_no = last_ack_no
    data = "\n" +http_status_response(status_code,path,server)
    ack_no = int(last_seq_no) + len(data)
    log_response = log_tcp_segment(seq_no, ack_no, "PSH-ACK", data)
    identification = str(random.randint(0, 65535))
    trial_log_IP_datagram = log_tcp_to_IP("TCP",log_response,server_ip,client_ip,identification,0,"000")
    if (len(trial_log_IP_datagram) > 750):
        IP_header_len = len(trial_log_IP_datagram) - len(log_response)
        IP_datagrams = fragment_IP(log_response,client_ip,identification,IP_header_len)
        for datagram in IP_datagrams:
            log_Eth_datagram = log_IP_to_ethernet("IPv4",datagram,client_mac)
            log_Eth_packets.append(log_Eth_datagram)        
    else:
        log_Eth_datagram= log_IP_to_ethernet("IPv4",trial_log_IP_datagram,client_mac)
        log_Eth_packets.append(log_Eth_datagram) 

    return log_Eth_packets

# given a HTTP status code and file path, it returns an HTTP response corresponding to the code.
def http_status_response(status_code,path,server):
    match status_code:
        case 300:
            status_response = "300 Multiple Choices"
            response = f"HTTP/1.1 {status_response}\r\n"
            content_type = mimetypes.guess_type(path)[0]
            response += f"Content Type: {content_type}\r\n"
            body = f"<html>\n<head><title>{status_response}</title></head>\n<body>\n   <h1>{status_response}</h1>\n   <p>this document can be found in multiple locations.</p>\n</body>\n</html>"
            response += f"Content Length: {len(body)}\r\n\r\n"
            response += body

            return response

        case 301:
            status_response = "301 Moved Permanently"
            response = f"HTTP/1.1 {status_response}\r\n"
            new_location = str(server) + "/new_"+(path)
            response += f"Location: {new_location}\r\n"
            content_type = mimetypes.guess_type(path)[0]
            response += f"Content Type: {content_type}\r\n"
            body = f"<html>\n<head><title>{status_response}</title></head>\n<body>\n   <h1>{status_response}</h1>\n   <p>this page has moved to <a href=http://{new_location}>http://{new_location}</a>.</p>\n</body>\n</html>"
            response += f"Content Length: {len(body)}\r\n\r\n"
            response += body

            return response

        case 302:
            status_response = "302 Found"
            response = f"HTTP/1.1 {status_response}\r\n"
            temp_location = str(server) + "/temporary_"+(path)
            response += f"Location: {temp_location}\r\n"
            content_type = mimetypes.guess_type(path)[0]
            response += f"Content Type: {content_type}\r\n"
            body = f"<html>\n<head><title>{status_response}</title></head>\n<body>\n   <h1>{status_response}</h1>\n   <p>this document is temporarily at <a href=http://{temp_location}>http://{temp_location}</a>.</p>\n</body>\n</html>"
            response += f"Content Length: {len(body)}\r\n\r\n"
            response += body

            return response

        case 303:
            status_response = "303 See Other"
            response = f"HTTP/1.1 {status_response}\r\n"
            other_location =  str(server) + "/other_"+(path)
            response += f"Location: {other_location}\r\n"
            content_type = mimetypes.guess_type(path)[0]
            response += f"Content Type: {content_type}\r\n"
            body = f"<html>\n<head><title>{status_response}</title></head>\n<body>\n   <h1>{status_response}</h1>\n   <p>this document is at <a href=http://{other_location}>http://{other_location}</a>.</p>\n</body>\n</html>"
            response += f"Content Length: {len(body)}\r\n\r\n"
            response += body

            return response

        case 304:
            status_response = "304 Not Modified"
            response = f"HTTP/1.1 {status_response}\r\n"
            content_type = mimetypes.guess_type(path)[0]
            response += f"Content Type: {content_type}\r\n"
            last_modified = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
            response += f"Last Modified: {last_modified}\r\n"
            body = f"<html>\n<head><title>{status_response}</title></head>\n</html>"
            response += f"Content Length: {len(body)}\r\n\r\n"
            response += body

            return response

        case 307:
            status_response = "307 Temporary Redirect"
            response = f"HTTP/1.1 {status_response}\r\n"
            temp_redirect_location = str(server) +"/temp_redirect_"+(path)
            response += f"Location: {temp_redirect_location}\r\n"
            content_type = mimetypes.guess_type(path)[0]
            response += f"Content Type: {content_type}\r\n"
            body = f"<html>\n<head><title>{status_response}</title></head>\n<body>\n   <h1>{status_response}</h1>\n   <p>this page is has been Temporarily moved to  <a href=http://{temp_redirect_location}>http://{temp_redirect_location}</a>.</p>\n</body>\n</html>"
            response += f"Content Length: {len(body)}\r\n\r\n"
            response += body

            return response

        case 308:
            status_response = "308 Permanent Redirect"
            response = f"HTTP/1.1 {status_response}\r\n"
            perm_redirect_location = str(server) +"/perm_redirect_"+(path)
            response += f"Location: {perm_redirect_location}\r\n"
            content_type = mimetypes.guess_type(path)[0]
            response += f"Content Type: {content_type}\r\n"
            body = f"<html>\n<head><title>{status_response}</title></head>\n<body>\n   <h1>{status_response}</h1>\n   <p>this page has been Permanently moved to <a href=http://{perm_redirect_location}>http://{perm_redirect_location}</a>.</p>\n</body>\n</html>"
            response += f"Content Length: {len(body)}\r\n\r\n"
            response += body

            return response



DNS_reply("1st")
time.sleep(3)
DNS_reply("2nd")
time.sleep(6)
ARP_reply()
time.sleep(7)
simulate_handshake()

time.sleep(7)
recieve_request_and_handle("1st request")
time.sleep(8)
recieve_request_and_handle("2nd request")
time.sleep(12)
simulate_closing_handshake()


