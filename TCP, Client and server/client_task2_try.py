# client_tcp_file.py
import os
import time
import random 

DNS_channel = 'DNS2.txt'
client_log  = 'client_task2_log.txt'
server_log = 'server_task2_log.txt'
client_ip =  "192.168.1.5"
DNS_ip = "1.1.1.1"
last_seq_no =0
last_ack_no = 0
server_ip=" "

open(client_log,'w')
open(DNS_channel,'a').close()

# DNS simulation function, it defines fields of DNS segment and send DNS lookup to DNS and receives the response.
def DNS_lookup(domain_name,request_number):
    template = (
    "Identification: {identification} |"
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
    with open(client_log, 'a') as log:
        log.write("Event: Sent a " + (request_number) + " DNS lookup request\n")
        log.write(formatted_string)
        log.write("\n")
        log.write("\n")
        log.flush()
    print("Sent a DNS lookup request")
    time.sleep(5)
    # reads the response from the DNS of the requested IP
    with open(server_log,'r') as log:
        lines =log.readlines()
        global server_ip
        server_ip = lines[-2].split("Address :")[1].strip()
    print("Received the requested IP")

       

# defines the tcp segment with all its fields and return the formatted tcp segment
def log_tcp_segment(sequence_no,acknowledgment_no,wanted_flag,payload):
    template = (
    "Source Port: {source_port} |"
    " Destination Port: {dest_port} |"
    " Sequence number: {seq_no} |"
    " Acknowledgment number: {ack_no} |"
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
    data_offset=int(20 / 4 ) # header length is equal 20 bytes because options field is not used, and divided by 4 because it is measured in 32 bit words
    )
    return formatted_string

# used in simulating the 3 way connection handshake, it sends a TCP segment with the syn flag, then receives a TCP segment with the SYN-ACK flag from the server and acknowledges it by a TCP segment.
def simulate_handshake():
    # Simulate initiating the handshake with SYN
    initial_syn = random.randint(0, 4294967296)
    initial_ack = 0
    log_request = log_tcp_segment(initial_syn,initial_ack,"SYN","NONE")
    with open(client_log,'a') as log:
        log.write("Event: Sent a tcp packet with the SYN flag on \n")
        log.write(log_request)
        log.write("\n")
        log.flush()
        print("Sent a TCP with SYN flag")

    time.sleep(4)  
    # reads the TCP segment containing the SYN-ACK flag received from the server and send a TCP segment to acknowledge and start the connection
    with open(server_log, 'r') as file:
        lines = file.readlines()
        if lines:
            flag = lines[-1].split("Flags:")[1].split("|")[0].strip()
            if flag == "SYN-ACK":
                seq_no = lines[-1].split("Acknowledgment number:")[1].split("|")[0].strip()
                ack_no = int(lines[-1].split("Sequence number:")[1].split("|")[0].strip()) +1
                log_request = log_tcp_segment(seq_no,ack_no,"ACK","NONE")
                global last_seq_no
                global last_ack_no
                last_seq_no = seq_no
                last_ack_no = ack_no
                with open(client_log, 'a') as log:
                    log.write("\n")
                    log.write("Event: Recieved a TCP packet with the SYN-ACK and sent a TCP segment with an ACK to confirm it\n")
                    log.write(log_request)
                    log.write("\n")
                    log.flush()
                    print("Received a SYN-ACK and sent an ACK")

# sends a TCP segment carrying the http request, receives the http response from server, read the response, and send an acknowledgment to the server
def send_request(method,path,previous_seq_no,previous_ack_no,request_number):
    data = f"{method} {path.split('/')[1]} HTTP/1.1\ Host: {path.split('/')[0]}"
    seq_no = previous_seq_no
    ack_no= previous_ack_no -1 + len(data)
    log_request = log_tcp_segment(seq_no,ack_no,"PSH-ACK",data)
    with open(client_log,'a') as log:
        log.write("\n")
        log.write("Event: Sent a " + (request_number) +" TCP segment that has the HTTP request\n")
        log.write(log_request)
        log.write("\n")
        log.flush()  
        print("Sent a HTTP request")

    time.sleep(5)
    # read the HTTP response sent by the server, and sends a TCP segment with ACK flag to confirm it
    with open(server_log,'r') as file:
        lines = file.readlines()
        if lines:
            lines_string = ' '.join(lines)
            request_reply = str(lines_string.split("Event: TCP segment holding " + (request_number) +" data")[1:])
            flag = request_reply.split("Flags:")[1].split("|")[0].strip()
            if flag == "PSH-ACK":
                seq_no = request_reply.split("Acknowledgment number:")[1].split("|")[0].strip()
                ack_no = int(request_reply.split("Sequence number:")[1].split("|")[0].strip()) +1
                log_request = log_tcp_segment(seq_no,ack_no,"ACK","NONE")
                global last_seq_no
                global last_ack_no
                last_seq_no = seq_no
                last_ack_no = ack_no
                with open(client_log,'a') as log:
                    log.write("\n")
                    log.write("Event: Recieved a response for " + (request_number) +" and sent a TCP segment with the ACK flag on to confirm it\n")
                    log.write(log_request)
                    log.write("\n")
                    log.flush()
                    print("Received a response and sent an ACK")
    

# used in simulating the 3 way connection termination handshake, it sends a TCP segment with the FIN flag, then receives a TCP segment with the FIN-ACK flag from the server and acknowledges it by a TCP segment.
def simulate_closing_handshake(previous_seq_no,previous_ack_no):
    seq_no = previous_seq_no
    ack_no = int(previous_ack_no)+1
    log_request = log_tcp_segment(seq_no,ack_no,"FIN","NONE")
    with open(client_log,'a') as log:
        log.write("\n")
        log.write("Event: Sent a TCP segment with FIN flag on to close the connection\n")
        log.write(log_request)
        log.write("\n")
        log.flush()
        print("Sent a FIN to close the connection")

    time.sleep(4)
    # read the TCP segment contating FIN-ACK sent by the server and acknowledges it to close the connection
    with open(server_log,'r') as file:
        lines = file.readlines()
        if lines:
            flag = lines[-1].split("Flags:")[1].split("|")[0].strip()
            if flag == "FIN-ACK":
                seq_no = lines[-1].split("Acknowledgment number:")[1].split("|")[0].strip()
                ack_no = int(lines[-1].split("Sequence number:")[1].split("|")[0].strip()) +1
                log_request = log_tcp_segment(seq_no,ack_no,"ACK","NONE")
                with open(client_log,'a') as log:
                    log.write("\n")
                    log.write("Event: Recieved a TCP segment with FIN-ACK flag and sent a TCP segment with ACK flag to close the connection\n")
                    log.write(log_request)
                    log.write("\n")
                    log.flush()
                print("Received a FIN-ACK and sent an ACK to close the connection")
                
DNS_lookup("localhost","1st")
time.sleep(3)
simulate_handshake()

time.sleep(5)

send_request('GET',str(server_ip)+'/ring.txt',last_seq_no,last_ack_no,"1st request")
time.sleep(3)
send_request('HEAD',str(server_ip)+'/wizzard.jpg',last_seq_no,last_ack_no,"2nd request")

time.sleep(4)

simulate_closing_handshake(last_seq_no,last_ack_no)

time.sleep(1)
os.remove(DNS_channel)










