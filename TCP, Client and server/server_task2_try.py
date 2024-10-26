# server_tcp_file.py
import os
import time
import random
from datetime import datetime
import mimetypes  

server_log = "server_task2_log.txt"
client_log = 'client_task2_log.txt'
DNS_channel = 'DNS2.txt'
server_ip = "192.168.1.1"
client_ip =" "
open(server_log,'w')

# DNS simulation function, it defines fields of DNS segment and receives DNS lookup from the client and send a response.
def DNS_reply(request_number):
    while not os.path.exists(DNS_channel):
        time.sleep(0.1)
    time.sleep(2)
    with open(client_log,'r') as log:
        lines = log.readlines()
        iden = lines[-2].split("Identification:")[1].split("|")[0].strip()
        domain_name = lines[-2].split("Name:")[1].split("|")[0].strip()

    template = (
    "Identification: {identification} |"
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
    with open(server_log, 'a') as log:
        log.write("Event: Received a " + (request_number) + " DNS lookup request and sent a reply with The IP of the " +(request_number) +" request \n")
        log.write(formatted_string)
        log.write("\n")
        log.write("\n")
        log.flush()
    print("Response to the DNS lookup request")

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
    data_offset=int(20/4) # header len is 20 bytes because options is not used and is divided by 4 because it is measured in 32 bit words
    )
    return formatted_string

# used in simulating the 3 way connection handshake, it receives a TCP segment with the syn flag from the client , then sends a TCP segment with the SYN-ACK flag to the client and wait for the acknowledgment to start the connection .
def simulate_handshake():
    with open(client_log, 'r') as file:
        lines = file.readlines()
        if lines:
            flag = lines[-1].split("Flags:")[1].split("|")[0].strip()
            if flag == "SYN":
                seq_no = random.randint(0, 4294967296)
                ack_no = int(lines[-1].split("Sequence number:")[1].split("|")[0].strip()) +1
                log_request = log_tcp_segment(seq_no,ack_no,"SYN-ACK","NONE")
                with open(server_log,'a') as log:
                    log.write("Event: Recieved a TCP packet with SYN flag on and sent a TCP segment contaning a SYN-ACK\n")
                    log.write(log_request)
                    log.write("\n")
                    log.flush()
                    print("Received a SYN and sent a SYN-ACK")
    time.sleep(4)
    # reads the TCP segment containing the ACK flag received from the client and start the connection
    with open(client_log, 'r') as file:
        lines = file.readlines()
        if lines:
            flag = lines[-1].split("Flags:")[1].split("|")[0].strip()
            if flag == "ACK":
                print("Received an ACK")
                print("Connection established")
                
# receive the TCP segment carrying the HTTP request and return a HTTP respond to the HTTP request from the client               
def recieve_request_and_handle(request_number):
    with open(client_log,'r') as file:
        lines = file.readlines()
        if lines:
            flag =lines[-1].split("Flags:")[1].split("|")[0].strip()
            if flag == "PSH-ACK":
                request = lines[-1].split("|")[-1].strip()
                last_client_seq_no=lines[-1].split("Sequence number:")[1].split("|")[0].strip()
                last_client_ack_no = lines[-1].split("Acknowledgment number:")[1].split("|")[0].strip()
                log_response = handle_client_request(request,last_client_seq_no,last_client_ack_no)            
                with open(server_log,'a') as log:
                    log.write("\n")
                    log.write("Event: TCP segment holding " + (request_number)  + " data\n")
                    log.write(log_response)
                    log.write("\n")
                    log.flush()
                print("Handeled HTTP request")

# used in simulating the 3 way connection termination handshake, it receives a TCP segment with the FIN flag from the client, then sends a TCP segment with the FIN-ACK flag to the client and close the connection.
def simulate_closing_handshake():
    with open(client_log,'r') as file:
        lines = file.readlines()
        if lines:
            flag = lines[-1].split("Flags:")[1].split("|")[0].strip()
            if flag =="FIN":
                seq_no =  lines[-1].split("Acknowledgment number:")[1].split("|")[0].strip()
                ack_no = int(lines[-1].split("Sequence number:")[1].split("|")[0].strip()) +1
                log_request = log_tcp_segment(seq_no,ack_no,"FIN-ACK","NONE")              
                with open(server_log,'a') as log:
                    log.write("\n")
                    log.write("Event: Received a TCP segment with FIN flag on and sent TCP with FIN-ACK to close the connection\n")
                    log.write(log_request)
                    log.write("\n")
                    log.flush()
                    print("Received a FIN segment will send FIN-ACK and close connection")

# supporting method used in receive_request_and_handle function, it returns the HTTP response encapsulated inside a TCP segment
def handle_client_request(request,last_seq_no,last_ack_no):
    request_lines = request.split('\r\n')
    first_line_components = request_lines[0].split()
    method = first_line_components[0]
    path = first_line_components[1]
    server = first_line_components[4]
    status_code = random.choice([ 300, 301, 302, 303, 304, 307, 308])
    seq_no = last_ack_no
    data = "\n" +http_status_response(status_code,path,server)
    ack_no = int(last_seq_no) + len(data)
    log_response = log_tcp_segment(seq_no,ack_no,"PSH-ACK",data)
    return log_response

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
time.sleep(8)
simulate_handshake()
time.sleep(5)
recieve_request_and_handle("1st request")
time.sleep(8)
recieve_request_and_handle("2nd request")
time.sleep(10)
simulate_closing_handshake()

