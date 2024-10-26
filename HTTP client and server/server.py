# server.py
import os
import random
import time
from datetime import datetime
import mimetypes  

channel_path = 'server_client_task1.txt'
client_channel_path = 'client_server_task1.txt'
open(channel_path, 'w')  

# reads the request from the client file and send to the client an HTTP response.
def receive_request(request_number):
    time.sleep(3)
    with open(client_channel_path,'r') as file:
        lines = file.readlines()
    if lines:
        request = ''.join(lines[-2])
        method = request.split(" ")[0]
        path = request.split(" ")[1]
        server = request.split(" ")[4].strip()
        status_code = random.choice([ 300, 301, 302, 303, 304, 307, 308])
        http_response = http_status_response(status_code,path,server)
        with open(channel_path,'a') as log:
            log.write("Event: Received a " + (request_number) + " HTTP request from client and sent a HTTP reply to the request\n")
            log.write(http_response)
            log.write("\n")
            log.write("\n")
            log.flush()
        print("Received a HTTP request and sent a HTTP reply to the request")

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


while True:
    print("Waiting for request...\n")
    initial_mtime = os.path.getmtime('client_server_task1.txt')
    time.sleep(1)
    current_mtime = os.path.getmtime('client_server_task1.txt')
    if initial_mtime != current_mtime:
        break

receive_request("1st")
time.sleep(3)
receive_request("2nd")