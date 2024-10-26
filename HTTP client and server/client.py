# client.py
import os
import time


channel_path = 'client_server_task1.txt'
server_channel_path = 'server_client_task1.txt'
open(channel_path, 'w')

# takes a method and path, and send the request using HTTP/1.1 to the server
def send_request(method, path,request_number):

    if method == 'GET' or method == 'HEAD':

        request = f"{method} {path.split('/')[1]} HTTP/1.1\ Host: {path.split('/')[0]}"
        
        with open(channel_path,'a') as channel:
            channel.write("Event: Sent a " +(request_number) + " HTTP request to server\n")
            channel.write(request)
            channel.write("\n")
            channel.write("\n")
            channel.flush()
        
        print("Sent a HTTP request to server")

# receives HTTP response from the server
def receive_response():
    with open(server_channel_path,'r') as channel:
        response = channel.readlines()
        if response:
            print("Received a HTTP response")
    

send_request('GET', 'localhost/ring.txt',"1st request")
time.sleep(6)
receive_response()
time.sleep(3)
send_request('HEAD', 'localhost/wizzard.jpg',"2nd request ")
time.sleep(5)
receive_response()




    


