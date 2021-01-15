import socket
import os
import yaml
import base64
import hashlib

HOST, PORT = '0.0.0.0', 8091

socketList=[]
http_request = b''

def authorization():
    client_connection.sendall(b"HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=Test\nContent-Type: text/html\n\r\n")
    client_connection.sendall(b"no auth header received") 

def authenticated_response(host, file, req):
    if host in req:
        f = open(file, 'r')
        file_details = os.stat(file)
        content_length = 'Content-Length: {0}\n'.format(file_details.st_size).encode()
        client_connection.sendall(b"HTTP/1.1 200 OK\nContent-Type: text/html\n")
        client_connection.sendall(content_length)
        client_connection.sendall(b"\r\n")
        for l in f.readlines():
            response_data = str.encode(l)
            client_connection.sendall(response_data)
            l = f.read(1024)
        f.close()
        if 'HTTP/1.0' in req:
            if 'Connection: keep-alive' in req:
                print("keeping your connection alive")
            else:
                client_connection.close()
                http_request = b''

def handle_request(client_connection):
    http_request = b''
    while True:
        response_file = ''
        try:
            for i in range(0,len(socketList)):
                try:
                    request_data = socketList[i].recv(1024)
                    http_request += request_data
                    decoded_request = http_request.decode()
                    request_host = decoded_request.splitlines()[1]

                    with open('config.yaml') as ymlfile:
                        dataMap = yaml.safe_load(ymlfile)
                        for d in dataMap:
                            host = dataMap[d]['hostname']
                            files = dataMap[d]['filename']
                            username = dataMap[d]['username']
                            password = dataMap[d]['password']
                            if host in request_host:
                                response_file = files
                                username = username
                                password = password

                    if response_file == '':
                        error_file = 'html-files/error/index.html'
                        f = open(error_file, 'r')
                        file_details = os.stat(error_file)
                        content_length = 'Content-Length: {0}\n'.format(file_details.st_size).encode()
                        client_connection.sendall(b"HTTP/1.1 404 Not Found\nContent-Type: text/html\n")
                        client_connection.sendall(content_length)
                        client_connection.sendall(b'\r\n')
                        for l in f.readlines():
                            response_data = str.encode(l)
                            client_connection.sendall(response_data)
                            l = f.read(1024)
                        f.close() 
                        http_request = b''   
                            
                    if '\r\n\r\n' in decoded_request:
                        if not 'Authorization' in decoded_request:
                            authorization()
                        else:
                            auth_req = decoded_request.split("\n")
                            for a in auth_req:
                                if 'Authorization' in a:
                                    print(a)
                                    token = a.split()[2]
                                    print('token', token)
                                    base64_message = token
                                    base64_bytes = base64_message.encode('ascii')
                                    message_bytes = base64.b64decode(base64_bytes)
                                    message = message_bytes.decode('ascii')
                                    print('message', message)
                                    entered_username, entered_password = message.split(":")
                                    hashed_password = hashlib.md5(entered_password.encode()).hexdigest()
                                    print(hashed_password)
                                    if entered_username == username and hashed_password == password:
                                        authenticated_response(request_host, response_file, decoded_request)
                                    else:
                                        authorization() 

                        http_request = b''
                except Exception as e:
                    pass
        
        except Exception as e:
            continue

def serve_forever():   
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 3)
    listen_socket.bind((HOST, PORT))
    listen_socket.listen(3)
    listen_socket.setblocking(0)
    print('Serving HTTP on port {0}'.format(PORT))

    while True:
        client_connection, client_address = listen_socket.accept()
        client_connection.setblocking(0)
        socketList.append(client_connection)

        pid = os.fork()
        if pid == 0:  # child
            listen_socket.close()  # close child copy
            handle_request(client_connection)
            client_connection.close()
            os._exit(0)
        else:  # parent
            client_connection.close()

if __name__ == '__main__':
    serve_forever()