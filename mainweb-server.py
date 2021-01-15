import socket
import os
import yaml
import jwt

HOST, PORT = '0.0.0.0', 8091

listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 3)
listen_socket.bind((HOST, PORT))
listen_socket.listen(3)
listen_socket.setblocking(0)
socketList=[]
print('Serving HTTP on port {0}'.format(PORT))
http_request = b''
key = "secret"

def RedirectToAuthServer(host):
    print("redirect to auth server")
    location = 'Location: http://www.authserver.com:8000/?redirect_uri={0}\n'.format(host).encode()
    print(location)
    client_connection.sendall(b'HTTP/1.1 302 Found\n')
    client_connection.sendall(location)
    client_connection.sendall(b'\n')
    print("auth server redirect complete")
    http_request = b''

def decoding(decodedmessage):
    decoded = jwt.decode(decodedmessage, key, algorithms="HS256")    
    return decoded

def SetCookie(host):
    print("went inside set cookie")
    domain = host.split(":")[0]
    location = 'Location: http://{0}/\n'.format(host).encode()
    set_cookie = 'Set-Cookie: cookie=shreya; Domain={1}\n'.format(host, domain).encode()
    print(location, set_cookie)
    client_connection.sendall(b'HTTP/1.1 301 Moved Permanently\n')
    client_connection.sendall(set_cookie)
    client_connection.sendall(location)
    client_connection.sendall(b'\n')
    print("cookie set")
    http_request = b''    

def authenticated_response(host, file, req):
    if host in req:
        f = open(file, 'r')
        client_connection.sendall(b"HTTP/1.1 200 OK\nContent-Type: text/html\nTransfer-Encoding: chunked\n")
        client_connection.sendall(b"\r\n")
    
        while True:
            data_read=f.read(100)
            if data_read:
                data_len = hex(len(data_read))[2:]
                print(data_len)
                chunk_length = "{0}".format(data_len)
                chunk_data = "{0}".format(data_read)
                send_chunk = "{0}\r\n{1}\r\n".format(chunk_length, chunk_data).encode('utf-8')
                client_connection.send(send_chunk)
                print("sent data chunk wise")
            else:
                break

        # if (int(data_len) < 64):
        if (data_len < (hex(100)[2:])):
            client_connection.send(b'0\r\n\r\n')
            print("sent the last chunk")
        f.close()

        if 'HTTP/1.0' in req:
            if 'Connection: keep-alive' in req:
                print("keeping your connection alive")
            else:
                client_connection.close()
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
                query_params = decoded_request.split("\n")
                print(query_params)
                for q in query_params:
                    if 'GET /?token=' in q:
                        params = q.split(" ")
                        received_token = params[1].split("=")
                        encoded_token = received_token[1]
                        print("encoded token", encoded_token)  

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
                    print('decoded req', decoded_request)  
                    if 'Cookie' in decoded_request: 
                        try: 
                            print("cookie sent by client")
                            authenticated_response(request_host, response_file, decoded_request)
                            http_request = b''
                        except Exception as e:
                            print(e)
                            pass  
                    elif '/?token=' in decoded_request:
                        try:
                            auth_req = decoded_request.split("\n")
                            print('auth req', auth_req)
                            for a in auth_req:
                                print("token was received")
                                print(request_host)
                                host = request_host.split()[1]
                                print(host)
                                try: 
                                    decoded_jwt = decoding(encoded_token)
                                    print("decoded_jwt", decoded_jwt)
                                    SetCookie(host)
                                except Exception as e:
                                    print("exception:", e)
                                    # if (e == 'Signature verification failed'):
                                    #     print("invalid signature")
                                    # RedirectToAuthServer()
                                    # http_request = b''
                                    pass 
                                http_request = b''
                        except Exception as e:
                            RedirectToAuthServer()
                            http_request = b''
                            print(e)    
                            pass     
                    else:
                        host = request_host.split()[1]
                        print(host)
                        print("inside no cookie or token")
                        RedirectToAuthServer(host)
                        
                    http_request = b''
            except Exception as e:
                pass
        
        client_connection, client_addrress = listen_socket.accept() 
        client_connection.setblocking(0)
        socketList.append(client_connection)
    except Exception as e:
        continue