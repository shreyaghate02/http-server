import socket
import os
import yaml
import hashlib
import jwt

HOST, PORT = '0.0.0.0', 8000

listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 3)
listen_socket.bind((HOST, PORT))
listen_socket.listen(3)
listen_socket.setblocking(0)
socketList=[]
print('Serving HTTP on port {0}'.format(PORT))
http_request = b''
key = "secret"

def authorization():
    f = open('html-files/auth-form.html', 'r')
    file_details = os.stat('html-files/auth-form.html')
    content_length = 'Content-Length: {0}\n'.format(file_details.st_size).encode()
    print(content_length)
    client_connection.sendall(b"HTTP/1.1 200 OK\n")
    client_connection.sendall(b"Content-Type: text/html\n")
    client_connection.sendall(content_length)
    client_connection.sendall(b'\r\n')
    for l in f.readlines():
        response_data = str.encode(l)
        client_connection.sendall(response_data)
        l = f.read(1024)
    f.close()
    http_request = b''
  

def authenticated_response(host, token):
    print(host, token)
    location = 'Location: http://{0}/?token={1}\n'.format(host, token).encode()
    print(location)
    client_connection.sendall(b'HTTP/1.1 301 Moved Permanently\n')
    client_connection.sendall(location)
    client_connection.sendall(b'\n')
    print('redirected to main server after auth')
    http_request = b''
    client_connection.close() 
    socketList.remove(client_connection)

def encoding(username, password):
    encoded = jwt.encode({"username": username, "password": password}, key, algorithm="HS256")
    return encoded    
    
while True:
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
                    if 'GET /?redirect_uri' in q:
                        params = q.split(" ")
                        redirect_to = params[1].split("=")
                        redirect_uri = redirect_to[1]
                        print('redirect_uri', redirect_uri)  

                with open('config.yaml') as ymlfile:
                    dataMap = yaml.safe_load(ymlfile)
                    redirect_uri_host = 'Host: '+redirect_uri
                    
                    for d in dataMap:
                        host = dataMap[d]['hostname']
                        files = dataMap[d]['filename']
                        username = dataMap[d]['username']
                        password = dataMap[d]['password']
                  
                        if host in redirect_uri_host:
                            def_username = username
                            def_password = password 
                            print(def_username, def_password)    

                        
                if '\r\n\r\n' in decoded_request:
                    print("request ended")
                    try: 
                        entered_credentials = decoded_request.split('\r\n\r\n', 1)[-1]
                    except Exception as e:
                        print(e)    
                        pass 

                    if (entered_credentials):
                        print("entered cred evaluation")
                        ent_user=entered_credentials.split('&',1)[0]
                        entered_username=ent_user.split('=',1)[1]
                        ent_pass=entered_credentials.split('&',1)[1]
                        entered_password=ent_pass.split('=',1)[1]
                    
                        hashed_password = hashlib.md5(entered_password.encode()).hexdigest()
                        print('hashed password', hashed_password)
                        print(hashed_password == def_password)    
                        print(entered_username == def_username)
                        
                        if entered_username == def_username and hashed_password == def_password:
                            print('host', redirect_uri)
                            print('redirecting to main server after auth')
                            encoded_jwt = encoding(entered_username, entered_password)
                            print("encoded data", encoded_jwt)
                            authenticated_response(redirect_uri, encoded_jwt)
                            http_request = b''          

                        else:
                            authorization() 
                            http_request = b''          

                    else:
                        authorization() 
                        http_request = b''          

                    http_request = b''
            except Exception as e:
                pass
        
        client_connection, client_addrress = listen_socket.accept() 
        client_connection.setblocking(0)
        socketList.append(client_connection)
    except Exception as e:
        continue