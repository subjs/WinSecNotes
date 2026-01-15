#To test this, run: python3 socks5_proxy.py in one terminal
#Then try to exec a client socks5 connection using curl: curl --socks5-hostname 127.0.0.1:1080 http://example.com
#The client should return a normal looking html response
#You will know it worked if you try the same curl command without this socks5_proxy running - and then you get a connection error.

import socket
import threading
import struct

def forwarder(source, destination):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
    except Exception as e:
        print(f"Error forwarding data: {e}")
    finally:
        source.close()
        destination.close()


def handle_client(client):
    try:
        #SOCKS5 handshake
        ver, nmethods = client.recv(2)
        methods = client.recv(nmethods)
        
        #Send response - 0x00 for no auth
        client.sendall(b"\x05\x00")

        #SOCKS5 request
        ver, cmd, _, atyp = client.recv(4)

        #CONNECT only
        if cmd != 0x01:
            client.close()
            return
        
        
        if atyp == 0x01: #IPv4
            addr = socket.inet_ntoa(client.recv(4))
        elif atyp == 0x03: # Domain name
            length = client.recv(1)[0]
            addr = client.recv(length).decode()
        else:
            client.close()
            return

        port = struct.unpack(">H", client.recv(2))[0]

        #Connect to target
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((addr, port))

        #response - success
        response = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0)
        client.sendall(response)

        #forward traffic
        thread1 = threading.Thread(target=forwarder, args=(client, remote), daemon=True)
        thread2 = threading.Thread(target=forwarder, args=(remote, client), daemon=True)

        thread1.start()
        thread2.start()

    except Exception:
        client.close()

def start_socks5(listen_host="0.0.0.0", listen_port=1080):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((listen_host, listen_port))
    server.listen(100)

    print(f"[+] SOCKS5 proxy listening in {listen_host}:{listen_port}")

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    start_socks5()
  
