from scapy.all import *
import sys
import socket
import ssl

def syn_scan(host, ports):
    scan_ports = []
    if host == '127.0.0.1' or host == '::1' or host == 'localhost':
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                res = sock.connect_ex((host, port))
                if res == 0:scan_ports.append(port)
    else:
        for port in ports:
            packet = IP(dst=host) / TCP(dport=port, flags="S")
            respond = sr1(packet, timeout=1, verbose=0)
            if respond and TCP in respond and respond[TCP].flags & 0x12:  
                scan_ports.append(port)
                send(IP(dst=host) / TCP(dport=port, flags="AR"), verbose=0) 
    return scan_ports




def clean_response(data):
    return ''.join(c if c.isprintable() else '.' for c in data)



def service_fingerprint(target, ports):
    results = {}
    generic_request = "\r\n\r\n\r\n\r\n"
    for port in ports:
        try:



            tls_response,connection = tls_probe(target, port, "")
            if tls_response:
                print(port,' : TLS Server-initiated')
                print('Data: ',clean_response(tls_response))
                continue
            
          
            tcp_response,connection = tcp_probe(target, port, "")
         
            if tcp_response:

                print(port,' : TCP Server-initiated')
                print('Data: ',clean_response(tcp_response))
                continue

           
        


            https_response,connection = tls_probe(target, port, "GET / HTTP/1.0\r\n\r\n")
            if "HTTP" in https_response:
                print(port,' : HTTPS Server')
                print('Data: ',clean_response(https_response.strip()))
               
                continue
            
            http_response,connection = tcp_probe(target, port, "GET / HTTP/1.0\r\n\r\n")
            if "HTTP" in http_response:
                print(port,' : HTTP Server')
                print('Data: ',clean_response(http_response.strip()))
              
                continue


            tls_generic_response,connection = tls_probe(target, port, generic_request)
            if tls_generic_response or connection == True:
                print(port,' : Generic TLS Server')
                if  tls_generic_response: print(clean_response('Data: ',tls_generic_response))
                else: print('Data: ',"none")
            
                continue

           

            tcp_generic_response ,connection = tcp_probe(target, port, generic_request)
            if tcp_generic_response:
                print(port,' : Generic TCP Server')
                if  tcp_generic_response: print('Data: ',clean_response(tcp_generic_response))
                else: print('Data: ',"none")
             
                continue
           
           
            print("no data found")

        except Exception as e:
            print(f"Error probing port {port}: {e}")

    


def tcp_probe(ip, port, request):
    connection=False

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            
            sock.settimeout(3)
            sock.connect((ip, port))
            
            sock.sendall(request.encode())
            
            response = sock.recv(1024).decode(errors='ignore')
            connection=True
            sock.close()
    except Exception as e:
        response = ''
    return response,connection

def tls_probe(ip, port, request):
   
    connection=False
    
   
    context = ssl.create_default_context()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
         
            sock.settimeout(3)
            sock.connect((ip, port))
            
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                
                ssock.sendall(request.encode())
                
                response = ssock.recv(1024).decode(errors='ignore')
               
                connection = True
                sock.close()
                
    except Exception as e:
       
        response = ''
   
    return response,connection



def main():
    if len(sys.argv) < 2:
        print("Usage: python synprobe.py [-p start_port[-end_port]] <target>")
        sys.exit(1)

    
    default_ports = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]
    port_range = default_ports
    target = None
    ports_defined = False

   
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '-p':
            if i + 1 < len(sys.argv):
                port_arg = sys.argv[i + 1]
                if '-' in port_arg:
                    start_port, end_port = map(int, port_arg.split('-'))
                    port_range = range(start_port, end_port + 1)
                else:
                    port_range = [int(port_arg)]
                ports_defined = True
                i += 2 
            else:
                print("Error: '-p' provided but no port range specified.")
                sys.exit(1)
        else:
           
            target = arg
            i += 1

    if not target:
        print("Error: No target specified.")
        sys.exit(1)

    if not ports_defined:
        print(f"No port range specified, using default ports: {default_ports}")

    open_ports = syn_scan(target, port_range)
    print(f"Open ports on {target}: {open_ports}")
    if open_ports:
        results = service_fingerprint(target, open_ports)
       
    else:
        print("No open ports found.")

if __name__ == '__main__':
    main()



