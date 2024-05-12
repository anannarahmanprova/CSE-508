Examples:

sudo python synprobe.py 8.8.8.8 

No port range specified, using default ports: [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]
Open ports on 8.8.8.8: [443, 853]
443  : HTTPS Server
Data:  HTTP/1.0 302 Found..X-Content-Type-Options: nosniff..Access-Control-Allow-Origin: *..Location: https://dns.google/..Date: Mon, 06 May 2024 02:31:18 GMT..Content-Type: text/html; charset=UTF-8..Server: HTTP server (unknown)..Content-Length: 216..X-XSS-Protection: 0..X-Frame-Options: SAMEORIGIN..Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000....<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">.<TITLE>302 Moved</TITLE></HEAD><BODY>.<H1>302 Moved</H1>.The document has moved.<A HREF="https://dns.google/">here</A>...</BODY></HTML>
853  : Generic TLS Server
Data:  none

-------------------------
sudo python synprobe.py gmail.com

No port range specified, using default ports: [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]
Open ports on gmail.com: [80, 443]
80  : HTTP Server
Data:  HTTP/1.0 200 OK..Date: Mon, 06 May 2024 02:33:41 GMT..Expires: -1..Cache-Control: private, max-age=0..Content-Type: text/html; charset=ISO-8859-1..Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-PiJzcQco4YOeKKWePNE4WQ' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp..P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."..Server: gws..X-XSS-Protection: 0..X-Frame-Options: SAMEORIGIN..Set-Cookie: AEC=AQTF6HytAICUlO_IsBOi5TcyahSL5RMQEFeR5drav_q_sEQrh6Wjm3kBXb0; expires=Sat, 02-Nov-2024 02:33:41 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax..Set-Cookie: NID=514=N_L0uKTPmGpGovtQ_dPvJXmlKWkv2THqQD8NgaR0nNgj2CceCu7xN8h58sTiCWzAU3-uOxSx_sLJruLZqZ_YLxj_cN-JKXdDSxfaeQZo6wfN93yO_fCSokwfviaxfSiN5FnhbjO2daotdsT_RB2nJjWQdu2sLbaytFhoGCLc5hg; expires=Tue, 05-Nov-2024 02:33:41 GMT; path=/; domain=.google.com; HttpOnly..Accept-Ranges: none..Vary: Accept-Encoding....<!doctyp
443  : HTTPS Server
Data:  HTTP/1.0 200 OK..Date: Mon, 06 May 2024 02:33:47 GMT..Expires: -1..Cache-Control: private, max-age=0..Content-Type: text/html; charset=ISO-8859-1..Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-AjZtFW4pBckHLZlN0XWlCw' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp..P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."..Server: gws..X-XSS-Protection: 0..X-Frame-Options: SAMEORIGIN..Set-Cookie: 1P_JAR=2024-05-06-02; expires=Wed, 05-Jun-2024 02:33:47 GMT; path=/; domain=.google.com; Secure..Set-Cookie: AEC=AQTF6Hy8rynmQwoWVYtz96lq1zy8x0Dtq4z40NySkqDZoJttYuJmOCQdfQ; expires=Sat, 02-Nov-2024 02:33:47 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax..Set-Cookie: NID=514=gxENhhOdHkZs8TGOCST9V876D8c1TCp4wNbQ6rofIdMGE0AkOsoepVud_eoElGHMwLO6l5OZMp7lBuP83tAs1t19bREfy-L6Zr43cu1zR5jUm0vsdAn-b4TW6-ShJcoMrETOIcHi7gYxZ1ANOOvThGub1CtHubXItUELV-lyWDU; expires=Tue, 05-Nov-202

--------------------------------

sudo python synprobe.py imap.gmail.com

No port range specified, using default ports: [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]
Open ports on imap.gmail.com: [587, 993]
587  : TCP Server-initiated
Data:  220 smtp.gmail.com ESMTP br41-20020a05620a462900b0078d54363075sm3435587qkb.40 - gsmtp..
993  : TLS Server-initiated
Data:  * OK Gimap ready for requests from 130.245.192.1 h12mb238973002qkn..

--------------------------------------

sudo python synprobe.py -p 130 compute.cs.stonybrook.edu

Open ports on compute.cs.stonybrook.edu: [130]
130  : TCP Server-initiated
Data:  SSH-2.0-OpenSSH_7.4..

---------------------------------------

sudo python synprobe.py -p 8000 localhost 

Open ports on localhost: [8000]
8000  : HTTP Server
Data:  HTTP/1.0 200 OK..Server: SimpleHTTP/0.6 Python/3.11.8..Date: Mon, 06 May 2024 03:00:53 GMT..Content-type: text/html; charset=utf-8..Content-Length: 1496....<!DOCTYPE HTML>.<html lang="en">.<head>.<meta charset="utf-8">.<title>Directory listing for /</title>.</head>.<body>.<h1>Directory listing for /</h1>.<hr>.<ul>.<li><a href=".bash_logout">.bash_logout</a></li>.<li><a href=".bashrc">.bashrc</a></li>.<li><a href=".bashrc.original">.bashrc.original</a></li>.<li><a href=".cache/">.cache/</a></li>.<li><a href=".config/">.config/</a></li>.<li><a href=".dmrc">.dmrc</a></li>.<li><a href=".face">.face</a></li>.<li><a hresf=".face.icon">.face.icon@</a></li>.<li><a href=".gnupg/">.gnupg/</a></li>.<li><a href=".ICEauthority">.ICEauthority</a></li>.<li><a href=".java/">.java/</a></li>.<li><a href=".local/">.local/</a></li>.<li><a href=".mozilla/">.mozilla/</a></li>.<li><a href=".profile">.profile</a></li>.<li><a href=".sudo_as_admin_successful">.sudo_as_admin_successful</a></li>.<li><a href=".Xauthority">.Xauthority</a><
                                                                                                                

------------------------------------------


Design:

main
Main function Provides a command-line interface to specify the target system and port range.It parses command-line arguments to extract the target and port range information.
Executes the SYN scanning and service fingerprinting functions based on the provided input.

syn_scan 
It uses SYN scanning technique to detect open ports on the target system. It
Sends SYN packets to each port in the specified range and waits for a response. If a SYN-ACK packet is received, the port is considered open.If no response is received, the port is considered closed.


service_fingerprinting
It connects to all the identified open ports, and either print the first 1024
bytes returned by the server. In case the server doesn't send any data after 3 seconds, try to elicit a response by sending a series of probe requests (and if a probe request succeeds, again print the first 1024 bytes returned)

tls_probe
Establishes a TLS connection to the open ports detected during SYN scanning. It uses ssl_module to secure connection. It tries to receive data. If data is not received succesfully ,it sends a http get request and then generic request to each open port to determine if it gets any respond

tcp_probe 
Establishes a TCP connection to the open ports detected during SYN scanning. It tries to receive data and if data is not found it sends a http get request and then generic request to each open port to determine if it gets any respond. 


all resonses are cleaned by clean_response which replaces non printable symbol as .






