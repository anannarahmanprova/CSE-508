mysniffer.py
my program utilizes Scapy to sniff packets, supporting both live capture and reading from pcap files. It searches for HTTP client or TLS client hello messages within the packets. If a pcap file is provided, it sniffs packets from the file; otherwise, it performs live sniffing. Upon identifying HTTP traffic, it searches for GET and POST requests, printing datetime, source, destination, hostname, URL, and datetime for each discovered request. Additionally, upon detecting a TCP client hello message, it parses the packet and prints datetime, servername, source, destination, and version information.

File Read: hw1.pcap ( the one which was given for hw1)
command:python mysniffer.py -r hw1.pcap
output:

Starting reading from hw1.pcap
reading from file hw1.pcap, link-type EN10MB (Ethernet), snapshot length 65535
2013-01-12 22:30:49.032953 HTTP 192.168.0.200:40341 -> 87.98.246.8:80 pic.leech.it:80 GET /i/f166c/479246b0asttas.jpg
2013-01-12 22:31:19.244125 HTTP 192.168.0.200:40630 -> 216.137.63.121:80 ecx.images-amazon.com:80 GET /images/I/41oZ1XsiOAL.
2013-01-12 22:31:50.359908 HTTP 192.168.0.200:55528 -> 159.148.96.184:80 images4.byinter.net:80 GET /DSC442566.gif
2013-01-13 02:54:46.028958 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/InRelease
2013-01-13 02:54:46.032578 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/InRelease
2013-01-13 02:54:46.056291 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release.gpg
2013-01-13 02:54:46.062554 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release.gpg
2013-01-13 02:54:46.082239 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release
2013-01-13 02:54:46.094457 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release
2013-01-13 02:54:46.102039 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/InRelease
2013-01-13 02:54:46.142106 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/main/source/Sources.bz2
2013-01-13 02:54:46.146533 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/source/Sources.bz2
2013-01-13 02:54:46.170058 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/restricted/source/Sources.bz2
2013-01-13 02:54:46.176724 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/binary-i386/Packages.bz2
2013-01-13 02:54:46.207856 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/Release.gpg
2013-01-13 02:54:46.209010 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.bz2
2013-01-13 02:54:46.209744 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/universe/i18n/Index
2013-01-13 02:54:46.241556 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.bz2
2013-01-13 02:54:46.265204 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/restricted/i18n/Translation-en.bz2
2013-01-13 02:54:46.273872 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.xz
2013-01-13 02:54:46.301378 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.xz
2013-01-13 02:54:46.311794 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/Release.gpg
2013-01-13 02:54:46.329564 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.lzma
2013-01-13 02:54:46.361462 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.lzma
2013-01-13 02:54:46.393264 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.gz
2013-01-13 02:54:46.412166 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/Release
2013-01-13 02:54:46.425136 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.gz
2013-01-13 02:54:46.455147 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US
2013-01-13 02:54:46.485361 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en
2013-01-13 02:54:46.512734 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/main/source/Sources.bz2
2013-01-13 02:54:46.619069 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/restricted/i18n/Index
2013-01-13 02:54:46.739714 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/universe/binary-i386/Packages.bz2
2013-01-13 02:54:46.848014 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/restricted/source/Sources.bz2
2013-01-13 02:54:46.949092 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/multiverse/i18n/Index
2013-01-13 02:54:47.049476 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/main/i18n/Translation-en.bz2
2013-01-13 05:36:10.191159 HTTP 192.168.0.200:49291 -> 46.51.197.89:80 duckduckgo.com GET /favicon.ico
2013-01-13 05:36:10.559804 HTTP 192.168.0.200:42497 -> 91.189.90.40:80 start.ubuntu.com GET /11.10/Google/?sourceid=hp
2013-01-13 05:36:15.266947 HTTP 192.168.0.200:42990 -> 62.252.170.91:80 www.nature.com GET /news/2009/090527/images/459492a-i1.0.jpg
2013-01-13 05:44:43.557881 HTTP 192.168.0.200:52724 -> 91.189.89.88:80 start.ubuntu.com GET /11.10/Google/?sourceid=hp
2013-01-13 05:44:46.286274 HTTP 192.168.0.200:43029 -> 216.137.63.137:80 ecx.images-amazon.com GET /images/I/41oZ1XsiOAL
2013-01-13 05:44:46.446757 HTTP 192.168.0.200:43029 -> 216.137.63.137:80 ecx.images-amazon.com GET /favicon.ico
2013-01-13 05:45:22.469955 HTTP 192.168.0.200:42503 -> 91.189.90.40:80 start.ubuntu.com GET /11.10/Google/?sourceid=hp
2013-01-13 05:45:26.008031 HTTP 192.168.0.200:58724 -> 159.148.96.184:80 images4.byinter.net GET /DSC442566.gif
2013-01-13 05:45:26.248386 HTTP 192.168.0.200:58724 -> 159.148.96.184:80 images4.byinter.net GET /favicon.ico
2013-01-13 05:45:26.345418 HTTP 192.168.0.200:58724 -> 159.148.96.184:80 images4.byinter.net GET /favicon.ico
2013-01-13 05:45:50.155155 HTTP 192.168.0.200:58460 -> 91.189.90.41:80 start.ubuntu.com GET /11.10/Google/?sourceid=hp
2013-01-14 02:52:52.081372 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/InRelease
2013-01-14 02:52:52.114281 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/InRelease
2013-01-14 02:52:52.119556 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release.gpg
2013-01-14 02:52:52.145686 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release.gpg
2013-01-14 02:52:52.149573 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release
2013-01-14 02:52:52.174435 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release
2013-01-14 02:52:52.194232 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/InRelease
2013-01-14 02:52:52.233034 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/source/Sources.bz2
2013-01-14 02:52:52.267644 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/binary-i386/Packages.bz2
2013-01-14 02:52:52.273227 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/main/source/Sources.bz2
2013-01-14 02:52:52.297942 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.bz2
2013-01-14 02:52:52.306347 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/Release.gpg
2013-01-14 02:52:52.337264 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.bz2
2013-01-14 02:52:52.374989 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.xz
2013-01-14 02:52:52.392300 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/restricted/source/Sources.bz2
2013-01-14 02:52:52.403938 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.xz
2013-01-14 02:52:52.416806 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/Release.gpg
2013-01-14 02:52:52.431794 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.lzma
2013-01-14 02:52:52.444629 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/universe/i18n/Index
2013-01-14 02:52:52.459934 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.lzma
2013-01-14 02:52:52.497420 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.gz
2013-01-14 02:52:52.527154 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/Release
2013-01-14 02:52:52.528532 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.gz
2013-01-14 02:52:52.562789 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US
2013-01-14 02:52:52.596265 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/main/i18n/Translation-en.bz2
2013-01-14 02:52:52.596648 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en
2013-01-14 02:52:52.631843 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/Release
2013-01-14 02:52:52.645051 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/universe/i18n/Translation-en.bz2
2013-01-14 02:52:52.738992 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/Release
2013-01-14 02:52:53.044882 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/main/source/Sources.bz2
2013-01-14 02:52:53.206107 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/universe/i18n/Index
2013-01-14 02:52:53.421887 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/universe/binary-i386/Packages.bz2
2013-01-14 02:52:53.882844 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/restricted/i18n/Index
2013-01-14 02:52:54.025756 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/universe/i18n/Index
2013-01-14 02:52:54.133711 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/main/source/Sources.bz2
2013-01-14 02:52:54.464350 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/universe/source/Sources.bz2
2013-01-14 02:52:54.706714 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/main/binary-i386/Packages.bz2
2013-01-14 02:52:54.951569 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/restricted/i18n/Translation-en.bz2
2013-01-14 12:47:49.310903 HTTP 1.234.31.20:38720 -> 192.168.0.200:80 86.0.33.20 GET /w00tw00t.at.blackhats.romanian.anti-sec:)
2013-01-14 12:47:54.817639 HTTP 1.234.31.20:42230 -> 192.168.0.200:80 86.0.33.20 GET /phpMyAdmin/scripts/setup.php
2013-01-14 12:48:00.827917 HTTP 1.234.31.20:45552 -> 192.168.0.200:80 86.0.33.20 GET /phpmyadmin/scripts/setup.php
2013-01-14 12:48:06.817903 HTTP 1.234.31.20:48734 -> 192.168.0.200:80 86.0.33.20 GET /pma/scripts/setup.php
2013-01-14 12:48:12.822560 HTTP 1.234.31.20:52079 -> 192.168.0.200:80 86.0.33.20 GET /myadmin/scripts/setup.php
2013-01-14 12:48:18.817364 HTTP 1.234.31.20:55672 -> 192.168.0.200:80 86.0.33.20 GET /MyAdmin/scripts/setup.php


Live capture:
command:python mysniffer.py -i eth0  

Start capturing
2024-03-08 19:16:26.407070 TLS v1.2 172.24.25.229:53540 -> 34.160.144.191:443 mozilla.net
2024-03-08 19:16:26.586839 HTTP 172.24.25.229:56020 -> 184.25.127.150:80 r3.o.lencr.org POST /
2024-03-08 19:16:27.270003 TLS v1.2 172.24.25.229:40914 -> 34.107.243.93:443 mozilla.com
2024-03-08 19:16:27.299180 HTTP 172.24.25.229:56020 -> 184.25.127.150:80 r3.o.lencr.org POST /
2024-03-08 19:16:27.359230 TLS v1.2 172.24.25.229:43158 -> 54.218.225.239:443 mozilla.com
2024-03-08 19:16:27.360776 TLS v1.2 172.24.25.229:40926 -> 34.107.243.93:443 mozilla.com
2024-03-08 19:16:27.539695 HTTP 172.24.25.229:51940 -> 184.25.127.151:80 r3.o.lencr.org POST /
2024-03-08 19:16:27.765474 TLS v1.2 172.24.25.229:47610 -> 34.149.100.209:443 mozilla.com
2024-03-08 19:16:27.808865 HTTP 172.24.25.229:56020 -> 184.25.127.150:80 r3.o.lencr.org POST /
2024-03-08 19:16:27.868817 TLS v1.2 172.24.25.229:33040 -> 34.120.115.102:443 mozilla.com
2024-03-08 19:16:27.870426 TLS v1.2 172.24.25.229:33030 -> 34.120.115.102:443 mozilla.com
2024-03-08 19:16:27.886302 HTTP 172.24.25.229:56020 -> 184.25.127.150:80 r3.o.lencr.org POST /
2024-03-08 19:16:27.919063 HTTP 172.24.25.229:56020 -> 184.25.127.150:80 r3.o.lencr.org POST /
2024-03-08 19:16:28.920118 TLS v1.2 172.24.25.229:59240 -> 162.219.225.118:443 amazon.com
2024-03-08 19:16:29.399644 HTTP 172.24.25.229:60334 -> 192.229.211.108:80 ocsp.digicert.com POST /
2024-03-08 19:16:29.399706 HTTP 172.24.25.229:60330 -> 192.229.211.108:80 ocsp.digicert.com POST /
2024-03-08 19:16:29.992087 TLS v1.2 172.24.25.229:46572 -> 18.67.83.222:443 media-amazon.com
2024-03-08 19:16:30.163944 TLS v1.2 172.24.25.229:39314 -> 172.253.122.95:443 googleapis.com
2024-03-08 19:16:30.233544 HTTP 172.24.25.229:58434 -> 142.251.167.94:80 ocsp.pki.goog POST /gts1c3
2024-03-08 19:16:30.414066 TLS v1.2 172.24.25.229:49408 -> 52.46.131.231:443 amazon.com
2024-03-08 19:16:30.415834 TLS v1.2 172.24.25.229:49406 -> 52.46.131.231:443 amazon.com
2024-03-08 19:16:30.552894 TLS v1.2 172.24.25.229:60548 -> 52.86.40.156:443 amazon.com
2024-03-08 19:16:30.561491 TLS v1.2 172.24.25.229:60546 -> 52.86.40.156:443 amazon.com
2024-03-08 19:16:30.563341 TLS v1.2 172.24.25.229:42568 -> 18.160.51.31:443 amazon-adsystem.com
2024-03-08 19:16:30.830946 HTTP 172.24.25.229:58736 -> 108.138.63.181:80 ocsp.r2m02.amazontrust.com POST /
2024-03-08 19:16:30.831128 HTTP 172.24.25.229:58728 -> 108.138.63.181:80 ocsp.r2m02.amazontrust.com POST /
2024-03-08 19:16:30.846712 TLS v1.2 172.24.25.229:60550 -> 52.86.40.156:443 amazon.com
2024-03-08 19:16:31.129110 TLS v1.2 172.24.25.229:52330 -> 52.46.143.56:443 amazon-adsystem.com
2024-03-08 19:16:31.283961 TLS v1.2 172.24.25.229:35636 -> 52.46.155.114:443 amazon.com
2024-03-08 19:16:31.488470 TLS v1.2 172.24.25.229:58370 -> 52.46.146.128:443 amazon.com
2024-03-08 19:16:32.035789 TLS v1.2 172.24.25.229:40210 -> 185.167.164.52:443 adform.net
2024-03-08 19:16:32.138882 HTTP 172.24.25.229:60330 -> 192.229.211.108:80 ocsp.digicert.com POST /
2024-03-08 19:16:32.160428 HTTP 172.24.25.229:58728 -> 108.138.63.181:80 ocsp.r2m02.amazontrust.com POST /
2024-03-08 19:16:32.184269 HTTP 172.24.25.229:54776 -> 104.18.21.226:80 ocsp.globalsign.com POST /gsgccr3dvtlsca2020
2024-03-08 19:16:32.190289 HTTP 172.24.25.229:58744 -> 108.138.63.181:80 ocsp.r2m01.amazontrust.com POST /
2024-03-08 19:16:32.385001 TLS v1.2 172.24.25.229:40808 -> 3.136.148.195:443 serving-sys.com
2024-03-08 19:16:32.422698 HTTP 172.24.25.229:58744 -> 108.138.63.181:80 ocsp.r2m01.amazontrust.com POST /
2024-03-08 19:16:32.532478 TLS v1.2 172.24.25.229:38136 -> 68.67.160.26:443 adnxs.com

 
Live capture with filter:
command:python mysniffer.py -i eth0 "tcp port 443"
output:

Start capturing
2024-03-08 19:20:25.088878 TLS v1.2 172.24.25.229:53360 -> 34.120.115.102:443 mozilla.com
2024-03-08 19:20:26.703935 TLS v1.2 172.24.25.229:44200 -> 23.197.108.220:443 expedia.com
2024-03-08 19:20:27.646728 TLS v1.2 172.24.25.229:54610 -> 23.197.109.32:443 travel-assets.com
2024-03-08 19:20:27.651119 TLS v1.2 172.24.25.229:54602 -> 23.197.109.32:443 travel-assets.com
2024-03-08 19:20:27.653499 TLS v1.2 172.24.25.229:54618 -> 23.197.109.32:443 travel-assets.com
2024-03-08 19:20:27.749657 TLS v1.2 172.24.25.229:54636 -> 23.197.109.32:443 travel-assets.com
2024-03-08 19:20:27.754403 TLS v1.2 172.24.25.229:54640 -> 23.197.109.32:443 travel-assets.com
2024-03-08 19:20:27.755730 TLS v1.2 172.24.25.229:54624 -> 23.197.109.32:443 travel-assets.com
2024-03-08 19:20:28.259032 TLS v1.2 172.24.25.229:54648 -> 23.197.109.32:443 travel-assets.com
2024-03-08 19:20:28.264097 TLS v1.2 172.24.25.229:54660 -> 23.197.109.32:443 travel-assets.com
2024-03-08 19:20:28.545266 TLS v1.2 172.24.25.229:54722 -> 23.208.35.57:443 uciservice.com
2024-03-08 19:20:28.546858 TLS v1.2 172.24.25.229:54708 -> 23.208.35.57:443 uciservice.com
2024-03-08 19:20:28.914093 TLS v1.2 172.24.25.229:52612 -> 172.253.122.95:443 googleapis.com
2024-03-08 19:20:29.290463 TLS v1.2 172.24.25.229:55394 -> 52.204.130.249:443 demdex.net
2024-03-08 19:20:29.409220 TLS v1.2 172.24.25.229:45718 -> 192.229.163.55:443 tagcommander.com



Pcap file read with filter:
command:python mysniffer.py -r hw1.pcap "port 55672"
Output:

Starting reading from hw1.pcap
reading from file hw1.pcap, link-type EN10MB (Ethernet), snapshot length 65535
2013-01-14 12:48:18.817364 HTTP 1.234.31.20:55672 -> 192.168.0.200:80 86.0.33.20 GET cripts/setup.php

arpwatch.py
Initially, my program inspects the ARP cache located at /proc/net/arp. It records the IP addresses and their corresponding MAC addresses locally. Subsequently, it monitors network traffic to detect any changes. If it encounters a packet where the IP address does not align with the recorded MAC address, it alerts to the discrepancy

Attacker's Vm:ubuntu
Victim's Vm:kali linux

Arpwatch is running on victim's vm :
command: python arpwatch.py
output:
	ARP Cache Initial State:
	172.24.16.3->08:f1:ea:5e:8d:00
	172.24.25.160->08:00:27:9a:4f:26
	172.24.16.2->08:f1:ea:5e:4a:00
	172.24.16.1->aa:bb:cc:dd:ee:ff
	Looking For ARPSPOOF


	
Attacker starts attack 
Attaker's command:arpspoof -i enp0s3 -t 172.24.25.229 172.24.16.1
Arp reply:
8:0:27:9a:4f:26 8:0:27:21:b1:d0 0806 42: arp reply 172.24.16.1 is-at 8:0:27:9a:4f:26
8:0:27:9a:4f:26 8:0:27:21:b1:d0 0806 42: arp reply 172.24.16.1 is-at 8:0:27:9a:4f:26

When attacker attacks arpwatch's output:
172.24.16.1 changed from aa:bb:cc:dd:ee:ff to 08:00:27:9a:4f:26
172.24.16.1 changed from aa:bb:cc:dd:ee:ff to 08:00:27:9a:4f:26
172.24.16.1 changed from aa:bb:cc:dd:ee:ff to 08:00:27:9a:4f:26
172.24.16.1 changed from aa:bb:cc:dd:ee:ff to 08:00:27:9a:4f:26
172.24.16.1 changed from aa:bb:cc:dd:ee:ff to 08:00:27:9a:4f:26
172.24.16.1 changed from aa:bb:cc:dd:ee:ff to 08:00:27:9a:4f:26

	



 
