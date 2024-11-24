# DEP bypass Note

## Kiểm tra security của binary và các modules 
    - B1: Load narly extension bằng lệnh `.load narly`
    - B2: List các security attribute bằng lệnh `!nmod`
    
    -> Chỉ sử dụng những dll/binary nào **KHÔNG** có ASLR

## Tấn công **buffer overflow** 
- Tạo input là chuỗi unique để tìm điểm overflow
    - Tạo chuỗi unique bằng python `cyclic(size)` (size là độ dài chuỗi) 
    - Quan sát crash trên `windbg`
        - Dùng `cyclic_find('\xAA\xBB\xCC\xDD')` trên python terminal để tìm điểm overflow. `\xAA\xBB\xCC\xDD` là giá trị của thanh ghi EIP (DDCCBBAA) lúc bị crash 
        - Xác minh lại điểm crash bằng cách truyền input với format `chunk * size + b'BBBB'`, EIP lúc crash sẽ phải có giá trị `42424242` (BBBB)

    - Tìm kiếm badchar
        - Truyền chuỗi có đầy đủ ký tự từ `0x00 -> 0xFF`
        - Trên windbg tại của sổ `memory` gõ `esp` để quan sát stack
        - Dò từng ký tự, ký tự nào bị chuyển thành `/x00` sẽ là bad char.
        - Lặp lại cho đến khi tìm được hết bad char
        
        Code tạo chuỗi badchar: 

    ```    
    badchars = (
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
        b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
        b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
        b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
        b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
        b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
        b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
        b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
        b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
        b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
        b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
        b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
        b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
        b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
        b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    )
    ```


## Bypass DEP ##

- Trên máy window, thực hiện tìm các gadget trong binary mong muốn bằng lệnh `rp_win_x86.exe -f <binary name> -r 5 > rop.txt`
- Các gadgets sẽ được lưu vào file rop.txt

- Tìm địa chỉ hàm tại Import Adrress table Directory
    - Trên windbg tại của sổ `command` gõ `!dh <tên module> -f`
    - Lấy địa chỉ của import table và size
    - Trên windbg tại của sổ `command` gõ `dps <tên module> + địa chỉ <tên module> + địa chỉ + size`

- Tạo sample stack cho việc gọi hàm.
    ```
    functionAddress = b"AAAA"
    shellcodeAddress = b"BBBB"
    param1 = b"CCCC"
    param2 = b"DDDD"
    param3 = b"EEEE"
    param4 = b"FFFF"
    ```
    Có thể tùy biến dựa theo số lượng param mà hàm yêu cầu 

- Lưu lại thanh ghi ESP
    - Sử dụng các [gadget](./saveESP.md) để lưu lại thanh ghi `ESP` ở thời điểm hiện tại

- Đưa địa chỉ của thanh ghi lưu giá trị của ESP về đúng vị trí của tham số cần setup
    - functionAddress địa chỉ hàm gọi 
    - shellcodeAddess địa chỉ shellcode sẽ được chạy sau khi hàm được gọi
    - param1, param2, ... tham số cho hàm được gọi
    - Có thể sử dụng 1 số cách sau [đây](./AglinStackPointer.md)

- Khi đưa con trỏ vào đúng vị trí thực hiện setup giá trị và [truyền vào stack](./save2Stack.md) 

- Sau khi setup xong stack thực hiện thay đổi lại địa chỉ của esp bằng địa chỉ của thanh ghi sử dụng để lưu ban đầu bằng [gadget](./swapESP.md)
