# 1 Số gadget có thể dùng

*: bất kỳ thanh ghi nào ngoại trừ esp

```
push esp ; pop * ; ret ;
push esp ; (.*) ; pop (.*) ; ret ; 
```
Số lần push và pop phải bằng nhau 


```
mov *, esp ; ret ;
```
```
mov ebp, esp ; ... ; ret ; 
lea *, [ebp ...] ; ret ;
```
