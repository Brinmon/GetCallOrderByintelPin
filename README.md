
#### 解题思路：
加密手段：[[SM4加密解密]] && [[base64加解密算法]] &&[[凯撒加密解密]]
数据结构分析：
逆向分析中的问题：
获得flag：**flag{SM4foRExcepioN?!}**

##### 学到的知识：

题目类型：
[[程序入口点前的初始化mainCRTStartup 和 WinMainCRTStartup]]
[[pysm4库的使用]]
[[Findcrypt插件]]
[[SEH反调试机制]]
[[x96dbg的使用(Windows Reverse)]]
[[IDA动态调试]]
[[二进制插桩(Pin)]]
[[hook]]
[[异常与调试之SEH、UEH、VEH、VCH以及SEH的区别总结]]
[[栈溢出混淆代码]]
##### 题目信息：
![](https://raw.githubusercontent.com/Brinmon/Brinmon-blog-img/main/Pasted image 20231117095901.png)
简介：
wp借鉴：[(5条消息) 【BUUCTF逆向 [安洵杯 2019]crackMe】_nb_What_DG的博客-CSDN博客](https://blog.csdn.net/chuxuezhewocao/article/details/125494055)
[re学习笔记（51）BUUCTF-re-[安洵杯 2019]crackMe-CSDN博客](https://blog.csdn.net/Palmer9/article/details/104776022)
[re | buuctf逆向刷题之crackMe - z5onk0 - 博客园 (cnblogs.com)](https://www.cnblogs.com/z5onk0/p/17506136.html)
[[安洵杯 2019]crackMe - Moominn - 博客园 (cnblogs.com)](https://www.cnblogs.com/Moomin/p/15824028.html)

##### 核心伪代码分析：
先分析一下程序的执行流程！
```c
int start()
{
  return mainCRTStartup();
}
int mainCRTStartup()
{
  j____security_init_cookie();
  return __tmainCRTStartup();
}
```
start()->mainCRTStartup()->`__tmainCRTStartup()`->main()
在`__tmainCRTStartup()`的调用过程中隐蔽的调用了hook的过程！！
```d
.text:002C292E loc_2C292E:                             ; CODE XREF: sub_2C27B0+151↑j
.text:002C292E                 mov     esi, esp
.text:002C2930                 lea     eax, [ebp+flOldProtect]
.text:002C2936                 push    eax             ; lpflOldProtect
.text:002C2937                 mov     ecx, [ebp+Buffer.Protect]
.text:002C293A                 push    ecx             ; flNewProtect
.text:002C293B                 mov     edx, [ebp+Buffer.RegionSize]
.text:002C293E                 push    edx             ; dwSize
.text:002C293F                 mov     eax, [ebp+Buffer.BaseAddress]
.text:002C2942                 push    eax             ; lpAddress
.text:002C2943                 call    ds:VirtualProtect
.text:002C2949                 cmp     esi, esp
.text:002C294B                 call    j___RTC_CheckEsp
.text:002C2950                 mov     eax, 1
.text:002C2955                 jmp     short loc_2C2967
```
![](https://raw.githubusercontent.com/Brinmon/Brinmon-blog-img/main/Pasted image 20231119212318.png)
该段程序hook的目标是MEssageBoxW
![](https://raw.githubusercontent.com/Brinmon/Brinmon-blog-img/main/Pasted image 20231119212403.png)
所以在主程序运行的时候：
```c
int __cdecl __noreturn main_0(int argc, const char **argv, const char **envp)
{
  int (__cdecl *v3)(int); // [esp-4h] [ebp-D0h]

  printf("please Input the flag:\n");
  scanf_s("%s", a123456789);
  MessageBoxW(0, L"Exception", L"Warning", 0);  // sub_782AB0
  v3 = sub_78100F;
  MEMORY[0] = 1;                                // 这段汇编代码会向0的地址写入1，引发报错
  sub_781136(HIWORD(v3));
}
```
这个位置的汇编注册了一个SEH异常处理函数！
```d
.text:00783440                 push    offset sub_78100F
.text:00783445                 push    large dword ptr fs:0
.text:0078344C                 mov     large fs:0, esp
```
该位置注册的SEH异常处理函数，汇编才看的出来！

![](https://raw.githubusercontent.com/Brinmon/Brinmon-blog-img/main/Pasted image 20231118232634.png)
该位置注册了SEH函数，sub4100F

所以在调用MessageBoxW的时候会跳转到sub_4F2AB0的位置！
```c
int __stdcall sub_4F2AB0(int a1, int a2, int a3, int a4)
{
  size_t i; // [esp+D8h] [ebp-8h]

  for ( i = 0; i < j_strlen(Str); ++i )
  {
    if ( Str[i] <= 122 && Str[i] >= 97 )
    {
      Str[i] -= 32;
    }
    else if ( Str[i] <= 90 && Str[i] >= 65 )
    {
      Str[i] += 32;
    }
  }
  MessageBoxA(0, "hooked", "successed", 0);
  AddVectoredExceptionHandler(0, Handler);
  return 0;
}
```
所以执行流程是main()->输入flag- >执行MessageBoxW（被hook）执行sub_4F2AB0！

在sub_4F2AB0中：
```c
int __stdcall sub_782AB0(int a1, int a2, int a3, int a4)
{
  size_t i; // [esp+D8h] [ebp-8h]

  for ( i = 0; i < j_strlen(Str); ++i )
  {
    if ( Str[i] <= 122 && Str[i] >= 97 )
    {
      Str[i] -= 32;
    }
    else if ( Str[i] <= 90 && Str[i] >= 65 )
    {
      Str[i] += 32;
    }
  }
  MessageBoxA(0, "hooked", "successed", 0);
  AddVectoredExceptionHandler(0, Handler);
  return 0;
}
```
这里注册了一个VEH异常处理函数！
return后，又会返回到`MEMORY[0] = 1;  `                              // 这段汇编代码会向0的地址写入1，引发报错
然后再执行VEH处理函数：
```c
int __stdcall Handler_0(_DWORD **a1)
{
  char v2[20]; // [esp+D0h] [ebp-18h] BYREF

  if ( **a1 == -1073741819 )
  {
    qmemcpy(v2, "where_are_u_now?", 16);
    sub_411172(&unk_41A218, v2);
    SetUnhandledExceptionFilter(TopLevelExceptionFilter);
  }
  return 0;
}
```
这里注册了一个UEH异常处理函数！
return后，又会返回到`MEMORY[0] = 1;  `                              // 这段汇编代码会向0的地址写入1，引发报错
但这次报错会被SEH捕捉！
```c
int __cdecl sub_412EA0(_DWORD *a1)
{
  if ( *a1 == -1073741819 )
    sub_411131((int)&unk_41A218, 1, 16, (int)&unk_41A1E4, (int)byte_41A180);
  return 1;
}
```
return后，又会返回到`MEMORY[0] = 1;  `                              // 这段汇编代码会向0的地址写入1，引发报错
这次报错会被UEH捕捉！
```c
int __cdecl sub_412C30(_DWORD *a1)
{
  int result; // eax
  char v2; // [esp+D3h] [ebp-11h]
  size_t i; // [esp+DCh] [ebp-8h]

  result = (int)a1;
  if ( *(_DWORD *)*a1 == -1073741819 )
  {
    for ( i = 0; i < j_strlen(Str2); i += 2 )
    {
      v2 = Str2[i];
      Str2[i] = Str2[i + 1];
      Str2[i + 1] = v2;
    }
    Str1 = (char *)sub_41126C(byte_41A180);
    *(_DWORD *)(a1[1] + 176) = *(_DWORD *)(*a1 + 20);
    *(_DWORD *)(a1[1] + 164) = *(_DWORD *)(*a1 + 24);
    *(_DWORD *)(a1[1] + 172) = *(_DWORD *)(*a1 + 28);
    *(_DWORD *)(a1[1] + 168) = *(_DWORD *)(*a1 + 32);
    *(_DWORD *)(a1[1] + 156) = *(_DWORD *)(*a1 + 36);
    *(_DWORD *)(a1[1] + 160) = *(_DWORD *)(*a1 + 40);
    *(_DWORD *)(a1[1] + 184) = sub_411136;
    return -1;
  }
  return result;
}
```
这里存在一个栈溢出混淆代码，最后这里的ret会调用sub_411136->sub_A832E0进行最后的结果比较,判断flag是否正确

```c
void __noreturn sub_A832E0()
{
  if ( !j_strcmp(Str1, Str2) )
    printf("right\n");
  else
    printf("wrong\n");
  system("pause");
  exit(0);
}
```
比较s1和s2的结果！！！！


通过程序插桩获取执行流程：
```d
E:\ReverseTools\pin-3.28-msvc-windows\source\tools\BUU刷题安洵杯_2019_crackMe\Release>pin32 -t .\BUU刷题安洵杯_2019_crackMe.dll -o .\log.log -- D:\桌面\attachment.exe
please Input the flag:
1
wrong
请按任意键继续. . .
===============================================
array[0] = 调用被hook的MessgaeBoxW
array[1] = 设置SET_VEH函数
array[2] = 设置SET_SEH函数.
array[3] = 调用VEH_1
array[4] = 设置SET_UEH函数.
array[5] = 调用SEH_1.
array[6] = 调用UEH_1.
===============================================
```
程序执行流程为：main()->调用被hook的MessgaeBoxW->调用VEH_1->调用SEH_1->调用UEH_1
最后判断flag是否正确！！！
###### 分析：
逻辑分清楚了，接下来就是看加密过程了！！！
通过插件ida的[[Findcrypt插件]]
![](https://raw.githubusercontent.com/Brinmon/Brinmon-blog-img/main/Pasted image 20231121201436.png)
存在base64加密

总的思路就是：输入内容经过 SM4 加密后再经过变表 base64 加密，结果应当与经过变换后的 Str2 一致

写脚本解密，先利用变换后的 Str2 解 base64

```python
import base64
base = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
diy_base = 'yzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuvwx'

s = 'U1ATIOpkOyWSvGm/YOYFR4!!'
ss = ''
for i in range(len(s)-2):
	ss += base[diy_base.find(s[i])]
ss += '=='
a = base64.b64decode(ss)
print(list(map(hex,a)))
```

得到：

```txt
['0x59', '0xd0', '0x95', '0x29', '0xd', '0xf2', '0x40', '0x6', '0x14', '0xf4', '0x8d', '0x27', '0x69', '0x6', '0x87', '0x4e']
```

然后解 SM4，并将结果转换为字符串，得到 flag

```python
from pysm4 import encrypt, decrypt
cipher_num = 0x59d095290df2400614f48d276906874e
mk = 0x77686572655f6172655f755f6e6f773f
clear_num = decrypt(cipher_num, mk) 
print('flag{'+bytes.fromhex(hex(clear_num)[2:]).decode()+'}')
```

**flag{SM4foRExcepioN?!}**


##### 脚本：
```python

```

```c

```

```c++

```
