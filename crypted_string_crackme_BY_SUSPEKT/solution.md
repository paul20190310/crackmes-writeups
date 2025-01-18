# crypted string crackme

## Overview

After execute this crackeme file, asking for an input to verify whether it is correct.  When I casually enter 123456, it outputs `FIMOZ OWNER ACCES DENIED!!!!` and then continues to ask for the next input.

```bash
> cracksme.exe
Enter: 123456
FIMOZ OWNER ACCES DENIED!!!!
Enter: 
```

Our GOAL is to find a input that makes it correct.

## Analysis

Open the file in **IDA pro 7.5** to see how the code is working.  When I opened it, I pressed F5 to decompile the program, and I found that there was a infinite loop responsible for the whole input and output process.

This decompiled code snippet looks like:

```C
while ( 1 )
{
    v6 = v35;
    if ( v37 > 0xF )
        v6 = (void **)v35[0];
    sub_140002140(std::cout, v6, v36);
    LOBYTE(v7) = 10;
    v8 = std::ios::widen((char *)&std::cin + *(int *)(std::cin + 4i64), v7);
    sub_140002300(std::cin, Buf1, v8);
    v9 = Buf2;
    if ( (unsigned __int64)v3 > 0xF )
        v9 = v5;
    v10 = Buf1;
    v11 = (void **)Buf1[0];
    v12 = v34;
    if ( v34 > 0xF )
        v10 = (void **)Buf1[0];
    v13 = Size;
    if ( (void *)Size == v4 && !memcmp(v10, v9, Size) )
        break;
    v14 = Buf1;
    if ( v12 > 0xF )
        v14 = v11;
    if ( v13 == 3 && *(_WORD *)v14 == 12849 && *((_BYTE *)v14 + 2) == 51 )
    {
        v15 = (_QWORD *)sub_140001830(v10, Block);
        v16 = v15[2];
        if ( v15[3] > 0xFui64 )
            v15 = (_QWORD *)*v15;
        v17 = sub_140002140(std::cout, v15, v16);
        std::ostream::operator<<(v17, sub_140001F20);
        if ( v29 > 0xF )
        {
            v18 = Block[0];
            if ( v29 + 1 >= 0x1000 )
            {
                v18 = (_BYTE *)*((_QWORD *)Block[0] - 1);
                if ( (unsigned __int64)(Block[0] - (void *)v18 - 8) > 0x1F )
                    invalid_parameter_noinfo_noreturn();
            }
            goto LABEL_20;
        }
    }
    else
    {
        v19 = (_QWORD *)sub_140001A30(v10, &v30);
        v20 = v19[2];
        if ( v19[3] > 0xFui64 )
            v19 = (_QWORD *)*v19;
        v21 = sub_140002140(std::cout, v19, v20);
        std::ostream::operator<<(v21, sub_140001F20);
        if ( v31 > 0xF )
        {
            v18 = v30;
            if ( v31 + 1 >= 0x1000 )
            {
            v18 = (_BYTE *)*((_QWORD *)v30 - 1);
            if ( (unsigned __int64)(v30 - v18 - 8) > 0x1F )
                invalid_parameter_noinfo_noreturn();
            }
LABEL_20:
            j_j_free(v18);
        }
    }
}
```

Dynamic analysis executed this program, and I found that the last if-else statement in this code snippet would output `FIMOZ OWNER ACCES DENIED!!!!`, and the first if condition is to check whether the input is `123`.

So I want to avoid letting the program execute until the last if-else statement.  I noticed that in the middle of this code snippet, there is a `break` statement.  I think I should try to arrive here to exit this infinite loop and avoid output errors.

```C
v13 = Size;
if ( (void *)Size == v4 && !memcmp(v10, v9, Size) )
    break;
v14 = Buf1;
```

When I dynamically analyzed and checked this if condition, I found that `v10` is my input, and my input must be consistent with the `v9` string to meet the condition.

In debug mode, before reaching the line before the if statement, I used IDA pro's **hex dump** to check what the string value of `v9` is.

`v9` points to 0x78870FF7D0 in my program, and the value at memory address 0x78870FF7D0 is "crackmeYG".  So when my input is `crackmeYG`, it will meet the if condition of the `break` statement.

```text
00000078870FF7B0  45 6E 74 65 72 3A 20 00  00 00 00 00 00 00 00 00  Enter: .........
00000078870FF7C0  07 00 00 00 00 00 00 00  0F 00 00 00 00 00 00 00  ................
00000078870FF7D0  63 72 61 63 6B 6D 65 59  47 00 00 00 00 00 00 00  crackmeYG.......
00000078870FF7E0  09 00 00 00 00 00 00 00  0F 00 00 00 00 00 00 00  ................
00000078870FF7F0  A6 FF FF FF 91 FF FF FF  D5 FF FF FF 15 00 00 00  ................
```

## Verification

```bash
> cracksme.exe
Enter: crackmeYG
Grats!
```

The password for this challenge is "crackmeYG".
