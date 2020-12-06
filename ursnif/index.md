# Ursnif Word macro deobfuscation

## Intro

Given the recent, new campaign aimed at distributing the Ursnif trojan, I thought I would take a look at malicious documents observed dropping said malware. I took one .doc with tag Gozi off of MalwareBazaar and started dissecting it: what I found is an amount of obfuscation and general chaotic code that is almost unprecedented, so here is an exaplanation of the most intriguing aspects of the code, which has it all: useless variables, unused functions, bitwise operations, many programming languages, a LOLBAS (kind of), encoding, and so on.

## The sample

Uploaded to Malwaare Bazzar by ["@JAMES_MHT"](https://twitter.com/JAMESWT_MHT/) on the 3rd of December:

_File Name:_ scongiurare.12.01.2020.doc_
_MD5:_ 9edc856edd53b45e9c6f84c2e65e1cc7_
_SHA256:_ 4d1c37dac45daec5880750b8499b337e6ccf3696bfd645c4e22f388001e79900_
_MIME type:_ application/vnd.openxmlformats-officedocument.wordprocessingml.document_
_VirusTotal score:_ 32/64 (at the time of writing)_
_Document Author:_ egmu_
_Creation time:_ 02/12/2020 04:05_

## Overview

The macro creates an HTML document which contains JS code that will be ran with `mshta.exe`: it will dowload the ursnif payload and execute it; the file retrieved from the Internet is a DLL that will be executed with `regsrv 32` as a file named `temp.tmp` saved in the %temp% folder.
Notably, the source code of the HTML is not inside the macre but inside the property "Comments" of the document: at the end, I will show a way of extracting the domain hosting the ursnif payload without executing the Macro and without any tool other than a browser.

## Macro

This is the output of `oledump.py`:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/oledump.PNG)

The malicious code is (almost) completely inside the streams A9 to A15. I dumped all of them and analysed them.

Each and every stream has its own purpose, but they are very intricately interconnected so I will try and cover all of them. Note that I have already removed all of the junk code, such as functions not doing anything or unreferenced variables.

I tried visualising all of the interconnectionts between them in ["this"](https://twitter.com/elioxyz/status/1335707853118722048) image. It's also hosted ["here"](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/connections.PNG).

### VBA/amhF7

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/amhF7.PNG)

This is very simple, as it just contains an AutoOpen sub that points to `ailPn1`. For that, we will go into the following stream.

### VBA/aHSh4

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/aHSh4.PNG)

This stream builds the whole infection process. The sub of `ailPn1` executes `mshta.exe` with the HTML file, so let's start from the bottom:

`CreateObject(a3ZEzx).create (aMHvsL)`

The class of the ActiveX object created by this function is contained in a3ZEzx, which is the output of the following function (the line above):

`aiPnSR(aviJBH(a5WFEA))`

We will encounter those functions again, as they are used to deobfuscate pieces of text around this initial code. Let's deconstruct the output:

`a5WFEA` = "sse)cor)P_2)3ni)W:2)vmi)c\t)oor):st)mgm)niw" (defined in another stream)
`aviJBH()` = reverse text (defined with a rather convoluted method at the beginning of the stream)
`aiPnSR()` = remove parenthesis (defined in another stream)

So we now know that the stream will create a new process, but which one? At the end, it will look like this:

`CreateObject(winmgmts:root\cimv2:Win32_Process).Create c:\windows\system32\mshta.exe c:\users\public\ms.html`

But let's figure out how, with the functions `ap7how` and `a3guMK` that are called just before this command: they point to the next stream.

### VBA/a94yD

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/a94yD.PNG)

We immediately see three global variables declared at the beginning of the stream: the first one is the obfuscated argument of the `CreateObject()` we saw before, the second is a string that contains the character to delete when the "remove parenthesis" function is called (`aiPnSR()`) and the third one is just a number that will be used in the last stream.
Then, `ap7how` and `a3guMK` are sent to two different subs (note: `If 17728 / 277 < 217 Then` is just a different way to create a `True` statement).

`ap7how` -> `aimbhA` (stream `VBA/aMuVl`)
`a3guMK` -> `a4c1t` (stream `VBA/a4eq3S`)

### VBA/aMuVl

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/aMuVl.PNG)

This stream contains some operations that are going to be used later, mainly in the second half of the code; the two other interesting functions are `aimbhA()` and `aMHvsL()`.
`aimbhA()` outputs the variable used with `CreateObject()`, so basically `c:\windows\system32\mshta.exe c:\users\public\ms.html` (we will see how in the stream `a4eq3S`), while `aMHvsL()` is going to copy the contents of filename `c:\users\public\ms.com` into filename `c:\users\public\ms.html` (`ac9wVj` is a reference to `FileCopy`).

### VBA/a0Ep5s

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/a0Ep5s.PNG)

This stream is only used to create functions that write the contents of a file into another (`atkoV5`) and copy the contents of a file into another (`ac9wVj`); this last function is used in the previous stream.

### VBA/a4eq3S

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/a4eq3S.PNG)

So, let's see how filenames are created in this stream. As for the variables we saw earlier, here is another string that is going to be passed to the "reverse text" and "remove parenthesis" functions, after it has been split at `|`:

`aJ4q5H = VBA.Split(avijBH("l)m)t)h).)s)m)\)c)i)l)b)u)p)\)s)r)e)s)u)\):)C)|)m)o)c).)s)m)\)c)i)l)b)u)p)\)s)r)e)s)u)\):)C)|)e)x)e).)a)t)h)s)m)\)2)3)m)e)t)s)y)s)\)s)w)o)d)n)i)w)\):)c)|)o)t)o)m) )o)l)l)e)h)"), "|")"`

Which becomes:

`C:\users\public\ms.html`
`C:\users\public\ms.com`
`c:\windows\system32\mshta.exe`
`hello moto`

The output is given to a `select...case` statement.

So it now becomes easier to understand parts of the code above, given that we know that `(ae3vX(0) = C:\users\public\ms.html`, `(ae3vX(1) = C:\users\public\ms.com` and so on. The string `hello moto` is not referenced anywhere else.

There is another key thing happening in this stream, which is `a4c1t()`: this takes the contents of the "Comments" built-in property of the Word document and copies them to `C:\users\public\ms.com`. If you recall, this function was called by `a3guMK` in the `VBA/aHSh4` stream. Before going into that, a bit of context.

### VBA/aDktG

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/aDktG.PNG)

As we said, `VBA/aHSh4` builds the whole infection process: we understand that the last part executes `mshta.exe` with an HTML file, and that this file is in reality `ms.com` which then gets copied into `ms.html`. There is one stream left for us to completely understand this first part. The "Comments" property is called by `aW3j7` (in stream `VBA/a94yD`), and gets deobfsuscated in this last stream. The contents of the "Comments" property is in fact an HTML file, although (again) heavily obfuscated:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/comments.PNG)

All this stream does is perform seemingly complicated operations on each single character of "Comments", which is actually a very simple ROT13 algorithm applied to letters only.
The names in the image are in fact:

```html
<html>
<body>
<script
```
## Comments

After decoding the text in the "Comments" section with ROT13 we are left with another encoded and obfuscated piece of code, albeit in this case HTML. The HTML document only contains three JS scripts that will decode a very long string that contains a new JS. They too contain garbage code (unused/useless functions and unreferenced variables, I have already cleaned them). Let's see them in details.

### Decoding function

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/deconding_func.PNG)

In this first part we see `decode(input)`: this function will perform bit operations on the string given as input. Then, it will write the contents of `awChra` (around 18k characters) into a registry key (`"HKEY_CURRENT_USER\\Software\\a7igH2\\awnoB1"`).

### Read from registry

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/read_reg.PNG)

This script only reads the contents of the registry key, and deletes it.

### Clean and execute

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/execute.PNG)

What is inside this registry key? So, after running it through the decoding algorithm, the string `7cjhz` will be removed. Now we are left with yet another JS script responsible for the remaining part of the infection.

## Payload

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif/images/payload.PNG)

Finally, we are near the end of this atrocious amount of obfuscation. This last piece of JS is very similar to the last one, as it contains the same decoding function (`decode(input)`). It creates a file called `temp.tmp` in the %temp% folder and runs it with `regsrv32`. Inside this file is the content of what has been downloaded with `ahtDex` (`ActiveXObject("msxml2.xmlhttp")`). This file comes from the contents of the previous JS: the output of `aGnD8` is passed as a value to the `decode()` function in this last piece of code. It gets reversed by `aoBFH(aWyla)` and then decoded, in order to finally get this:

hxxp://knt807fault[.]com/analytics/YipebtxQnlzZXt9dGEfR8DO1Pi9MJpcgMRdGS7DLZZNd/xspcd8?cbM=qjOzKRsf&Hrw=VfwkIOZxHpKkTpDWL&BR=jgdzWlTjN&xb=mOJlfD

This contains a DLL that is the final payload which will get executed.

## Notes

Getting the domain used in this type of document is rather straightforward: we unzip the Word document, go into `docProps` and open `core.xml`; there are two very long strings, one is the final payload and the other is the domain. Then:

1. Paste the domain into this CyberChef receipe: https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,13)Reverse('Character')
2. Paste the output into the contents of `var a` of this JS snippet and execute it: https://js.do/code/540270

The result is a cleartext domain.

