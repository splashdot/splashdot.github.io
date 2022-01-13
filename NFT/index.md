# Ad-hoc malware for NFT artists

[@elioxyz](https://twitter.com/elioxyz)

[Home](https://splashdot.github.io)


## Background

The NFT world became extremely notorious during the course of 2021, and for many different reasons. One of them is money: the amount of it that is moved every day by NFT vendors, brokers and producers made it possible to create a whole new market. The demand for NFT has skyrocketed and VFX artists have moved towards it, creating NFTs for companies and for their own.

The nature of NFTs and, more generally, the cryptocurrency world unfortunately attract lots of criminals that are willing to go long ways to scam people and steal their cryptocurrencies. In this instance, a popular NFT artist was approached by an individual claiming to be associated with a game developing firm (Wargaming), who offered to work on a project about NFTs. This individual eventually shared a folder allegedly containing sketches and information about the company. At this point, once realised that the files in the folder were odd, this person reached out to me asking to take a look, which I much happily did. The result of the files' analysis is presented below.

Some key aspects are available here:

* the Threat Actor (TA) is familiar with the NFT ecosystem, and knows how to use the jargon specific to the NFT markets
* the TA is using commodity malware and is therefore not sophisticated
* the TA is using some anti-analysis techniques such as code obfuscation, shortcut modification and filesize inflation
* the TA is also using Discord's CDN to store their payloads
* The TA is only interested in data related to browsers (cookies, passwords,...) and cryptocurrency (wallets, credentials,...)

## Initial archive

The archive initially shared with the victim is password protected. The following table shows its details:

| *Type*     | *data*|
| :---       |    :---|
| Name       | Presentation for artist Wargaming NFT.rar| 
| MD5        | 7b26b892c3e8e053f56f00c0df0614c9|
| SHA1       | ac8583c42ebe918e3a8e2d0df78819d2c34d6e7b|
| SHA256     | df899b52549a484b5f5be15743a85582eba54a2149f88b9790da60c927af5104|

Upon extraction, the content, displayed below, are a file and folder named `Sketch Pack` with three more files.

C:.
│   `Wargaming_nft_presentation_for_artist - www.clound.com`
│
└───`Sketch Pack`
        `sketch_nn_wot_tank1.png.lnk`
        `sketch_nn_wot_tank2.png.lnk`
        `sketch_nn_wot_tank3.png.lnk`

In the following chapters a closer inspection of the files is presented.

## 500 Mb of nothing

The file `Wargaming_nft_presentation_for_artist - www.clound.com`, despite its name, is an MS-DOS application and is not really 500 Mb in size, as opposed to what appears on Windows. In fact, the file was filled with null-bytes to purposely thwart automated analysis by Antivirus tools, which tyipically have a size limit (ref: https://capec.mitre.org/data/definitions/572.html). Looking at it in a Hex editor, one can clearly see that is has a legitimate MZ header, but also that the majority of the file is empty. This is clearly evident in Pe-bear.

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/NFT/images/presentation_empty.png)<br />

The file's details are shown in the table below.

| *Type*     | *data*|
| :---       |    :---|
| Name       | Wargaming_nft_presentation_for_artist - www.clound.com| 
| MD5        | c9b92bc28fb1339eb450ff2061760352|
| SHA1       | bcff8fc3b1e98c10b168fcb5c61a56b51092dda1|
| SHA256     | 087f89fb729da54b2f2e2f68266c2f4fa51f7b14ecb5d6b7b0c550d9f8d64e88|

The binary is a Portable Executable (PE) written in dotNET, and can be entirely decompiled. Although it appears to employ some basic obfuscation, the code is easy to read and immediately tells us the main purpose of the binary in this `case-switch` contained in the `Main()`:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/NFT/images/discord_download.png)<br />

It downloads a file with `.png` extension from Discord, reverses it and treats is like a ByteArray. Doesn't really sound like a PNG, does it? Take a look at the file last bytes:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/NFT/images/dll.png)<br />

That is an MZ header, and this is a Portable Executable (PE). The file is a DLL written in dotNET, and this time obfuscated, named `Szclhysb.dll`. The following table shows its details.

| *Type*     | *data*|
| :---       |    :---|
| Name       | Szclhysb.dll| 
| MD5        | dee66f52d1ded3e7d0c8e6e27441d7f4|
| SHA1       | e922c69518557345dd46fb9d4e3da7e52d30a593|
| SHA256     | 671235cec67289a4e398935f88666157c9b78fbd6bee599d6b34616767efe100|
| Compiled   | Tue Jan 11 16:13:05 2022 (0x61DD9E81)|

This DLL contains the logic for the infection of the system. The whole 500 Mb program will also be copied to `%appdata%\Microsoft\Windows\Start Menu\Programs\mplayer\` as `mplayer.exe`, to achieve persistence, and `%temp%`.

## Shortcuts to... infection!

Windows shortcuts, or LNKs, have been abused in every way possible by Threat Actors ([this](https://splashdot.github.io/LNK/) is an article I wrote on the subject). In this instance, they appear like regular PNG files. This is because Windows preserved the original icon, and did not change the file extension. So, to an untrained eye, they will look like legitimate images.

The following picture shows the LNK file's EXIF data, and shows that the shortcut is actually invoking `PowerShell` with an obfuscated command line. Also, note that the timestamps present are on the same date and time of the day as the DLLs compilation time.

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/NFT/images/shortcuts_exif.png)<br />

There is no need to go as far as analysing the shortcut with forensic tools: a simple `right-click > Properties` would have shown part of the PowerShell command, enough to arise suspicion.

The three LNKs are actually the same file with different filenames, as they share the same hash. Their details are visible in the table below.

| *Type*     | *data*|
| :---       |    :---|
| Name       | sketch_nn_wot_tank_1/2/3.png| 
| MD5        | 0af5392da151a262a9249bd03c5d8748|
| SHA1       | 9ead6f36ae43ac36555f78a3ab43b1a70bab7d16|
| SHA256     | 95192a5ea068f2042e6fe26423299d82aa781d4d7de3f08400198103d6f9e4f6|

The Powershell script contains two arrays that are turned into characters by the function `nT()`.

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/NFT/images/powershell_shortcut.png)<br />

The smaller one (`$ac`) translates to `IEX`, while the other (`$es`) is `mshta https://cdn.discordapp.com/attachments/930485322846986240/930495210625064990/pngsuka.hta`. So, the script downloads and executes an HTA application. `pngsuka.hta` contains obfuscated VBScript (which is trivial to deobfuscate), and it's around 600 lines long. Much like the initial PowerShell, this VBScript translates a long array into characters and executes it. The result is yet more obfuscated PowerShell, that aims at downloading, saving and executing a PE file from a Discord CDN. The function responsible for downloading and executing the file is displayed in the following image.

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/NFT/images/powershell.png)<br />

The resulting binary (`PNGBLYAT.exe`) is also an obfuscated dotNET PE (details in the table below). Its infection logic is the same as `Szclhysb.dll`, and will be presented in the next paragraph.

| *Type*     | *data*|
| :---       |    :---|
| Name       | PNGBLYAT.exe| 
| MD5        | c43f329192fb3dd114c1149086c16f5f|
| SHA1       | 8e21c7b8ee01b45398b28371ba1766362faf3221|
| SHA256     | 423c964bf7c78b8b83f8864b854d6cb0c6b18ddb8c46849eae3b569951f83443|

This is a summary of this infection chain:

`LNK` -> `PowerShell` -> `HTA with VBScript` -> `PowerShell` -> `EXE`

## Ok, but happened to my PC?

Both the shortcuts contained in the `Sketch Pack` folder and the 500 Mb executable convey the same malware to the host. It is likely that the Threat Actor wanted to be sure to infect the host, and thus used two different methods. This also helped the archive seem more legitimate: if it contained only the shortcuts or only the executable, it would be more suspicious.

The final payload is an information stealer that contacts the Threat Actor's Command and Control (C&C or C2) and retrieves a list of files to look for. Then, it will browse the filesystem and send the files that match over to the TA through the C2. The server used is hosted at `185.215.113.15`, and listens on port `8080`.

The data the malware looks for can be separated into three categories:

i) all the files with extension `.txt`, `.key`, `.wallet`, `.seed` located in `%userprofile%\Desktop` and `%userprofile%\Documents`.
ii) all the files in the folder `%USERPROFILE%\AppData\Local\$name\User Data` and `%USERPROFILE%\AppData\Roaming\$name`, where `$name` indicates browsers (such as Chromium, YandexBrowser, Vivaldi,...) and other programs (such as NVIDIA GeForce Experience, Steam and Thunderbird).
iii) cryptocurrency wallets (e.g., Electrum, Exodus, Atomic,...).

In essence, the Threat Actor is stealing credentials, cookies, documents, licenses, and many more from infected PCs.

### How do I know if I was infected?

Look in the following paths:

-`\Microsoft\Windows\Start Menu\Programs\` for a folder named `mplayer` with an executable named `mplayer.exe`
-`%temp%` for an executable file more than 500Mb in size named something like `Wargaming_nft_presentation_for_artist - www.clound.com`

If you have matching files in these locations, it means you were infected. In case you have some kind of network logs, look for communication with the IP `185.215.113.15` on port `8080`.

### What can I do?

First, calm.

Then, change all the passwords for all the accounts you have, and enable MFA oon everywhere you can. Try as much as you can to find evidence of intrusion in your accounts: you may have received a warning email, or even some notifications in the app. If you suspect that someone might have accessed your accounts, contact the platform's support. Delete the above mentioned files and run an Antivirus scan.

