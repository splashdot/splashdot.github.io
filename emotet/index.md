# New Emotet spam campaign (July, 2020) - Analysis of the VBA macro

["@elioxyz"](https://twitter.com/elioxyz)

## Intro

Thanks to the work of a few invested people like [@Cryptolaemus](https://twitter.com/Cryptolaemus1) we were able to detect a new wave of Emotet spam, starting on 17th, July 2020.
I have downloaded a few samples and tried extracting network indicators as an excercise. I was expecting a much simpler code, but when I realised the intricacies I decided to write it all down.

## Samples

I have downloaded some documents from [Malware Bazaar](https://bazaar.abuse.ch/browse/) with tag Emotet, all of which were uploaded on the 17th. All of them presented the same behaviour, so I'll choose a random one to show the code of.

MD5: 10127152f4dc273b931eb4c65c7e9814 <br>
VT Score: 20/62 <br>
[VirusTotal](https://www.virustotal.com/gui/file/25941d1dac273e9438afe0bf0b3a913474ff21b6c559c8f9c5a1820eac5e6281/detection)

## Initial analysis

Running `olevba.py` and `oledump.py` shows some results, as the document does in fact contain macros:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/emotet/images/oledump_1.PNG)

`joiwweiquvair` is very simple:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/emotet/images/oledump_2.PNG)

So the objective becomes now to understand `yuamcuatpaztheubchuthpiv`, wich is contained in `kuujdout`. I've dumped it and opened it on a text editor for a better view.
The code is around 270 lines long and is heavily obfuscated, here are some lines that are put there to disturb analysis and automatic detection, they appear several times throughout the code:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/emotet/images/sublime_1.PNG)

Once removed we end up with still a very hardly readable code, given that variables and functions are referenced many times around the code as a mean of confusion. It contains four functions:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/emotet/images/sublime_2.PNG)

Of particular importance is the string `vaodboorqueodquuuthcav`, which translates into `winmgmts:win32_process`.
However, following the code does not reveal much about network indicators, as it apears that the majority of it is meant to create a very real-looking prompt to enable macros.

In order to find the other part of the code we need to poke into the other "unusual" directory in the .doc file (`zouzluumthoempooh`), invoked by `conzuugdeerboocchath()`. <br>
This is the output of `tree` run against the directory /Macro:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/emotet/images/tree_1.PNG)

The file we are going to be interested in is `Macros/zouzluumthoempooh/i09/o`:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/emotet/images/xxd_1.PNG)

## Finding the domains

The file is a block of data that contains a string that can be decoded like the previous ones with `quovcoaljiochchuav()`. I dumped it and sure enough it is a base64 encoded Powershell command:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/emotet/images/base64_d.PNG)

Once decoded is once again an obfuscated Powershell script.
Here it is a little prettified (I have removed some useless variables and formatted it):

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/emotet/images/final_1.PNG)

The code is rather straightforward, it requests some domains and if contents are found, the file is written to disk and executed.

Finally I was able to find the domains serving the Emotet executable:

hxxp://mican.tri-comma[.]com/wp-admin/BmKOeycm0704/ <br>
hxxp://defensacovid[.]com/wp-admin/dGzIMVvo/ <br>
hxxp://doorbhai[.]com/wp-admin/Wq6Kdoisk1r4060453/ <br>
hxxp://agilentgame.reviewshell[.]com/cgi-bin/csoa45gw51315935/ <br>
hxxp://karir-up[.]com/wp-admin/CCzj96yk23/ <br>

## Considerations

As others have already noted the macro has some possible indicators of compromise that could be used to generate detection rules. One of them is definitely the intense use of chr() in the VBA code. Also, all the macros seem to cycle through 5 hardcoded domains.

What is intriguing is that CLI tools were a little unsure of the documents behaviour. For instance, mraptor does not detect files being written to disk:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/emotet/images/mraptor_1.PNG)

VirusTotal scores also seem to vary greatly: so it seems that the authors did a very good job at obfuscating the code intentions.

Lastly, domains extraction could be automated, supposing that all of the documents have the same structure. That I will have to look into once I have accumulated a more reasonable amount of samples.