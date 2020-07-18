# Finding IOCs in a malicious Excel VBA mcacro

## Analysis

This is the analysis and deobfuscation of a malicious Excel VBA Macro from a sample found on [Malware Bazaar](https://bazaar.abuse.ch/browse/)

The sample had tag "Lokibot", hence the filename I will be using (loki.xlsx).

At the time of writing the hash has a 37/62 score on VT:

MD5: b1258a49ab3ff21f9c8587cf2a8d17ec
SHA-256: edbb25dfdfe594eb597484e31968fafa0462e81b203497aff0f5a60879860e53
[Virus Total](https://www.virustotal.com/gui/file/edbb25dfdfe594eb597484e31968fafa0462e81b203497aff0f5a60879860e53/detection)

This is the output of `olevba.py -a loki.xlsx`:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/loki/images/loki_olevba1.PNG)

It found some OLE streams. Inflating the file with `7z x loki.xlsx` does in fact show a VBA directory with a very big file (ThhfLkbook):

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/loki/images/loki_tree.PNG)

To dump the contents I used oledump.py, and found a rather obfuscated VB script:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/loki/images/loki_wc.PNG)

The script has some blobs of useless code, which I determined by ensuring that the functions declared were not referenced anywhere else.
Once I removed them, I was left with a still long code, and the two parts that draw my attention were of course ShellExecuteA and URLDownloadToFileA, which were also picked up by olevba:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/loki/images/loki_functions.PNG)

Here is where they are called:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/loki/images/loki_references.PNG)

`URLDownloadToFileA` is called with parameter `PGxKUDDrdEbUYGJHGFCNGFgfngjgcgny`, which makes very little sense. The parameter is a variable to which is assigned the value of a string passed to another function `JGVDHlbKUIKYUGkgjHVF()`. So understanding what the function does is needed to determine the URL.
Here is the function, after I cleaned up a little the garbage code:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/loki/images/loki_url_obf.PNG)

The functions takes each element of a reversed/backwards string, calculates its ASCII value, subtracts 1 and the calculates its chr value.

I wrote a simple python script that does exactly this and gave it the encoded URL:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/loki/images/loki_python_deobf.PNG)

So I was able to find the malicious domain:

hxxps://nilemixitupd.biz[.]pl/DFGzsfgs/tuesday.exe

## Takeaways

A simple `grep http` on the macro code, which is a very simple step I typically take when assessing a file, would not detect anything unusual: so, although tools like mraptor and olevba were succesfully able to determine that the Excel file was malicious based on the plaint-text functions URLDownloadToFileA and ShellExecuteA, at a first glance it would appear that no URLs are found in the code. This is why I would also add a signature that detects these obfuscated URLs using Regular Expressions:

`fyf\/(.*)00;tquui`<br>

or <br>

`^(.*)[^00;tquui]`<br> 

Of course this only works for this kind of "algorithm" that subtracts 1, but if it's consistent in the spam campaign it may be able to alert on further malicious attachments.

## IOCs

MD5: b1258a49ab3ff21f9c8587cf2a8d17ec <br>
SHA-256: edbb25dfdfe594eb597484e31968fafa0462e81b203497aff0f5a60879860e53 <br>
Domain: nilemixitupd.biz[.]pl <br>
URL: hxxps://nilemixitupd.biz[.]pl/DFGzsfgs/tuesday.exe <br>
IP: 185.189.112[.]191
