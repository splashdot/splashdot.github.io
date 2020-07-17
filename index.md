## Analysis of malicious VBA Macro ##

This is the analysis and deobfuscation of a malicious Excel VBA Macro from a sample found on [Malware Bazaar](https://bazaar.abuse.ch/browse/)

The sample had tag "Loki", hence the filename I will be using (loki.xlsx).

At the time of writing the hash has a 37/62 score on VT:

b1258a49ab3ff21f9c8587cf2a8d17ec
edbb25dfdfe594eb597484e31968fafa0462e81b203497aff0f5a60879860e53
[Virus Total](https://www.virustotal.com/gui/file/edbb25dfdfe594eb597484e31968fafa0462e81b203497aff0f5a60879860e53/detection)

This is the output of `olevba.py -a loki.xlsx`:
(loki_olevba)

It found some OLE streams. Inflating the file with `7z x loki.xlsx` does in fact show a VBA directory with a very big file (ThhfLkbook):

(loki_tree)

To dump the contents I used oledump.py, and found a rather obfuscated VB script:

(loki_wc)

The script has some blobs of useless code, which I determined by ensuring that the functions declared were not referenced anywhere else.
Once I removed them, I was left with a still long code, and the two parts that draw my attention were of course ShellExecuteA and URLDowloadToFileA, which were also piced up by olevba:

(loki_funtions)

Here is where they are called:

(loki_reference)

`URLDownloadToFileA` is called with parameter `PGxKUDDrdEbUYGJHGFCNGFgfngjgcgny`, which makes very little sense. The parameter is a variable to which is assigned the value of a string passed to another function `JGVDHlbKUIKYUGkgjHVF()`. So understanding what the function does is needed to determine the URL.
Here is the function, after I cleaned up a little the garbage code:

(loki_url_obf)

Te functions takes each element of a reversed/backwards string, calculates its ASCII value, subtracts 1 and the calculates its chr value.

I wrote a simple python script that does exactly this and gave it the encoded URL:

(loki_python_deobf)

So I was able to find the malicious domain:

hxxps://nilemixitupd.biz[.]pl/DFGzsfgs/tuesday.exe

