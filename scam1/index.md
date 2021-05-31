# A different type of scam

[@elioxyz](https://twitter.com/elioxyz)

[Home](https://splashdot.github.io)

## Intro

A type of scam regarding the abuse of the online screenshots sharing service Lightshot has been identified in the wild. Lightshot is a screenshot capturing program that allows screenshots to be uploaded to a web-based service hosted on `prnt.sc`, in order for them to be easily shared: their URI is composed of a seemingly random seven characters alphanumeric string, e.g.: `prnt.sc/12abcdef`. Considering the lack of access controls and the predictability of the URI, other people's screenshots can be easily viewed by bruteforcing the URL.

An unkown actor is uploading several images containing login information to bitcoin exchange websites, with accounts that appear to have some balance. These websites are fake and contain no functionality other than asking for a small fee to confirm cryptocurrency withdrawals. The core idea is that people bruteforcing the website's URLs are going to find and log into these fake exchanges and try to withdraw the money, but in order to do that they must first give some money to the actors. Following is a more detailed explanation of the scam's mechanisms.

## Abusing Lightshot

Lightshot comes as an executable that installs itself as a service and waits for the user to press the PrintScreen button. Once taken, the screenshot can be uploaded to `prnt.sc` with a unique URL.

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/scam1/images/lightshot_1.PNG)

The URL can be easily changed to view other screenshots, and while doing so one can quickly notice a pattern consisting of several images of login information to websites related to bitcoins. The images range from fake gmail screenshots of a password reset notification with cleartext credentials, to notepad++ screenshots, up to even handwritten notes. Some examples are reported below.

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/scam1/images/fake_1.PNG)
![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/scam1/images/fake_2.PNG)

## The Actor's infrastructure

A total of five different fake websites has been discovered:

`sellbuy-btc[.]online`
`crypto-trade24[.]eu`
`bit-trade[.]pro`
`crypto-wallet-btc[.]com`
`btc-ex[.]org`

Their WHOIS information show no common signs, other than the fact that they are all relatively new domains, registered a few weeks to some months ago. Searching for similar websites on urlscan yields some results, suggesting that there may be many others. For instance, the websites `sell-buy-btc[.]online` and `bit-trading[.]online`, small variations of the domains above, are hosting the same fake websites.

The actor employs two different websites templates: one is used by `crypto-wallet-btc`, `sell-buy-btc`, `sellbuy-btc` and `bit-trading`, while the other one is used by `crypto-trade24`, `btc-ex` and `bit-trade`. Searching on urlscan for the favicons' hashes show that the first template is partially copied by `cex.io`, a legitimate bitcoin exchange. However, the websites are thought to use other bitcoin exchanges' parts: in fact, they appear as if they are up-to-date, full-fledged and complete modern websites with dashboards, legal information and "About us" pages. Although at first glance they appear to be legitimate, a closer look reveals that their functionality is somewhat broken, e.g. there is no possibility to signup, some links are not leading anywhere, and contact information are made up. It looks like the only thing that can be done is logging in with the fake account: even then, the only available working operation seems to be withdrawing cryptocurrencies.

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/scam1/images/login_1.PNG)
![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/scam1/images/login_2.PNG)

When trying to withdraw money, the websites prompts the user to confirm the request by sending a small fee to an address controlled by the actors.

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/scam1/images/confirm_1.PNG)

## Embedded scripts

The websites' malicious intents are visibile through their source code. The ones with the first template contain a plaintext JS script in the HTML source code that generates the confirmation request. Following is a snippet of the part shown when chosing to withdraw BTC:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/scam1/images/withdraw_1.PNG)

As can be seen, everything is hardcoded and simply aims at having the user pay the fee.

## Other servers

The websites discussed above use three different favicons. Their MurmurHash values have been calculated and searched for on Shodan: in this way new, different IPs using the same favicon were discovered. Two of the three favicons have the following matches:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/scam1/images/favicon_1.PNG)
![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/scam1/images/favicon_2.PNG)

Two of the four IPs show some connections with the fake websites. For instance, this is the page that appears when navigating to `144.91.125[.]234`:

![alt text](https://raw.githubusercontent.com/splashdot/splashdot.github.io/master/scam1/images/server_1.PNG)

This page is the same used in some of the other websites. Note that the URL contains one of the websites mentioned above.

## Wallets used by the actors

The wallets' addresses contained in the websites are the following:

| *Currency* | *Wallet*								      |
| :---       |    :---   								  |
| Bitcoin    | 1Pai1bdsHzYEtc87GAChJRe2BMBVn4Kq4G     	  | 
| Bitcoin    | 1Npvg7sB8SPUi3L9qPLrQrq4y84ZcGHJF6         |
| Bitcoin    | 37BEduTbBh9z68gDdDRAnkx2JTb2rcA1nr		  |
| Ethereum   | 0x9fde7bd79830b7c6df049c9b6fcf6f04f7c9e62b |
| Ethereum   | 0x90D51665164baf6eCF29cDAcDC9390FB7660bb0c |

As of the time of writing, they have up to dozens of transactions for a total of around 0.2384 BTC and 1 ETH. Therefore, it can be concluded that many victims have fallen for this scam.

## Final words

Although this scam seems to be fairly successful, what makes it interesting is the fact that it targets people who are knowingly gaining unauthorized access to a bitcoin exchange account, thus avoiding the possibility that they may report the accounts (as they themselves were doing an illegal activity!). This scam leverages the illegitimacy of the intentions of the people looking for personal information on the website `prnt.sc`.

The actor seems sufficiently knowledgeable about their OPSEC: they mask themselves behind services like Cloudflare, they avoid adding contact information on WHOIS and SSL/TLS certificates, they use different hosting providers and their websites seem hardened enough to prevent basic information gathering such as directory enumeration. For these reasons, attribution was not possible.

## IOCs

Domains:

`sellbuy-btc[.]online`
`crypto-trade24[.]eu`
`bit-trade[.]pro`
`crypto-wallet-btc[.]com`
`btc-ex[.]org`
`sell-buy-btc[.]online`
`bit-trading[.]online`

IPs hosting the websites:

`45.147.197.180`
`85.128.138.167`
`172.67.144.250`
`172.67.163.128`

IPs using the same favicons:

`145.249.106.231`
`144.91.125.234`
`163.172.143.114`
`149.56.165.224`

Favicons' MurmurHash values:

`1522891389`
`-1799963930`
`-2126251205`

Actor's wallets:

`1Pai1bdsHzYEtc87GAChJRe2BMBVn4Kq4G`
`1Npvg7sB8SPUi3L9qPLrQrq4y84ZcGHJF6`
`37BEduTbBh9z68gDdDRAnkx2JTb2rcA1nr`
`0x9fde7bd79830b7c6df049c9b6fcf6f04f7c9e62b`
`0x90D51665164baf6eCF29cDAcDC9390FB7660bb0c`