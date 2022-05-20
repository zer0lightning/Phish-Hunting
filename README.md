Original Article: https://decentsecurity.com/#/malware-web-and-phishing-investigation/

**Easily Report Phishing and Malware**

This is how you can strike back at criminals sending phishing spam - by getting their webpages on blacklists. Blocking their sites helps protect other people and helps researchers trying to stop this. Sites can be blocked within 15 minutes of your report, but you may not immediately see it. 

Some phishing pages might also use 0-days exploit to target researchers or increase effectiveness. Maximum precaution should be observed - dedicated analysis machines in a secure environment is necessary.

**Preparation**

1. Create an analyst lab (VM Firewall > Observation VM).
2. Firewall VM: Create rules, dedicated VLAN to harden and isolate connections from your real network.
3. Internet <> Firewall VM + VPN < Host to Host Adapter > Observation VM.
4. Observation VM: Apply hardening, updates, tools, bookmarks and applications.
5. Create a snapshot.
6. After each analysis, restore to original snapshot.

**Report phishing website:**

Right-click the link in the phishing email, and copy the hyperlink. Do not click the link, which is less useful to security companies.

**Evaluation stage**

1.  [MXToolbox Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx) - Email headers can provide valuable diagnostic information like hop delays, anti-spam results and more.
2.  [urlscan.io](https://urlscan.io/) - Quickly get a screenshot and redirects (run by [@heipi](https://twitter.com/heipei))
3.  [CheckPhish.ai](https://checkphish.ai/) - Phishing detection engine (run by [RedMarlin](https://www.redmarlin.ai/))
4.  [phishcheck.me](http://phishcheck.me/) - Custom phishing detection engine
5.  [VirusTotal](https://www.virustotal.com/#/home/url) - Checks against multiple blacklists
6.  [any.run](https://app.any.run/): Remotely download and interactively sandbox analyze arbitrary file downloads (run by [@anyrun\_app](https://twitter.com/anyrun_app))
7.  [DomainTools](https://whois.domaintools.com/) - Registration information
8.  [MXToolbox](https://mxtoolbox.com/blacklists.aspx) - SMTP/IP blacklist check
9.  [Maltiverse](https://maltiverse.com/collection) - IOC search
10.  [URLVoid](https://www.urlvoid.com/) - URL reputation
11. [WhereGoes](https://www.wheregoes.com/) - Redirect tracker
12. [WannaBrowser](https://www.wannabrowser.net/) - User agent spoofer
13. [Site-Shot](https://www.site-shot.com/) - Screenshot a website
14. [Browserling](https://www.browserling.com/) - Cross browser testing

**Virtual Systems Online**
1. [APKOnline](https://www.apkonline.net)
2. [OnWorks](https://www.onworks.net)
3. [BrowserStack](https://www.browserstack.com)

**Reporting stage**

[Phish.Report](https://www.phish.report) - Phish Report monitors the status of phishing sites giving you to the minute info about when the site first became active, how quickly you detected it, what actions were taken, when the attack became inactive.

1.  [Google](https://www.google.com/safebrowsing/report_phish/) - Block in Chrome, Firefox, Android, iPhone, Google, and more
2.  [Microsoft](https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site) - Block in Edge, Office 365, and Internet Explorer
3.  [NetCraft](http://toolbar.netcraft.com/report_url) - Send to computer security companies
4.  [Symante](https://submit.symantec.com/antifraud/phish.cgi)[c](http://rulespace.com/swg-ratertool/tool.php) - Submit to Norton
5.  [Blue Coat](http://sitereview.bluecoat.com/sitereview.jsp) - Symantec has not yet integrated with Norton submission
6.  [McAfee](https://www.trustedsource.org/en/feedback/url) - Select real-time, click Check, and click Submit at the bottom
7.  [Websense/Forcepoint](https://csi.websense.com/)
8.  [Webroot BrightCloud](http://brightcloud.com/tools/change-request-url-categorization.php) - Provides data to PaloAlto firewalls, many others.
9.  [Cisco PhishTank](https://www.phishtank.com/add_web_phish.php) - Wide distribution, but requires registration.
10.  [Kaspersky](https://virusdesk.kaspersky.com/)
11.  [CIRCL](https://www.circl.lu/urlabuse/) - Shares with European partners, lookup and click "Send report to CIRCL"

**Report phishing/file hosting abuse directly:**

**Link shorteners:**

*   [bit.ly: Report spam](https://support.bitly.com/hc/en-us/articles/231247908-I-ve-found-a-bitlink-that-directs-to-spam-what-should-I-do-)
*   [goo.gl: Report spam](https://goo.gl/#reportspam)
*   [is.gd: Report spam](https://is.gd/contact.php)
*   [x.co: Report abuse](https://supportcenter.godaddy.com/AbuseReport/)
*   [tiny.cc: Report abuse](https://tiny.cc/contact)

*   [000webhost.com: Report abuse](https://www.000webhost.com/report-abuse)
*   Dropbox: [abuse@dropbox.com](mailto:abuse@dropbox.com)
*   SugarSync: support \[at\] sugarsync.zendesk.com
*   [Weebly: Report spam](https://www.weebly.com/spam)
*   [Wix: Report spam](https://www.wix.com/upgrade/abuse#!spam-report/c18hy)

**Extra-credit phishing reporting:**

**Via Email:**

*   [spam@uce.gov](mailto:spam@uce.gov)
*   [reportphishing@apwg.org](mailto:reportphishing@apwg.org)
*   [phishing-report@us-cert.gov](mailto:phishing-report@us-cert.gov)
*   [phish@office365.microsoft.com](mailto:phish@office365.microsoft.com)

**To representative organizations:**

*   Financial companies - [FS-ISAC](https://www.fsisac.com/contact-us)
*   Universities - [REN-ISAC](https://www.ren-isac.net/contact/index.html)

**Via Twitter:**  
If you have a Twitter account, message these people the link (add a space somewhere so clicking it doesn't work). They are high-powered researchers with lots of connections who track down clues and **shut down** entire constellations of fraud. Like computer Batman.

*   [illegalFawn](https://twitter.com/illegalFawn)
*   [phishingalert](https://twitter.com/phishingalert)

**Other malware tools:**

*   [any.run](https://any.run/): Interactive sandbox for arbitrary files
*   [IRIS-H](https://iris-h.services): Analyze Office, RTF, LNK
*   [sekoia](https://malware.sekoia.fr/new): Broad frontend to multiple analysis tools
*   [quicksan.io](https://quicksand.io/): Analyze Office documents
*   [cryptam](http://cryptam.com/): Analyze Office documents
*   [PDFExaminer](http://pdfexaminer.com/): Analyze PDF files

**Report malware:**

1.  [VirusTotal.com](https://virustotal.com) (Shares reports publicly, shares files with Premium subscribers)
2.  [Hybrid-Analysis.com](https://www.hybrid-analysis.com/) (Shares reports and files publicly, uses Payload Security's VxStream sandbox)
3.  [Malwr.com](https://malwr.com) (Shares reports and files publicly)
4.  [Microsoft](https://www.microsoft.com/en-us/security/portal/submission/submit.aspx) (Select 'Home User')
5.  [Webroot](http://snup.webrootcloudav.com/SkyStoreFileUploader/upload.aspx) (Detections and threat intelligence go to multiple other products)
6.  [Kaspersky](https://scan.kaspersky.com)
7.  [ClamAV](https://www.clamav.net/reports/malware) (Especially for files that came through email, used in many spam filters)
8.  [Emsisoft](https://www.emsisoft.com/en/support/submit/)

**Report phishing/spam text (SMS) message:**

Copy the contents of the spam SMS and paste it into a message to this four-digit number. This reports it to your phone company so they can search for who sent it and block them. Don't click the link, it could be dangerous!

 **7 7 2 6 (** S - P - A - M )

**On iPhone:** Hold your finger on the message, tap "More...", tap the Forward icon in the bottom right of the screen.

**Report unsolicited calls and SMS**

Use the form on [SpamResponse](https://www.spamresponse.com/report-spam).

**Report abuse to website hosts:**

Find who hosts the website with [WhoIsHostingThis](http://www.whoishostingthis.com/) and search Google for "webhost + abuse" to find their complaint contact information.

**Investigate IP/domains:**

*   [Pulsedive](https://pulsedive.com/)
*   [Netcraft SiteReport](http://toolbar.netcraft.com/site_report)
*   [ThreatMiner.org](https://www.threatminer.org/)
*   [ThreatCrowd.org](https://www.threatcrowd.org/)
*   [AlienVault OTX](https://otx.alienvault.com/)
*   [RiskIQ PassiveTotal](https://www.passivetotal.org/login) (requires registration)
*   [Cisco SenderBase](http://www.senderbase.org/)
