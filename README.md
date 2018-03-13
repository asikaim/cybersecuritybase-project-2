cybersecuritybase-project-2
======

Course Project II for F-Secure Cyber Security Base MOOC

Setup
------

Target machine is Metasploitable3 using Snort v. 2.9.8 with registered rules (I couldn’t get community rules working because of mysterious rule classification issues). Attacker machine is Kali Linux v. 2018.1. Both machines are running on Virtualbox v. 5.2.6 which is running on Windows 10. Kali and Metasploitable3 are both on the same network.


Portscan on Metasploitable3 
------

First, I ran netdiscover from attacker machine, which gave away IP address of our target.

![alt text](/img/img1.jpg)

After that I used nmap to do port scan on all 65 536 TCP ports
![alt text](/img/img2.jpg)
![alt text](/img/img3.jpg)
 
 
The scan results gave away a lot of valuable information about services running on target machine. There is no authentication required to access the administrative functions, default credentials are not changed and there are several outdated versions running. Snort didn’t alert about anything, because port scan detection configurations has been commented out from snort.conf on default. I didn’t bother to change snort.conf at this point, so I moved on.


#1.Exploiting Elasticsearch v1.1.1 (CVE-2014-3120)
------

Googling around possible vulnerabilities (on services that nmap gave away), I decided to tackle Elasticsearch first. I went to check out if Metasploit already had an exploit for this vulnerability.

![alt text](/img/img4.jpg)
 
Surprise, surprise…
First, I wrote “use exploit/multi/elasticsearch/script_mvel_rce” to choose the exploit. Then I set the remote host’s IP to address one that is assigned to target machine by writing “set RHOST 172.28.128.3.” After that I ran the exploit.

![alt text](/img/img5.jpg)
 
Exploit worked as intended and I got shell on Metasploitable3. After that I used “whoami” to check my privileges and found out that I am the ultimate authority with the highest possible level of privileges on Windows machine.

![alt text](/img/img6.jpg)

Snort didn’t log any alerts, but after uncommenting line 811 (depends about ruleset) on server-other.rules file, Snort produces the following message:
`SERVER-OTHER ElasticSearch script remote code execution attempt [**] [Classification: Attempted User Privilege Gain]`


#2. Exploiting ManageEngine (CVE-2015-8249)
------

Nmap showed us that Metasploitable3 is running Apache HTTPD service on port 8020. Using browser to access https://172.28.128.3:8020 we can verify that Apache is running ManageEngine Desktop Central 9 with default admin password. Also, administration panel shows us that the build version is 91084. Google shows us that this build has known vulnerabilities which can easily be exploited on Metasploit.

![alt text](/img/img7.jpg)
 
Once again, Snort doesn’t alert about anything, but this can easily be changed by fixing rules. Uncommenting lines 1854-1856 on server-webapp.rules gives us following:
`SERVER-WEBAPP ManageEngine Desktop Central FileUploadServlet directory traversal attempt [**] [Classification: Web Application Attack]`


#3. Exploiting WordPress (CVE-2016-1209)
------

After seeing previous Metasploitable exploits, I figured out that there must be a weakness on some of the forms. I had some problems running this exploit until I figured that my TARGETURI and FORM_PATH was wrong. Google was a great help here. Previously I didn’t even think about those pre-installed flags that were made into Metasploitable3.
 
![alt text](/img/img8.jpg)

After uncommenting line 2284 in server-webapp.rules and adding the port 8585 into monitoring HTTP traffic, Snort gives the following alert:
`SERVER-WEBAPP WordPress Ninja Forms nf_async_upload arbitrary PHP file upload attempt [**] [Classification: Attempted Administrator Privilege Gain]`


#4. Exploiting Apache Struts (CVE-2016-3087
------

I tried several ways to exploit Apache on port 8282 before I found out that Metasploitable3 had a legit list of vulnerabilities in GitHub (https://github.com/rapid7/metasploitable3/wiki/Vulnerabilities#apache-struts). No need to Google around. I feel so stupid now. Oh well… Let’s do this. 

![alt text](/img/img9.jpg)

We can get Snort to figure this out by uncommenting lines 118 and 119 from server-apache.rules (which I had already done) and adding port 828 for monitoring. This gives us following message:
`SERVER-APACHE Apache Struts remote code execution attempt [**] [Classification: Attempted Administrator Privilege Gain]`


#5. Bruteforcing SSH
------

It’s probably a good idea to grab some user names while we are here. I pasted the user names into file that I named users.txt. 

![alt text](/img/img10.jpg)

Metasploit has a ssh_login module which can be used to perform brute-force attempts. Let’s check it out.

![alt text](/img/img11.jpg)
![alt text](/img/img12.jpg)
 
User “vagrant” has “vagrant” as password, which we have known all along. Snort didn’t give any reaction and frankly, I don’t even know if rule changes can help us here. Snort could probably be generated for slower (longer) SSH brute force attempts, but for such a fast SSH connection it wouldn’t be wise to start raising alert flags (considering admin’s point of view).


Is it easier to fix the application than to detect attacks?
------

Both are obviously needed, but if we take the assignment literally, we must consider the target system, applications, and attackers. Complexity, vulnerabilities, and experience of the parties involved all play into this.
Often servers are not up to date and software that isn’t up to date have known vulnerabilities. 
Fixing applications is a complicated matter, because software being used might be proprietary and/or legacy. Monolithic software with millions of lines of code on dead language are obviously near impossible to fix. This leads to a lot of vulnerabilities on system running the software and that’s where intrusion detection comes in. Intrusion detection is at least a countermeasure (even though not a direct one) and it gives information about the possible vulnerabilities both on the system and its applications. Systems that are based on modern open source are obviously easier to fix, but first you must find the vulnerabilities, so considering the problem at hand, intrusion detection is also needed.
