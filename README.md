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
- So i just find this guide on the HackTricks website [Docker Breakout](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#mounting-disk-poc1).
- If we do `sudo -l`, we can see we are already root.
- So we can check if there are any disks attached with the `sudo fisk -l` command.
- We can see here the `/dev/vda` disk, so we can just mount it `sudo mkdir -p /mnt/hola;sudo mount /dev/vda /mnt/hola`.
- We successfully mount the disk we can navigate to it `cd /mnt/hola` and find the flag `cat home/jailer/.ssh/jail.key.priv`.
- Yeee `082bb339ec19de4935867`.

### Jolly CI/CD
- Ok, so first things first this challange need realy some time to bake.
- In the meantime, you might have noticed that *Tinsel Upatree* leaked the git repository.
- I know it's stupid, but you can watch it (the 10 means the reload time in seconds) `watch -n 10 "git clone http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git"`.
- Once you see *Updating files* stuff you are ready to go. Just remove the repo `rm -f -r wordpress.flag.net.internal` and clone it again properly `git clone http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git`.
