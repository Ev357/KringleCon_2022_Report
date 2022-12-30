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

## Windows Event Logs
- This one is little bit harder so i will just say the answers:
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