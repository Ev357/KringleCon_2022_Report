# KringleCon 2022 Report
## Tolkien Ring
### Wireshark Practice
1.
- So the most common object is http, so i tried and... yeah.
- answer: `http`
2. 
- Wireshark -> File -> Export Objects -> HTTP...
- We can see here that the biggest file is the app.php file..
- answer: `app.php`
3.
- Wireshark -> File -> Export Objects -> HTTP...
- We can also see here the packet number.
- answer: `687`
4.
- Wireshark -> File -> Export Objects -> HTTP...
- If we click on the app.php, wireshark will display the packet, and we can see in the source the IP.
- answer: `192.185.57.242`
5.
- Wireshark -> File -> Export Objects -> HTTP... -> app.php (The larger one) -> Save
- If we explore the app.php file we can see in the javascript function that it save a file from the blob to the host with file name.
- answer: `Ref_Sept24-2020.zip`
