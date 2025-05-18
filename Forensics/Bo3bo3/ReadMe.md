### Challenge Details
- **Category**: Network Forensics
- **Difficulty**: Medium

In the depths of a chaotic network environment, hidden communications and encrypted secrets flow among the noise. Your task is to analyze the provided capture file, reconstruct key evidence, and uncover the truth behind the suspicious activities. Only a true master of digital forensics will be able to piece together the scattered traces and retrieve the hidden flag.

### Requirements
- Packet analysis proficiency
- Protocol understanding (HTTP, SSL, TCP/IP)
- Basic cryptography knowledge
- Attention to detail

![Challenge GIF](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExYXI0bWdrdWhjcGdqOWpqa2lqbGJwdDJ2MWc2a3A2Y21vbmdrbXZ6dyZlcD12MV9naWZzX3NlYXJjaCZjdD1n/077i6AULCXc0FKTj9s/giphy.gif)

---

*Author: xtle0o0*

https://www.mediafire.com/file/js2ykpou4mt66xi/bo3bo3i.zip/file

Participants were provided with a link to a zip file containing a bo3bo3.ad1 file and a capture.pcapng. Based on the description, we can see "encrypted secrets," suggesting the flag has been sent via a secure protocol. The requirements indicate we need understanding of HTTP, SSL, and TCP/IP. Things are starting to become clear.

Let's examine the traffic capture first.

Looking through the protocols hierarchy in TCP, we can see that we have TLS: 
![image](../../assets/{5719A3E4-FE23-4C15-A974-BD81FE6DAB23}.png) 


Let's check the image file: 
![](../../assets/{5DBC2DFB-09C4-421E-9515-585BDBB5E734}.png) 


As we can see, we have a user named BO3BO3.

Let's navigate through the file system and see if we can find something to decrypt the traffic.


Checking Documents, we find a subdirectory inside it containing a sslkeylog.log file: 
![image](../../assets/{E2CEB10F-1EBA-4D92-82EB-FD65AB0CC43E}.png)

By extracting the log file and going to Wireshark, we can use it to decrypt traffic by going to Edit > Preferences > Protocols > TLS and choosing the sslkeylog as Pre-master secret log filename. This gives us our decrypted file:
![images](../../assets/{47F1BBE6-EE2E-4957-8B17-B2D44EE05392}.png)


After clicking Apply, we get a new protocol "HTTP".

To save time, filter for the flag using "CMC", and you will find the flag in headers that were sent to 192.168.33.32 when the user visited http://157.245.47.158:
![image](../../assets/{96582579-7842-4F3F-9F04-026B5CA35B18}.png)


flag: `CMC{D1g1t4l_F0r3ns1cs_3xp3rt_4_L1f3}`