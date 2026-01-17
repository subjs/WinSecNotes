# LLMNR Posioning

LLMNR (Link-Local Multicast Name Resolution) is a protocol that Windows when it needs to find another machine (and it cannot find a DNS server). The Windows machine will broadcast a message
to all devices on the network, asking for the machine.

An attacker can then perform a Man-in-the-Middle attack to intercept the message, and act like the machine (the one that is being searched for). [Impacket](https://github.com/fortra/impacket) has a Python program (Responder.py) that will listen for LLMNR (amoong other) broadcasts.

The Windows client will then try to authenticate (with the MitM machine) and send its username and password (hashed as NTLMv2). The attacker can then take the NTLMv2 password and run it through 
a password cracker to get a plaintext password.

The attacker now has username+password of this account without being on the Windows Machine, but simply being on another machine in the same network.

# Mitigations

1. Microsoft has been pushing to deprecate NTLMv2 password hashes for a while in favor for Kerberos and its ticketing system.

2. Enable Network Access Control - so a MitM program can't just access any network.

3. Require a longer password (so password crackers take longer) and also enforce users to change passwords regularly.
