# HyperRDP
HyperRDP can automatically start a Hyper-V Remote Desktop Protocol server on the host system

# Features
* Adds firewall bypass for RDP
* Adds firewall rules
* Adds group policies to support connecting from the internet outside local network
* Adds a new user account for hidden interaction (remotedesktop password: remotedesktop)
* Patches c:\Windows\System32\termsrv.dll to allow multiple simultaneous connections
* Starts RDP services

# Usage
Compile this and start it as an administrator

# Problems
* Can't actually start the RDP server on the host system fully. Starting the services is not enough. But it does however look like it's started when you go into Windows settings.
* Regular PCs don't normally allow multiple instances/connections so it shows popups and warnings, this can be bypassed with the patch
* Patch is broken for K systems, but works on other Windows 10 systems

# Donate
Bitcoin: 12FP1JisjYCsgfteTLMQQMLnVBs65wZD8G