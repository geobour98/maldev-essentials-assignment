# Malware Development Essentials Assignment

This is a simple dropper, which was developed for the assignment part of the course: Malware Development Essentials, by sektor7. The course can be found here: [MalDev Essentials](https://institute.sektor7.net/red-team-operator-malware-development-essentials). The payload is a MessageBox, just for PoC purposes.

*The implant was developed for educational and learning purposes only!*

## Features

- AES encrypted shellcode and strings
- Obfuscated function calls, by creating pointers to them
- Payload stored in the resources (.rsrc) section of the PE 

## Getting Started

By executing `implant.exe`, a process injection happens into `explorer.exe`, which pops up the MessageBox coming from the `explorer.exe` process.

> A detailed blog post is coming soon! 
