# Pmaping v.1.0
Scanning tool written by python,understand some common scanning technique works.

## Features
- ![VERSION](https://img.shields.io/badge/version-1.0-orange.svg)

	* added TCP SYN scan.
	* added TCP connect scan.
	* added UDP scan.
	
## Requirements
- Python 3.5+
- Libpcap 1.7.4+
- Pcapy 0.10.8+
- dnspython 1.12.0+

## Installation
- Ubuntu
		
		sudo apt-get install libpcap-dev
		
- Arch Linux

		sudo pacman -S libpcap
		
- Python libraries
		
		pip install pcapy dnspython

## Tested platforms
- ![UBUNTU](https://img.shields.io/badge/Linux-Ubuntu-orange.svg) ![ARCH LINUX](https://img.shields.io/badge/linux-Arch%20Linux-blue.svg)

## Note
- Arch linux got problem with libpcap and pcapy library, so in TCP SYN and UDP scan pcapy can't timed out that will make tool stuck and freeze.
