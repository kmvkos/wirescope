# WireScope dependency inventory

Python: `>=3.11`

## Pinned Python runtime

- alembic==1.19.1
- fastapi==0.141.1
- pydantic==2.13.4
- SQLAlchemy==2.0.52
- uvicorn==0.52.4

## Pinned Python development extras

- httpx==0.28.1
- pytest==9.1.1
- scapy==2.7.0

## Required OS packages (Debian / Raspberry Pi OS)

- python3
- python3-venv
- python3-pip
- python3-dev
- iproute2
- libcap2-bin
- ca-certificates
- sqlite3
- tshark
- wireshark-common
- adduser
- passwd

## Optional providers (not Nuclei/Nikto)

- nmap
- openssl
- curl
- bind9-dnsutils
- smbclient
- snmp
- ldap-utils
- ssh-audit

## Optional kiosk stack

- xserver-xorg
- xinit
- openbox
- unclutter
- chromium

## Gated scanners never installed by default

- nuclei
- nikto
