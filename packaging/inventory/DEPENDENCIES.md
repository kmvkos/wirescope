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

## Required OS packages — Debian / Ubuntu (apt)

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
- passwd
- adduser

## Optional providers — Debian / Ubuntu (apt)

- nmap
- openssl
- curl
- bind9-dnsutils
- smbclient
- snmp
- ldap-utils
- ssh-audit

## Required OS packages — Fedora / RHEL / Rocky (dnf or yum)

- python3
- python3-pip
- python3-devel
- iproute
- libcap
- ca-certificates
- sqlite
- wireshark-cli
- shadow-utils

## Optional providers — Fedora / RHEL / Rocky (dnf or yum)

- nmap
- openssl
- curl
- bind-utils
- samba-client
- net-snmp-utils
- openldap-clients
- ssh-audit

## Required OS packages — openSUSE / SLES (zypper)

- python3
- python3-venv
- python3-pip
- python3-devel
- iproute2
- libcap-progs
- ca-certificates
- sqlite3
- wireshark-cli
- shadow

## Optional providers — openSUSE / SLES (zypper)

- nmap
- openssl
- curl
- bind-utils
- samba-client
- net-snmp
- openldap2-client
- ssh-audit

## Optional kiosk stack (local display; not a full desktop)

- cage
- xserver-xorg
- xinit
- openbox
- chromium

## Gated scanners never installed by default

- nuclei
- nikto
