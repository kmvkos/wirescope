"""Structured output parsers for external evidence providers."""

from parsers.nmap import parse_nmap_xml
from parsers.passive import PassivePacketParser

__all__ = ["PassivePacketParser", "parse_nmap_xml"]
