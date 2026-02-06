#!/usr/bin/env python3
"""
RedAudit - SNMP v3 Authenticated Scanner (Phase 4.3)
Uses PySNMP to perform authenticated enumeration of network devices.
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

from redaudit.core.credentials import Credential

# Optional Dependency: PySNMP
try:
    import pysnmp.hlapi as hlapi
    from pysnmp.hlapi import (
        SnmpEngine,
        UsmUserData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
        nextCmd,
        usmHMACSHAAuthProtocol,
        usmAesCfb128Protocol,
    )

    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False
    hlapi = None

    class UsmUserData:  # type: ignore[no-redef]
        pass


logger = logging.getLogger("redaudit.auth_snmp")


@dataclass
class SNMPHostInfo:
    sys_descr: str = "unknown"
    sys_name: str = "unknown"
    sys_uptime: str = "unknown"
    sys_contact: str = "unknown"
    sys_location: str = "unknown"
    interfaces: List[Dict[str, str]] = None
    routes: List[Dict[str, str]] = None
    arp_table: List[Dict[str, str]] = None
    error: Optional[str] = None


class SNMPScanner:
    """Authenticated SNMP v3 scanner wrapper."""

    def __init__(self, credential: Credential, timeout: int = 5, retries: int = 1):
        if not PYSNMP_AVAILABLE:
            raise ImportError("PySNMP library not found. Install via 'pip install pysnmp'.")

        self.credential = credential
        self.timeout = timeout
        self.retries = retries
        self.snmp_engine = SnmpEngine()

        # Determine Auth/Priv protocols
        # Credential object defines username/pass.
        # But SNMP v3 needs: Auth Proto, Auth Pass, Priv Proto, Priv Pass.
        # We need to extend Credential or pass extra config.
        # For now, we'll assume extra fields are passed in specific config keys,
        # or we rely on extended Credential properties (which don't strictly exist yet in base class).
        # Or we map from CLI args passed via a specialized dict/object if needed.
        # Implementation Plan says CLI: --snmp-auth-proto etc.
        # But Credentials class is generic.
        # We will parse these from 'extra' or assume standard if generic.
        # Let's assume for MVP: generic Credential stores user/pass.
        # Extra fields (protos) might need to be passed in __init__?
        # Let's add them to `__init__` for flexibility.

        self.auth_proto = usmHMACSHAAuthProtocol
        self.auth_key = getattr(credential, "snmp_auth_pass", None) or credential.password

        self.priv_proto = usmAesCfb128Protocol
        self.priv_key = getattr(credential, "snmp_priv_pass", None)
        # Wait, usually AuthPass and PrivPass differ.
        # We need a way to pass extended creds.

        # TODO: Refactor Credential to support extra fields, or pass them here.
        # For now, we will use attributes if they exist on credential, or defaults.
        if hasattr(credential, "snmp_auth_proto") and credential.snmp_auth_proto:
            self.auth_proto = credential.snmp_auth_proto
        if hasattr(credential, "snmp_priv_proto") and credential.snmp_priv_proto:
            self.priv_proto = credential.snmp_priv_proto
        if hasattr(credential, "snmp_priv_pass") and credential.snmp_priv_pass:
            self.priv_key = credential.snmp_priv_pass
        if hasattr(credential, "snmp_auth_pass") and credential.snmp_auth_pass:
            self.auth_key = credential.snmp_auth_pass

        self.auth_proto = self.auth_protocol_map(self.auth_proto)
        self.priv_proto = self.priv_protocol_map(self.priv_proto)

        # Setup User Data
        # User, AuthKey, AuthProto, PrivKey, PrivProto
        self.user_data = UsmUserData(
            credential.username,
            self.auth_key,
            self.auth_proto,
            self.priv_key,
            self.priv_proto,
        )

    @staticmethod
    def _normalize_proto_name(name_or_obj) -> str:
        if not isinstance(name_or_obj, str):
            return ""
        return name_or_obj.strip().upper().replace("-", "").replace("_", "")

    def auth_protocol_map(self, name_or_obj):
        if not name_or_obj:
            return usmHMACSHAAuthProtocol
        if not isinstance(name_or_obj, str):
            return name_or_obj

        normalized = self._normalize_proto_name(name_or_obj)
        mapping = {
            "SHA": usmHMACSHAAuthProtocol,
            "SHA1": usmHMACSHAAuthProtocol,
            "MD5": getattr(hlapi, "usmHMACMD5AuthProtocol", None),
            "SHA224": getattr(hlapi, "usmHMACSHA224AuthProtocol", None),
            "SHA256": getattr(hlapi, "usmHMACSHA256AuthProtocol", None),
            "SHA384": getattr(hlapi, "usmHMACSHA384AuthProtocol", None),
            "SHA512": getattr(hlapi, "usmHMACSHA512AuthProtocol", None),
        }

        mapped = mapping.get(normalized)
        if mapped is None:
            if normalized in mapping:
                logger.warning(
                    "SNMP auth protocol %s not supported by PySNMP; using SHA",
                    normalized,
                )
            else:
                logger.warning(
                    "SNMP auth protocol %s not recognized; using SHA",
                    normalized,
                )
            return usmHMACSHAAuthProtocol
        return mapped

    def priv_protocol_map(self, name_or_obj):
        if not name_or_obj:
            return usmAesCfb128Protocol
        if not isinstance(name_or_obj, str):
            return name_or_obj

        normalized = self._normalize_proto_name(name_or_obj)
        mapping = {
            "AES": usmAesCfb128Protocol,
            "AES128": usmAesCfb128Protocol,
            "AES192": getattr(hlapi, "usmAesCfb192Protocol", None),
            "AES256": getattr(hlapi, "usmAesCfb256Protocol", None),
            "DES": getattr(hlapi, "usmDESPrivProtocol", None),
            "3DES": getattr(hlapi, "usm3DESEDEPrivProtocol", None),
        }

        mapped = mapping.get(normalized)
        if mapped is None:
            if normalized in mapping:
                logger.warning(
                    "SNMP privacy protocol %s not supported by PySNMP; using AES",
                    normalized,
                )
            else:
                logger.warning(
                    "SNMP privacy protocol %s not recognized; using AES",
                    normalized,
                )
            return usmAesCfb128Protocol
        return mapped

    def get_system_info(self, host: str, port: int = 161) -> SNMPHostInfo:
        """Query system MIBs."""
        info = SNMPHostInfo(interfaces=[], routes=[], arp_table=[])
        target = UdpTransportTarget((host, port), timeout=self.timeout, retries=self.retries)

        try:
            # sysDescr .1.3.6.1.2.1.1.1.0
            # sysName .1.3.6.1.2.1.1.5.0
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(
                    self.snmp_engine,
                    self.user_data,
                    target,
                    ContextData(),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0)),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysUpTime", 0)),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysContact", 0)),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysLocation", 0)),
                )
            )

            if errorIndication:
                info.error = str(errorIndication)
            elif errorStatus:
                info.error = f"{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
            else:
                info.sys_descr = str(varBinds[0][1])
                info.sys_name = str(varBinds[1][1])
                info.sys_uptime = str(varBinds[2][1])
                info.sys_contact = str(varBinds[3][1])
                info.sys_location = str(varBinds[4][1])

            return info

        except Exception as e:
            info.error = str(e)
            return info

    def get_topology_info(self, host: str, port: int = 161) -> SNMPHostInfo:
        """Query system MIBs + Topology (Routes, ARP, Interfaces)."""
        # First get basic info
        info = self.get_system_info(host, port)
        if info.error:
            return info

        target = UdpTransportTarget((host, port), timeout=self.timeout, retries=self.retries)

        # 1. Get Interfaces (ifTable) .1.3.6.1.2.1.2.2.1
        info.interfaces = self._walk_interfaces(target)

        # 2. Get Routing Table (ipRouteTable) .1.3.6.1.2.1.4.21
        info.routes = self._walk_routes(target)

        # 3. Get ARP Table (ipNetToMediaTable) .1.3.6.1.2.1.4.22
        info.arp_table = self._walk_arp(target)

        return info

    def _walk_oid(self, target, root_oid: str) -> List[List[str]]:
        """Generic walker, returns list of list of strings for each row."""
        results = []
        try:
            for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
                self.snmp_engine,
                self.user_data,
                target,
                ContextData(),
                ObjectType(ObjectIdentity(root_oid)),
                lexicographicMode=False,
            ):
                if errorIndication or errorStatus:
                    break

                row = [str(varBind[1]) for varBind in varBinds]
                results.append(row)
        except Exception:
            pass
        return results

    def _walk_interfaces(self, target) -> List[Dict[str, str]]:
        # OID: .1.3.6.1.2.1.2.2.1 (ifEntry)
        interfaces = []
        cols = [
            ObjectIdentity("IF-MIB", "ifIndex"),
            ObjectIdentity("IF-MIB", "ifDescr"),
            ObjectIdentity("IF-MIB", "ifType"),
            ObjectIdentity("IF-MIB", "ifPhysAddress"),
            ObjectIdentity("IF-MIB", "ifOperStatus"),
        ]

        try:
            for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
                self.snmp_engine,
                self.user_data,
                target,
                ContextData(),
                *([ObjectType(c) for c in cols]),
                lexicographicMode=False,
            ):
                if errorIndication or errorStatus:
                    break

                # varBinds match stats order: [0]=idx, [1]=descr, [2]=type, [3]=mac, [4]=status
                mac_raw = varBinds[3][1]
                mac_str = ""
                try:
                    if hasattr(mac_raw, "asNumbers"):
                        mac_str = ":".join([f"{x:02x}" for x in mac_raw.asNumbers()])
                    elif hasattr(mac_raw, "prettyPrint"):
                        val = mac_raw.prettyPrint()
                        if val.startswith("0x"):
                            val = val[2:]
                        if len(val) == 12:
                            mac_str = ":".join(val[i : i + 2] for i in range(0, 12, 2))
                        else:
                            mac_str = val
                except Exception:
                    mac_str = str(mac_raw)

                iface = {
                    "index": str(varBinds[0][1]),
                    "descr": str(varBinds[1][1]),
                    "type": str(varBinds[2][1]),
                    "mac": mac_str,
                    "status": str(varBinds[4][1]),
                }
                interfaces.append(iface)
        except Exception as e:
            logger.debug(f"SNMP Interface walk failed: {e}")

        return interfaces

    def _walk_routes(self, target) -> List[Dict[str, str]]:
        # ipRouteDest(.1), ipRouteIfIndex(.2), ipRouteNextHop(.7), ipRouteType(.8), ipRouteMask(.11)
        routes = []
        cols = [
            ObjectIdentity("IP-MIB", "ipRouteDest"),
            ObjectIdentity("IP-MIB", "ipRouteIfIndex"),
            ObjectIdentity("IP-MIB", "ipRouteNextHop"),
            ObjectIdentity("IP-MIB", "ipRouteType"),
            ObjectIdentity("IP-MIB", "ipRouteMask"),
        ]

        try:
            for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
                self.snmp_engine,
                self.user_data,
                target,
                ContextData(),
                *([ObjectType(c) for c in cols]),
                lexicographicMode=False,
            ):
                if errorIndication or errorStatus:
                    continue

                routes.append(
                    {
                        "dest": str(varBinds[0][1]),
                        "if_index": str(varBinds[1][1]),
                        "next_hop": str(varBinds[2][1]),
                        "type": str(varBinds[3][1]),
                        "mask": str(varBinds[4][1]),
                    }
                )
        except Exception as e:
            logger.debug(f"SNMP Route walk failed: {e}")

        return routes

    def _walk_arp(self, target) -> List[Dict[str, str]]:
        # ipNetToMediaIfIndex(.1), ipNetToMediaPhysAddress(.2), ipNetToMediaNetAddress(.3), ipNetToMediaType(.4)
        arp_table = []
        cols = [
            ObjectIdentity("IP-MIB", "ipNetToMediaIfIndex"),
            ObjectIdentity("IP-MIB", "ipNetToMediaPhysAddress"),
            ObjectIdentity("IP-MIB", "ipNetToMediaNetAddress"),
            ObjectIdentity("IP-MIB", "ipNetToMediaType"),
        ]

        try:
            for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
                self.snmp_engine,
                self.user_data,
                target,
                ContextData(),
                *([ObjectType(c) for c in cols]),
                lexicographicMode=False,
            ):
                if errorIndication or errorStatus:
                    continue

                mac_raw = varBinds[1][1]
                mac_str = ""
                try:
                    if hasattr(mac_raw, "asNumbers"):
                        mac_str = ":".join([f"{x:02x}" for x in mac_raw.asNumbers()])
                    elif hasattr(mac_raw, "prettyPrint"):
                        val = mac_raw.prettyPrint()
                        if val.startswith("0x"):
                            val = val[2:]
                        if len(val) == 12:
                            mac_str = ":".join(val[i : i + 2] for i in range(0, 12, 2))
                        else:
                            mac_str = val
                except Exception:
                    mac_str = str(mac_raw)

                arp_table.append(
                    {
                        "if_index": str(varBinds[0][1]),
                        "mac": mac_str,
                        "ip": str(varBinds[2][1]),
                        "type": str(varBinds[3][1]),
                    }
                )
        except Exception as e:
            logger.debug(f"SNMP ARP walk failed: {e}")

        return arp_table
