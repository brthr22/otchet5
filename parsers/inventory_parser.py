"""
Parser for RedCheck inventory reports.

This module parses XML inventory reports containing information about:
- Operating systems and domain roles
- Hardware and architecture
- Installed updates (KB)
- Installed software
- Network interfaces
- Users and groups
- Services and processes
- Security policies
"""

from typing import Dict, List, Any, Optional
import xml.etree.ElementTree as ET
from pathlib import Path

from . import BaseParser, Host, ParsedData


class InventoryParser(BaseParser):
    """Parser for RedCheck inventory XML reports."""

    def __init__(self, file_path: str):
        super().__init__(file_path)

    def parse(self) -> ParsedData:
        """
        Parse the inventory XML report.

        Returns:
            ParsedData object with extracted host information
        """
        parsed_data = ParsedData()

        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            self._log_error(f"XML parsing error: {e}")
            parsed_data.errors.extend(self.errors)
            return parsed_data
        except FileNotFoundError:
            self._log_error(f"File not found: {self.file_path}")
            parsed_data.errors.extend(self.errors)
            return parsed_data

        # Try to find hosts in various possible XML structures
        hosts_elements = self._find_hosts_elements(root)

        if not hosts_elements:
            self._log_warning("No host elements found in inventory report")
            parsed_data.warnings.extend(self.warnings)
            return parsed_data

        for host_elem in hosts_elements:
            try:
                host = self._parse_host(host_elem)
                if host.ip or host.hostname:
                    parsed_data.hosts.append(host)
            except Exception as e:
                self._log_error(f"Error parsing host element: {e}")

        parsed_data.errors.extend(self.errors)
        parsed_data.warnings.extend(self.warnings)
        return parsed_data

    def _find_hosts_elements(self, root: ET.Element) -> List[ET.Element]:
        """Find host elements in various XML structures."""
        hosts = []

        # Try common patterns
        patterns = [
            ".//host",
            ".//Host",
            ".//HOST",
            ".//computer",
            ".//Computer",
            ".//system",
            ".//System",
            ".//inventory/host",
            ".//hosts/host",
            ".//Hosts/Host",
        ]

        for pattern in patterns:
            try:
                hosts = root.findall(pattern)
                if hosts:
                    break
            except Exception:
                continue

        # If no pattern matched, try root itself if it looks like a host
        if not hosts and root.tag.lower() in ['host', 'computer', 'system']:
            hosts = [root]

        return hosts

    def _parse_host(self, host_elem: ET.Element) -> Host:
        """Parse a single host element."""
        host = Host()

        # Basic info
        host.ip = self._safe_get(host_elem, "ip") or \
                  self._safe_get(host_elem, "ipAddress") or \
                  self._safe_get(host_elem, "IP") or \
                  self._safe_get_attr(host_elem, "ip")
        
        host.hostname = self._safe_get(host_elem, "hostname") or \
                       self._safe_get(host_elem, "HostName") or \
                       self._safe_get(host_elem, "name") or \
                       self._safe_get(host_elem, "computerName")

        host.os = self._safe_get(host_elem, "os") or \
                 self._safe_get(host_elem, "operatingSystem") or \
                 self._safe_get(host_elem, "OS") or \
                 self._safe_get(host_elem, "osName")

        host.architecture = self._safe_get(host_elem, "architecture") or \
                           self._safe_get(host_elem, "arch") or \
                           self._safe_get(host_elem, "Architecture") or \
                           self._safe_get(host_elem, "systemType")

        host.domain_role = self._safe_get(host_elem, "domainRole") or \
                          self._safe_get(host_elem, "domain_role") or \
                          self._safe_get(host_elem, "role") or \
                          self._safe_get(host_elem, "DomainRole")

        host.mac_address = self._safe_get(host_elem, "mac") or \
                          self._safe_get(host_elem, "macAddress") or \
                          self._safe_get(host_elem, "MAC")

        # Network interfaces
        host.network_interfaces = self._parse_network_interfaces(host_elem)

        # Users and groups
        host.users = self._parse_users(host_elem)
        host.groups = self._parse_groups(host_elem)

        # Services and processes
        host.services = self._parse_services(host_elem)
        host.processes = self._parse_processes(host_elem)

        # Software and updates
        host.installed_software = self._parse_software(host_elem)
        host.updates = self._parse_updates(host_elem)

        # Security policies
        host.security_policies = self._parse_security_policies(host_elem)

        return host

    def _parse_network_interfaces(self, host_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse network interfaces from host element."""
        interfaces = []

        # Look for network interface elements
        iface_patterns = [".//networkInterface", ".//NetworkInterface", 
                         ".//interface", ".//Interface", ".//netInterface",
                         ".//network_interfaces/interface", ".//networkInterfaces/interface"]

        for pattern in iface_patterns:
            try:
                ifaces = host_elem.findall(pattern)
                if ifaces:
                    for iface in ifaces:
                        interface_data = {
                            "ip": self._safe_get(iface, "ip") or self._safe_get(iface, "ipAddress"),
                            "mask": self._safe_get(iface, "mask") or self._safe_get(iface, "subnetMask"),
                            "gateway": self._safe_get(iface, "gateway") or self._safe_get(iface, "defaultGateway"),
                            "dns": self._safe_get(iface, "dns") or self._safe_get(iface, "dnsServers"),
                            "mac": self._safe_get(iface, "mac") or self._safe_get(iface, "macAddress"),
                            "name": self._safe_get(iface, "name") or self._safe_get(iface, "interfaceName"),
                        }
                        # Filter out empty values
                        interface_data = {k: v for k, v in interface_data.items() if v}
                        if interface_data:
                            interfaces.append(interface_data)
                    break
            except Exception:
                continue

        return interfaces

    def _parse_users(self, host_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse users from host element."""
        users = []

        user_patterns = [".//user", ".//User", ".//USER", 
                        ".//localUser", ".//LocalUser",
                        ".//users/user", ".//Users/User"]

        for pattern in user_patterns:
            try:
                user_elems = host_elem.findall(pattern)
                if user_elems:
                    for user in user_elems:
                        user_data = {
                            "name": self._safe_get(user, "name") or self._safe_get(user, "username"),
                            "type": self._safe_get(user, "type") or self._safe_get(user, "userType"),
                            "enabled": self._safe_get(user, "enabled") or self._safe_get(user, "isActive"),
                            "last_login": self._safe_get(user, "lastLogin") or self._safe_get(user, "last_logon"),
                        }
                        user_data = {k: v for k, v in user_data.items() if v}
                        if user_data:
                            users.append(user_data)
                    break
            except Exception:
                continue

        return users

    def _parse_groups(self, host_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse groups from host element."""
        groups = []

        group_patterns = [".//group", ".//Group", ".//GROUP",
                         ".//localGroup", ".//LocalGroup",
                         ".//groups/group", ".//Groups/Group"]

        for pattern in group_patterns:
            try:
                group_elems = host_elem.findall(pattern)
                if group_elems:
                    for group in group_elems:
                        group_data = {
                            "name": self._safe_get(group, "name") or self._safe_get(group, "groupName"),
                            "members": self._safe_get(group, "members") or self._safe_get(group, "memberCount"),
                        }
                        group_data = {k: v for k, v in group_data.items() if v}
                        if group_data:
                            groups.append(group_data)
                    break
            except Exception:
                continue

        return groups

    def _parse_services(self, host_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse services from host element."""
        services = []

        service_patterns = [".//service", ".//Service", ".//SERVICE",
                           ".//services/service", ".//Services/Service"]

        for pattern in service_patterns:
            try:
                svc_elems = host_elem.findall(pattern)
                if svc_elems:
                    for svc in svc_elems:
                        svc_data = {
                            "name": self._safe_get(svc, "name") or self._safe_get(svc, "serviceName"),
                            "status": self._safe_get(svc, "status") or self._safe_get(svc, "state"),
                            "startup": self._safe_get(svc, "startup") or self._safe_get(svc, "startType"),
                            "path": self._safe_get(svc, "path") or self._safe_get(svc, "binaryPath"),
                        }
                        svc_data = {k: v for k, v in svc_data.items() if v}
                        if svc_data:
                            services.append(svc_data)
                    break
            except Exception:
                continue

        return services

    def _parse_processes(self, host_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse processes from host element."""
        processes = []

        process_patterns = [".//process", ".//Process", ".//PROCESS",
                           ".//processes/process", ".//Processes/Process"]

        for pattern in process_patterns:
            try:
                proc_elems = host_elem.findall(pattern)
                if proc_elems:
                    for proc in proc_elems:
                        proc_data = {
                            "name": self._safe_get(proc, "name") or self._safe_get(proc, "processName"),
                            "pid": self._safe_get(proc, "pid") or self._safe_get(proc, "processId"),
                            "path": self._safe_get(proc, "path") or self._safe_get(proc, "executablePath"),
                        }
                        proc_data = {k: v for k, v in proc_data.items() if v}
                        if proc_data:
                            processes.append(proc_data)
                    break
            except Exception:
                continue

        return processes

    def _parse_software(self, host_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse installed software from host element."""
        software = []

        sw_patterns = [".//software", ".//Software", ".//SOFTWARE",
                      ".//installedSoftware/software", ".//InstalledSoftware/Software",
                      ".//program", ".//Program", ".//application", ".//Application"]

        for pattern in sw_patterns:
            try:
                sw_elems = host_elem.findall(pattern)
                if sw_elems:
                    for sw in sw_elems:
                        sw_data = {
                            "name": self._safe_get(sw, "name") or self._safe_get(sw, "productName"),
                            "version": self._safe_get(sw, "version") or self._safe_get(sw, "productVersion"),
                            "date": self._safe_get(sw, "date") or self._safe_get(sw, "installDate"),
                            "vendor": self._safe_get(sw, "vendor") or self._safe_get(sw, "manufacturer"),
                        }
                        sw_data = {k: v for k, v in sw_data.items() if v}
                        if sw_data:
                            software.append(sw_data)
                    break
            except Exception:
                continue

        return software

    def _parse_updates(self, host_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse installed updates (KB) from host element."""
        updates = []

        update_patterns = [".//update", ".//Update", ".//UPDATE",
                          ".//hotfix", ".//Hotfix", ".//HOTFIX",
                          ".//kb", ".//KB",
                          ".//updates/update", ".//Updates/Update",
                          ".//hotfixes/hotfix"]

        for pattern in update_patterns:
            try:
                upd_elems = host_elem.findall(pattern)
                if upd_elems:
                    for upd in upd_elems:
                        upd_data = {
                            "id": self._safe_get(upd, "id") or self._safe_get(upd, "kb") or self._safe_get(upd, "hotfixId"),
                            "name": self._safe_get(upd, "name") or self._safe_get(upd, "title"),
                            "date": self._safe_get(upd, "date") or self._safe_get(upd, "installDate"),
                        }
                        upd_data = {k: v for k, v in upd_data.items() if v}
                        if upd_data:
                            updates.append(upd_data)
                    break
            except Exception:
                continue

        return updates

    def _parse_security_policies(self, host_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse security policies from host element."""
        policies = []

        policy_patterns = [".//policy", ".//Policy", ".//POLICY",
                          ".//securityPolicy", ".//SecurityPolicy",
                          ".//policies/policy", ".//Policies/Policy",
                          ".//setting", ".//Setting"]

        for pattern in policy_patterns:
            try:
                pol_elems = host_elem.findall(pattern)
                if pol_elems:
                    for pol in pol_elems:
                        pol_data = {
                            "name": self._safe_get(pol, "name") or self._safe_get(pol, "policyName"),
                            "value": self._safe_get(pol, "value") or self._safe_get(pol, "setting"),
                            "enabled": self._safe_get(pol, "enabled") or self._safe_get(pol, "status"),
                        }
                        pol_data = {k: v for k, v in pol_data.items() if v}
                        if pol_data:
                            policies.append(pol_data)
                    break
            except Exception:
                continue

        return policies
