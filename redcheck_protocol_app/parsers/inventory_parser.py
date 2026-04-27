"""
Inventory report parser for RedCheck XML reports.
Parses OS info, hardware, network interfaces, software, users, services, security settings.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from xml.etree import ElementTree as ET

from core.parser_interface import ParserInterface, ParserError
from core.models import Host, NetworkInterface, Software, UserGroup, Service


logger = logging.getLogger(__name__)


class InventoryParser(ParserInterface):
    """Parser for RedCheck inventory XML reports."""
    
    # Common XML namespaces that might be used
    NAMESPACES = {
        '': '',  # Default namespace (will be updated dynamically)
        'rc': 'http://redcheck.local/inventory',
        'inv': 'http://redcheck.local/inventory',
    }
    
    def __init__(self):
        self.detected_namespace = ''
    
    def validate(self, file_path: Path) -> bool:
        """Check if file appears to be a valid inventory report."""
        try:
            if not file_path.exists():
                return False
            
            tree = ET.parse(str(file_path))
            root = tree.getroot()
            
            # Check for common inventory elements
            root_tag = root.tag.lower()
            text_content = ET.tostring(root, encoding='unicode').lower()
            
            indicators = ['inventory', 'host', 'os', 'operating system', 'network']
            return any(ind in text_content for ind in indicators) or \
                   'inventory' in root_tag or 'host' in root_tag
                   
        except ET.ParseError:
            return False
        except Exception as e:
            logger.debug(f"Validation error for {file_path}: {e}")
            return False
    
    def parse(self, file_path: Path) -> List[Host]:
        """
        Parse inventory XML and return list of Host objects.
        
        Handles multiple hosts in a single report.
        """
        if not file_path.exists():
            raise ParserError("File does not exist", file_path)
        
        try:
            tree = ET.parse(str(file_path))
            root = tree.getroot()
            self._detect_namespace(root)
            
            hosts = []
            
            # Try different strategies to find host elements
            host_elements = self._find_hosts(root)
            
            if not host_elements:
                # If no explicit host elements, treat root as single host
                logger.info("No explicit host elements found, treating document as single host")
                host = self._parse_host_element(root, file_path)
                if host:
                    hosts.append(host)
            else:
                for host_elem in host_elements:
                    host = self._parse_host_element(host_elem, file_path)
                    if host:
                        hosts.append(host)
            
            if not hosts:
                raise ParserError("No hosts found in inventory report", file_path)
            
            logger.info(f"Parsed {len(hosts)} host(s) from {file_path}")
            return hosts
            
        except ET.ParseError as e:
            raise ParserError("Invalid XML format", file_path, str(e))
        except Exception as e:
            logger.exception(f"Unexpected error parsing {file_path}")
            raise ParserError("Parsing failed", file_path, str(e))
    
    def _detect_namespace(self, root: ET.Element):
        """Detect XML namespace from root element."""
        tag = root.tag
        if tag.startswith('{'):
            end = tag.find('}')
            self.detected_namespace = tag[1:end]
            self.NAMESPACES[''] = self.detected_namespace
        else:
            self.detected_namespace = ''
    
    def _find_hosts(self, root: ET.Element) -> List[ET.Element]:
        """Find all host elements in the document."""
        host_elements = []
        
        # Strategy 1: Look for explicit host tags
        for tag_pattern in ['host', 'computer', 'system', 'machine', 'node']:
            elements = self._find_elements(root, tag_pattern)
            if elements:
                host_elements.extend(elements)
        
        # Strategy 2: Look for inventory containers
        if not host_elements:
            for tag_pattern in ['hosts', 'computers', 'systems', 'inventory']:
                container = self._find_element(root, tag_pattern)
                if container is not None:
                    # Get children as hosts
                    host_elements = list(container)
                    break
        
        return host_elements
    
    def _parse_host_element(self, elem: ET.Element, file_path: Path) -> Optional[Host]:
        """Parse a single host element into a Host object."""
        try:
            host = Host()
            
            # Basic info
            host.hostname = self._get_text(elem, ['hostname', 'name', 'computername', 'host_name'])
            host.ip = self._get_text(elem, ['ip', 'ipaddress', 'ip_address', 'primary_ip'])
            
            # OS Info
            os_elem = self._find_element(elem, ['os', 'operatingsystem', 'operating_system'])
            if os_elem is not None:
                host.os_name = self._get_text(os_elem, ['name', 'productname', 'product_name', 'os_name'])
                host.os_version = self._get_text(os_elem, ['version', 'os_version'])
                host.os_architecture = self._get_text(os_elem, ['architecture', 'arch', 'os_arch'])
                host.domain_role = self._get_text(os_elem, ['role', 'domainrole', 'domain_role', 'type'])
            
            # If OS info is at host level
            if not host.os_name:
                host.os_name = self._get_text(elem, ['os_name', 'osname', 'operating_system'])
            if not host.os_version:
                host.os_version = self._get_text(elem, ['os_version', 'osversion'])
            if not host.os_architecture:
                host.os_architecture = self._get_text(elem, ['architecture', 'arch'])
            
            # Hardware
            hw_elem = self._find_element(elem, ['hardware', 'hw', 'system_info'])
            if hw_elem is not None:
                host.cpu = self._get_text(hw_elem, ['cpu', 'processor', 'cpu_model'])
                host.ram = self._get_text(hw_elem, ['ram', 'memory', 'total_memory'])
                host.disk = self._get_text(hw_elem, ['disk', 'storage', 'total_disk'])
            
            # Network interfaces
            net_elem = self._find_element(elem, ['network', 'networking', 'interfaces', 'network_interfaces'])
            if net_elem is not None:
                host.interfaces = self._parse_network_interfaces(net_elem)
            
            # Also check for interface at host level
            if not host.interfaces:
                host.interfaces = self._parse_network_interfaces(elem)
            
            # Installed software
            sw_elem = self._find_element(elem, ['software', 'applications', 'installed_software', 'programs'])
            if sw_elem is not None:
                host.installed_software = self._parse_software(sw_elem)
            
            # Updates/KB
            upd_elem = self._find_element(elem, ['updates', 'patches', 'hotfixes', 'kb', 'security_updates'])
            if upd_elem is not None:
                host.updates_kb = self._parse_updates(upd_elem)
            
            # Users and groups
            usr_elem = self._find_element(elem, ['users', 'accounts', 'usergroups', 'local_users'])
            if usr_elem is not None:
                host.users_groups = self._parse_users_groups(usr_elem)
            
            # Services
            svc_elem = self._find_element(elem, ['services', 'processes', 'running_services'])
            if svc_elem is not None:
                host.services = self._parse_services(svc_elem)
            
            # Security settings
            sec_elem = self._find_element(elem, ['security', 'security_settings', 'policies', 'config'])
            if sec_elem is not None:
                host.security_settings = self._parse_security_settings(sec_elem)
            
            # Store raw data for debugging/extensibility
            host.raw_data = self._element_to_dict(elem)
            
            # Set IP from first interface if not set
            if not host.ip and host.interfaces:
                for iface in host.interfaces:
                    if iface.ip:
                        host.ip = iface.ip
                        break
            
            return host
            
        except Exception as e:
            logger.warning(f"Error parsing host element: {e}")
            return None
    
    def _parse_network_interfaces(self, parent: ET.Element) -> List[NetworkInterface]:
        """Parse network interfaces from XML element."""
        interfaces = []
        
        for tag_pattern in ['interface', 'adapter', 'nic', 'network_adapter']:
            iface_elems = self._find_elements(parent, tag_pattern)
            for iface_elem in iface_elems:
                try:
                    iface = NetworkInterface(
                        name=self._get_text(iface_elem, ['name', 'ifname', 'adapter_name']),
                        ip=self._get_text(iface_elem, ['ip', 'ipaddress', 'ipv4', 'address']),
                        mask=self._get_text(iface_elem, ['mask', 'netmask', 'subnet_mask']),
                        gateway=self._get_text(iface_elem, ['gateway', 'default_gateway']),
                        dns=self._get_text(iface_elem, ['dns', 'dns_servers']),
                        mac=self._get_text(iface_elem, ['mac', 'macaddress', 'physical_address'])
                    )
                    if iface.ip or iface.name:
                        interfaces.append(iface)
                except Exception as e:
                    logger.debug(f"Error parsing interface: {e}")
        
        return interfaces
    
    def _parse_software(self, parent: ET.Element) -> List[Software]:
        """Parse installed software from XML element."""
        software_list = []
        
        for tag_pattern in ['software', 'application', 'program', 'package', 'app']:
            sw_elems = self._find_elements(parent, tag_pattern)
            for sw_elem in sw_elems:
                try:
                    sw = Software(
                        name=self._get_text(sw_elem, ['name', 'productname', 'display_name']),
                        version=self._get_text(sw_elem, ['version', 'productversion', 'ver']),
                        install_date=self._get_text(sw_elem, ['installdate', 'install_date', 'date'])
                    )
                    if sw.name:
                        software_list.append(sw)
                except Exception as e:
                    logger.debug(f"Error parsing software: {e}")
        
        return software_list
    
    def _parse_updates(self, parent: ET.Element) -> List[str]:
        """Parse KB updates from XML element."""
        updates = []
        
        for tag_pattern in ['update', 'patch', 'hotfix', 'kb', 'security_update']:
            upd_elems = self._find_elements(parent, tag_pattern)
            for upd_elem in upd_elems:
                kb_id = self._get_text(upd_elem, ['id', 'kb', 'kb_id', 'name', 'update_id'])
                if kb_id:
                    updates.append(kb_id)
        
        return updates
    
    def _parse_users_groups(self, parent: ET.Element) -> List[UserGroup]:
        """Parse users and groups from XML element."""
        users_groups = []
        
        for tag_pattern in ['user', 'account', 'group', 'member']:
            ug_elems = self._find_elements(parent, tag_pattern)
            for ug_elem in ug_elems:
                try:
                    # Determine type from tag or attribute
                    tag = ug_elem.tag.lower()
                    utype = 'group' if 'group' in tag else 'user'
                    
                    ug = UserGroup(
                        name=self._get_text(ug_elem, ['name', 'username', 'account_name', 'groupname']),
                        type=utype,
                        description=self._get_text(ug_elem, ['description', 'desc', 'comment'])
                    )
                    if ug.name:
                        users_groups.append(ug)
                except Exception as e:
                    logger.debug(f"Error parsing user/group: {e}")
        
        return users_groups
    
    def _parse_services(self, parent: ET.Element) -> List[Service]:
        """Parse services from XML element."""
        services = []
        
        for tag_pattern in ['service', 'process', 'daemon']:
            svc_elems = self._find_elements(parent, tag_pattern)
            for svc_elem in svc_elems:
                try:
                    svc = Service(
                        name=self._get_text(svc_elem, ['name', 'servicename', 'process_name']),
                        status=self._get_text(svc_elem, ['status', 'state', 'running']),
                        startup=self._get_text(svc_elem, ['startup', 'startmode', 'start_type']),
                        path=self._get_text(svc_elem, ['path', 'pathname', 'executable', 'binary'])
                    )
                    if svc.name:
                        services.append(svc)
                except Exception as e:
                    logger.debug(f"Error parsing service: {e}")
        
        return services
    
    def _parse_security_settings(self, parent: ET.Element) -> Dict[str, str]:
        """Parse security settings from XML element."""
        settings = {}
        
        # Look for key-value pairs
        for tag_pattern in ['setting', 'policy', 'config', 'parameter', 'option']:
            setting_elems = self._find_elements(parent, tag_pattern)
            for setting_elem in setting_elems:
                key = self._get_text(setting_elem, ['name', 'key', 'parameter_name', 'setting_name'])
                value = self._get_text(setting_elem, ['value', 'data', 'parameter_value', 'setting_value'])
                if key:
                    settings[key] = value or ''
        
        return settings
    
    # Helper methods for XML navigation
    
    def _find_element(self, parent: ET.Element, names: list) -> Optional[ET.Element]:
        """Find first matching element by tag name(s)."""
        if isinstance(names, str):
            names = [names]
        
        for name in names:
            # Try without namespace
            elem = parent.find(name)
            if elem is not None:
                return elem
            
            # Try with detected namespace
            if self.detected_namespace:
                elem = parent.find(f'{{{self.detected_namespace}}}{name}')
                if elem is not None:
                    return elem
        
        # Try case-insensitive search
        for child in parent.iter():
            tag_lower = child.tag.split('}')[-1].lower() if '}' in child.tag else child.tag.lower()
            if tag_lower in [n.lower() for n in names]:
                return child
        
        return None
    
    def _find_elements(self, parent: ET.Element, names: list) -> List[ET.Element]:
        """Find all matching elements by tag name(s)."""
        if isinstance(names, str):
            names = [names]
        
        results = []
        names_lower = [n.lower() for n in names]
        
        for child in parent.iter():
            tag_lower = child.tag.split('}')[-1].lower() if '}' in child.tag else child.tag.lower()
            if tag_lower in names_lower:
                results.append(child)
        
        return results
    
    def _get_text(self, parent: ET.Element, names: list) -> str:
        """Get text content of first matching child element."""
        elem = self._find_element(parent, names)
        if elem is not None:
            # Check for value attribute first
            value = elem.get('value')
            if value:
                return value.strip()
            # Then check text content
            if elem.text:
                return elem.text.strip()
        return ''
    
    def _element_to_dict(self, elem: ET.Element) -> Dict[str, Any]:
        """Convert XML element to dictionary (for raw data storage)."""
        result = {}
        
        # Attributes
        for key, value in elem.attrib.items():
            result[f'@{key}'] = value
        
        # Children
        for child in elem:
            tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
            if tag in result:
                # Already exists, convert to list
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(self._element_to_dict(child))
            else:
                result[tag] = self._element_to_dict(child)
        
        # Text content
        if elem.text and elem.text.strip():
            if result:
                result['#text'] = elem.text.strip()
            else:
                return elem.text.strip()
        
        return result
