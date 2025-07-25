import asyncio
import subprocess
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from dataclasses import dataclass
from ...utils.logging import port_scan_logger

@dataclass
class NmapServiceInfo:
    port: int
    protocol: str
    service: str
    product: str
    version: str
    extrainfo: str
    state: str
    reason: str

@dataclass
class NmapScanResult:
    host: str
    state: str
    open_ports: List[int]
    services: Dict[int, NmapServiceInfo]
    os_info: Dict[str, str]
    scan_duration: float
    scan_stats: Dict[str, str]

class NmapService:
    def __init__(self):
        self.logger = port_scan_logger
        
    async def scan_host(self, 
                       host: str, 
                       ports: str = "1-1000",
                       service_detection: bool = True,
                       os_detection: bool = False,
                       stealth: bool = False) -> NmapScanResult:
        """
        Perform detailed Nmap scan on a host
        """
        try:
            self.logger.info(f"Starting Nmap scan for {host}")
            
            # Build Nmap command
            cmd = ['nmap']
            
            # Scan type options
            if stealth:
                cmd.extend(['-sS'])  # SYN stealth scan
            else:
                cmd.extend(['-sT'])  # TCP connect scan
            
            # Service detection
            if service_detection:
                cmd.extend(['-sV', '--version-intensity', '5'])
            
            # OS detection
            if os_detection:
                cmd.extend(['-O'])
            
            # Port specification
            cmd.extend(['-p', ports])
            
            # Output format
            cmd.extend(['-oX', '-'])  # XML output to stdout
            
            # Performance options
            cmd.extend(['-T4', '--max-retries', '2'])
            
            # Target
            cmd.append(host)
            
            # Execute Nmap
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8')
                self.logger.error(f"Nmap scan failed for {host}: {error_msg}")
                return None
            
            # Parse XML output
            xml_output = stdout.decode('utf-8')
            result = self._parse_nmap_xml(xml_output)
            
            self.logger.info(f"Nmap scan completed for {host}: {len(result.open_ports) if result else 0} open ports")
            return result
            
        except Exception as e:
            self.logger.error(f"Nmap scan error for {host}: {str(e)}")
            return None
    
    def _parse_nmap_xml(self, xml_data: str) -> Optional[NmapScanResult]:
        """
        Parse Nmap XML output into structured data
        """
        try:
            root = ET.fromstring(xml_data)
            
            # Find host element
            host_elem = root.find('.//host')
            if host_elem is None:
                return None
            
            # Get host address
            address_elem = host_elem.find('.//address[@addrtype="ipv4"]')
            if address_elem is None:
                return None
            host_addr = address_elem.get('addr')
            
            # Get host state
            status_elem = host_elem.find('.//status')
            host_state = status_elem.get('state') if status_elem is not None else 'unknown'
            
            # Parse ports
            open_ports = []
            services = {}
            
            ports_elem = host_elem.find('.//ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('.//port'):
                    portid = int(port_elem.get('portid'))
                    protocol = port_elem.get('protocol')
                    
                    state_elem = port_elem.find('.//state')
                    if state_elem is not None and state_elem.get('state') == 'open':
                        open_ports.append(portid)
                        
                        # Get service information
                        service_elem = port_elem.find('.//service')
                        if service_elem is not None:
                            service_info = NmapServiceInfo(
                                port=portid,
                                protocol=protocol,
                                service=service_elem.get('name', 'unknown'),
                                product=service_elem.get('product', ''),
                                version=service_elem.get('version', ''),
                                extrainfo=service_elem.get('extrainfo', ''),
                                state='open',
                                reason=state_elem.get('reason', '')
                            )
                            services[portid] = service_info
            
            # Parse OS information
            os_info = {}
            os_elem = host_elem.find('.//os')
            if os_elem is not None:
                osmatch_elem = os_elem.find('.//osmatch')
                if osmatch_elem is not None:
                    os_info['name'] = osmatch_elem.get('name', 'Unknown')
                    os_info['accuracy'] = osmatch_elem.get('accuracy', '0')
                    
                    osclass_elem = osmatch_elem.find('.//osclass')
                    if osclass_elem is not None:
                        os_info['type'] = osclass_elem.get('type', '')
                        os_info['vendor'] = osclass_elem.get('vendor', '')
                        os_info['osfamily'] = osclass_elem.get('osfamily', '')
            
            # Parse scan stats
            scan_stats = {}
            runstats_elem = root.find('.//runstats')
            if runstats_elem is not None:
                finished_elem = runstats_elem.find('.//finished')
                if finished_elem is not None:
                    scan_stats['elapsed'] = finished_elem.get('elapsed', '0')
                    scan_stats['summary'] = finished_elem.get('summary', '')
                
                hosts_elem = runstats_elem.find('.//hosts')
                if hosts_elem is not None:
                    scan_stats['hosts_up'] = hosts_elem.get('up', '0')
                    scan_stats['hosts_down'] = hosts_elem.get('down', '0')
                    scan_stats['hosts_total'] = hosts_elem.get('total', '0')
            
            return NmapScanResult(
                host=host_addr,
                state=host_state,
                open_ports=sorted(open_ports),
                services=services,
                os_info=os_info,
                scan_duration=float(scan_stats.get('elapsed', '0')),
                scan_stats=scan_stats
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing Nmap XML: {str(e)}")
            return None
    
    async def scan_multiple_hosts(self, 
                                 hosts: List[str], 
                                 **scan_options) -> Dict[str, NmapScanResult]:
        """
        Scan multiple hosts concurrently
        """
        tasks = []
        for host in hosts:
            tasks.append(self.scan_host(host, **scan_options))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        scan_results = {}
        for i, result in enumerate(results):
            if isinstance(result, NmapScanResult):
                scan_results[hosts[i]] = result
            elif isinstance(result, Exception):
                self.logger.error(f"Scan failed for {hosts[i]}: {str(result)}")
        
        return scan_results
