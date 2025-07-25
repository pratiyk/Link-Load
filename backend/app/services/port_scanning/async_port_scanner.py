import asyncio
import socket
import time
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
from ...utils.logging import port_scan_logger

@dataclass
class ServiceInfo:
    port: int
    protocol: str
    service: str
    version: str
    banner: str
    state: str

@dataclass
class ScanResult:
    host: str
    open_ports: List[int]
    services: Dict[int, ServiceInfo]
    scan_duration: float
    scan_time: str

class AsyncPortScanner:
    def __init__(self, max_concurrent: int = 1000, timeout: float = 3.0):
        self.logger = port_scan_logger
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # Common ports and their typical services
        self.common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 993: 'imaps', 995: 'pop3s', 1723: 'pptp',
            3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql', 5900: 'vnc',
            6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt', 9200: 'elasticsearch',
            27017: 'mongodb', 445: 'microsoft-ds', 636: 'ldaps', 1433: 'ms-sql-s',
            1521: 'oracle', 2049: 'nfs', 2121: 'ccproxy-ftp', 2222: 'ssh-alt',
            3000: 'ppp', 3001: 'nessus', 5000: 'upnp', 5001: 'commplex-link',
            5060: 'sip', 5061: 'sips', 8000: 'http-alt', 8888: 'sun-answerbook',
            9000: 'cslistener', 9001: 'tor-orport', 9090: 'zeus-admin'
        }
        
        # Top 1000 ports (most commonly used)
        self.top_1000_ports = [
            1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33,
            37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99,
            100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161,
            163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306,
            311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458,
            464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545,
            548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666,
            667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
            777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902,
            903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002,
            1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028,
            1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040,
            1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052,
            1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064,
            1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076,
            1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088,
            1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100
        ]
    
    async def scan_host(self, host: str, ports: List[int] = None) -> ScanResult:
        """
        Scan a single host for open ports and services
        """
        start_time = time.time()
        
        if ports is None:
            ports = self.top_1000_ports
        
        self.logger.info(f"Starting port scan for {host} on {len(ports)} ports")
        
        # Create tasks for all port scans
        tasks = []
        for port in ports:
            tasks.append(self._scan_port(host, port))
        
        # Execute all port scans concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        open_ports = []
        services = {}
        
        for i, result in enumerate(results):
            if isinstance(result, tuple) and result[1]:  # Port is open
                port = ports[i]
                open_ports.append(port)
                
                # Try to get service information
                service_info = await self._detect_service(host, port)
                if service_info:
                    services[port] = service_info
        
        scan_duration = time.time() - start_time
        
        self.logger.info(f"Port scan completed for {host}: {len(open_ports)} open ports in {scan_duration:.2f}s")
        
        return ScanResult(
            host=host,
            open_ports=sorted(open_ports),
            services=services,
            scan_duration=scan_duration,
            scan_time=time.strftime("%Y-%m-%d %H:%M:%S")
        )
    
    async def _scan_port(self, host: str, port: int) -> Tuple[int, bool]:
        """
        Scan a single port on a host
        """
        async with self.semaphore:
            try:
                # Create socket connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                
                # Close connection immediately
                writer.close()
                await writer.wait_closed()
                
                return (port, True)  # Port is open
                
            except Exception:
                return (port, False)  # Port is closed or filtered
    
    async def _detect_service(self, host: str, port: int) -> Optional[ServiceInfo]:
        """
        Attempt to detect service running on a port
        """
        try:
            # Try to grab banner
            banner = await self._grab_banner(host, port)
            
            # Determine service name
            service_name = self.common_ports.get(port, 'unknown')
            
            # Try to extract version from banner
            version = self._extract_version_from_banner(banner)
            
            return ServiceInfo(
                port=port,
                protocol='tcp',
                service=service_name,
                version=version,
                banner=banner,
                state='open'
            )
            
        except Exception as e:
            self.logger.debug(f"Service detection failed for {host}:{port} - {str(e)}")
            return None
    
    async def _grab_banner(self, host: str, port: int, timeout: float = 2.0) -> str:
        """
        Attempt to grab banner from a service
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Send common probes based on port
            if port == 80:
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 443:
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP usually sends banner immediately
            elif port == 22:
                pass  # SSH usually sends banner immediately
            elif port == 25:
                writer.write(b"EHLO example.com\r\n")
            elif port == 110:
                pass  # POP3 usually sends banner immediately
            elif port == 143:
                pass  # IMAP usually sends banner immediately
            else:
                writer.write(b"\r\n")
            
            await writer.drain()
            
            # Read response
            try:
                data = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=timeout
                )
                banner = data.decode('utf-8', errors='ignore').strip()
            except asyncio.TimeoutError:
                banner = ""
            
            writer.close()
            await writer.wait_closed()
            
            return banner
            
        except Exception:
            return ""
    
    def _extract_version_from_banner(self, banner: str) -> str:
        """
        Extract version information from service banner
        """
        if not banner:
            return "unknown"
        
        # Common version patterns
        import re
        
        patterns = [
            r'([\d]+\.[\d]+\.[\d]+)',  # x.y.z
            r'([\d]+\.[\d]+)',          # x.y
            r'version ([\d\.\w-]+)',     # version x.y.z
            r'v([\d\.\w-]+)',           # vx.y.z
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return "unknown"
    
    def get_port_list(self, port_range: str) -> List[int]:
        """
        Get list of ports based on range specification
        """
        if port_range.lower() == "top1000":
            return self.top_1000_ports
        elif port_range.lower() == "common":
            return list(self.common_ports.keys())
        elif port_range.lower() == "all":
            return list(range(1, 65536))
        elif "-" in port_range:
            # Range like "1-1000"
            start, end = map(int, port_range.split("-"))
            return list(range(start, end + 1))
        elif "," in port_range:
            # List like "80,443,22"
            return [int(p.strip()) for p in port_range.split(",")]
        else:
            # Single port
            return [int(port_range)]
