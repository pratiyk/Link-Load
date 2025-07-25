import asyncio
import dns.resolver
import dns.exception
from typing import Set, List
import itertools
from ...utils.logging import subdomain_logger

class DNSBruteForceService:
    def __init__(self):
        self.logger = subdomain_logger
        self.timeout = 2
        self.max_concurrent = 100
        
        # Common subdomain wordlists
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns', 'test', 'secure',
            'mx', 'dev', 'staging', 'admin', 'api', 'app', 'cdn', 'blog', 'shop', 'store',
            'portal', 'support', 'help', 'docs', 'status', 'monitor', 'remote', 'vpn',
            'git', 'svn', 'repo', 'backup', 'demo', 'beta', 'alpha', 'preview', 'mobile',
            'assets', 'static', 'images', 'img', 'css', 'js', 'cdn1', 'cdn2', 'media',
            'upload', 'uploads', 'files', 'download', 'downloads', 'ftp1', 'ftp2',
            'email', 'imap', 'pop3', 'smtp1', 'smtp2', 'exchange', 'owa', 'webmail1',
            'webmail2', 'mail1', 'mail2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
            'search', 'blog', 'news', 'forum', 'forums', 'community', 'wiki',
            'crm', 'erp', 'intranet', 'extranet', 'partner', 'partners', 'client',
            'clients', 'customer', 'customers', 'user', 'users', 'member', 'members',
            'login', 'signin', 'signup', 'register', 'auth', 'sso', 'oauth',
            'db', 'database', 'mysql', 'postgres', 'mongodb', 'redis', 'cache',
            'queue', 'worker', 'job', 'jobs', 'cron', 'scheduler', 'task', 'tasks',
            'log', 'logs', 'metrics', 'stats', 'analytics', 'track', 'tracking'
        ]
        
        # Extended wordlist for thorough scans
        self.extended_subdomains = self.common_subdomains + [
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
            'old', 'new', 'temp', 'tmp', 'backup1', 'backup2', 'bak',
            'prod', 'production', 'live', 'www1', 'www2', 'www3',
            'web1', 'web2', 'web3', 'server1', 'server2', 'host1', 'host2'
        ]
    
    async def discover_subdomains(self, domain: str, wordlist: str = "common") -> Set[str]:
        """
        Perform DNS brute force attack to discover subdomains
        """
        try:
            self.logger.info(f"Starting DNS brute force for {domain}")
            
            # Choose wordlist
            subdomains_to_test = self.common_subdomains if wordlist == "common" else self.extended_subdomains
            
            # Create semaphore for concurrent requests
            semaphore = asyncio.Semaphore(self.max_concurrent)
            
            # Create tasks for all subdomain tests
            tasks = []
            for subdomain in subdomains_to_test:
                full_domain = f"{subdomain}.{domain}"
                tasks.append(self._check_subdomain(semaphore, full_domain))
            
            # Execute all tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter successful results
            discovered = set()
            for result in results:
                if isinstance(result, str):  # Valid subdomain
                    discovered.add(result)
                elif isinstance(result, Exception):
                    continue  # Skip exceptions
            
            self.logger.info(f"DNS brute force found {len(discovered)} subdomains for {domain}")
            return discovered
            
        except Exception as e:
            self.logger.error(f"DNS brute force error for {domain}: {str(e)}")
            return set()
    
    async def _check_subdomain(self, semaphore: asyncio.Semaphore, subdomain: str) -> str:
        """
        Check if a subdomain exists using DNS resolution
        """
        async with semaphore:
            try:
                # Create resolver with timeout
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout
                
                # Try to resolve A record
                await asyncio.get_event_loop().run_in_executor(
                    None, resolver.resolve, subdomain, 'A'
                )
                
                return subdomain
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                # Subdomain doesn't exist or no A record
                return None
            except Exception:
                # Other DNS errors
                return None

    async def generate_mutations(self, subdomains: Set[str], domain: str) -> Set[str]:
        """
        Generate subdomain mutations based on discovered subdomains
        """
        mutations = set()
        prefixes = ['dev', 'test', 'stage', 'prod', 'beta', 'alpha', 'new', 'old']
        suffixes = ['1', '2', '3', 'new', 'old', 'bak', 'dev', 'test']
        
        for subdomain in subdomains:
            if subdomain.endswith('.' + domain):
                base = subdomain[:-len('.' + domain)]
                
                # Add prefixes
                for prefix in prefixes:
                    mutations.add(f"{prefix}-{base}.{domain}")
                    mutations.add(f"{prefix}.{base}.{domain}")
                
                # Add suffixes
                for suffix in suffixes:
                    mutations.add(f"{base}-{suffix}.{domain}")
                    mutations.add(f"{base}{suffix}.{domain}")
        
        return mutations
