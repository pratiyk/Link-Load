import sys
import pkg_resources
import shutil
from typing import Dict, Any
import subprocess
from loguru import logger

class HealthCheck:
    def __init__(self):
        self.required_packages = {
            'zaproxy': '0.4.0',
            'nuclei-sdk': '0.1.0',
            'wapiti3': '3.2.0',
            'fastapi': '0.100.0',
            'sqlalchemy': '2.0.0'
        }
        
        self.required_binaries = {
            'zap': 'zap-cli --version',
            'nuclei': 'nuclei -version',
            'wapiti': 'wapiti --version'
        }
    
    async def check_health(self) -> Dict[str, Any]:
        """Perform comprehensive health check"""
        try:
            python_deps = self._check_python_dependencies()
            binary_deps = self._check_binary_dependencies()
            system_deps = self._check_system_dependencies()
            
            status = all([
                python_deps['status'],
                binary_deps['status'],
                system_deps['status']
            ])
            
            return {
                'status': 'healthy' if status else 'unhealthy',
                'python_dependencies': python_deps,
                'binary_dependencies': binary_deps,
                'system_dependencies': system_deps,
                'python_version': sys.version,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _check_python_dependencies(self) -> Dict[str, Any]:
        """Check Python package dependencies"""
        results = {'status': True, 'details': {}}
        
        for package, required_version in self.required_packages.items():
            try:
                installed_version = pkg_resources.get_distribution(package).version
                meets_requirement = pkg_resources.parse_version(installed_version) >= \
                                  pkg_resources.parse_version(required_version)
                                  
                results['details'][package] = {
                    'installed': installed_version,
                    'required': required_version,
                    'status': 'ok' if meets_requirement else 'version_mismatch'
                }
                
                if not meets_requirement:
                    results['status'] = False
                    
            except pkg_resources.DistributionNotFound:
                results['status'] = False
                results['details'][package] = {
                    'installed': None,
                    'required': required_version,
                    'status': 'missing'
                }
        
        return results
    
    def _check_binary_dependencies(self) -> Dict[str, Any]:
        """Check required binary tools"""
        results = {'status': True, 'details': {}}
        
        for binary, check_command in self.required_binaries.items():
            try:
                if not shutil.which(binary.split()[0]):
                    raise FileNotFoundError(f"{binary} not found in PATH")
                    
                process = subprocess.run(
                    check_command.split(),
                    capture_output=True,
                    text=True
                )
                
                if process.returncode == 0:
                    version = process.stdout.strip()
                    results['details'][binary] = {
                        'status': 'ok',
                        'version': version
                    }
                else:
                    results['status'] = False
                    results['details'][binary] = {
                        'status': 'error',
                        'error': process.stderr.strip()
                    }
                    
            except FileNotFoundError:
                results['status'] = False
                results['details'][binary] = {
                    'status': 'missing'
                }
            except Exception as e:
                results['status'] = False
                results['details'][binary] = {
                    'status': 'error',
                    'error': str(e)
                }
        
        return results
    
    def _check_system_dependencies(self) -> Dict[str, Any]:
        """Check system requirements"""
        results = {'status': True, 'details': {}}
        
        # Check disk space
        try:
            total, used, free = shutil.disk_usage('/')
            free_gb = free // (2**30)
            
            if free_gb < 5:  # Less than 5GB free
                results['status'] = False
                results['details']['disk_space'] = {
                    'status': 'low',
                    'free_gb': free_gb
                }
            else:
                results['details']['disk_space'] = {
                    'status': 'ok',
                    'free_gb': free_gb
                }
        except Exception as e:
            results['status'] = False
            results['details']['disk_space'] = {
                'status': 'error',
                'error': str(e)
            }
        
        # Check memory
        try:
            import psutil
            memory = psutil.virtual_memory()
            free_mb = memory.available // (2**20)
            
            if free_mb < 1024:  # Less than 1GB free
                results['status'] = False
                results['details']['memory'] = {
                    'status': 'low',
                    'free_mb': free_mb
                }
            else:
                results['details']['memory'] = {
                    'status': 'ok',
                    'free_mb': free_mb
                }
        except ImportError:
            results['details']['memory'] = {
                'status': 'unknown',
                'error': 'psutil not installed'
            }
        except Exception as e:
            results['status'] = False
            results['details']['memory'] = {
                'status': 'error',
                'error': str(e)
            }
        
        return results

# Global health checker instance
health_checker = HealthCheck()