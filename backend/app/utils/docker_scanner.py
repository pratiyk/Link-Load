"""
Docker Scanner Execution Utility

This module provides utilities to execute scanner commands on Docker sidecar containers.
Used when running scans via Nuclei/Wapiti containers instead of local binaries.
"""

import asyncio
import logging
import os
import json
import subprocess
from typing import Optional, Tuple, List
import sys

logger = logging.getLogger(__name__)

# Check if running in Docker mode
def is_docker_scanner_mode() -> bool:
    """Check if we should use Docker sidecar containers for scanning."""
    return os.getenv("NUCLEI_USE_DOCKER", "").lower() in ("true", "1", "yes") or \
           os.getenv("WAPITI_USE_DOCKER", "").lower() in ("true", "1", "yes")


def get_docker_socket() -> str:
    """Get Docker socket path based on OS."""
    if sys.platform == 'win32':
        return "//./pipe/docker_engine"
    return "/var/run/docker.sock"


async def docker_exec_async(
    container_name: str,
    command: List[str],
    timeout: int = 600,
    work_dir: Optional[str] = None,
    env_vars: Optional[dict] = None
) -> Tuple[int, str, str]:
    """
    Execute a command in a Docker container asynchronously.
    
    Args:
        container_name: Name of the Docker container
        command: Command to execute as a list of strings
        timeout: Command timeout in seconds
        work_dir: Working directory inside the container
        env_vars: Environment variables to set
        
    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        docker_cmd = ["docker", "exec"]
        
        # Add working directory if specified
        if work_dir:
            docker_cmd.extend(["-w", work_dir])
        
        # Add environment variables
        if env_vars:
            for key, value in env_vars.items():
                docker_cmd.extend(["-e", f"{key}={value}"])
        
        # Add container name and command
        docker_cmd.append(container_name)
        docker_cmd.extend(command)
        
        logger.debug(f"Docker exec command: {' '.join(docker_cmd)}")
        
        # Execute the command
        proc = await asyncio.create_subprocess_exec(
            *docker_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )
            return proc.returncode or 0, stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8', errors='replace')
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return -1, "", f"Command timed out after {timeout} seconds"
            
    except Exception as e:
        logger.error(f"Docker exec failed: {str(e)}")
        return -1, "", str(e)


def docker_exec_sync(
    container_name: str,
    command: List[str],
    timeout: int = 600,
    work_dir: Optional[str] = None,
    env_vars: Optional[dict] = None
) -> Tuple[int, str, str]:
    """
    Execute a command in a Docker container synchronously.
    
    Args:
        container_name: Name of the Docker container
        command: Command to execute as a list of strings
        timeout: Command timeout in seconds
        work_dir: Working directory inside the container
        env_vars: Environment variables to set
        
    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        docker_cmd = ["docker", "exec"]
        
        # Add working directory if specified
        if work_dir:
            docker_cmd.extend(["-w", work_dir])
        
        # Add environment variables
        if env_vars:
            for key, value in env_vars.items():
                docker_cmd.extend(["-e", f"{key}={value}"])
        
        # Add container name and command
        docker_cmd.append(container_name)
        docker_cmd.extend(command)
        
        logger.debug(f"Docker exec command: {' '.join(docker_cmd)}")
        
        # Execute the command
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        return result.returncode, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        logger.error(f"Docker exec failed: {str(e)}")
        return -1, "", str(e)


async def check_container_running(container_name: str) -> bool:
    """Check if a Docker container is running."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", "-f", "{{.State.Running}}", container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip().lower() == "true"
    except Exception as e:
        logger.error(f"Failed to check container status: {str(e)}")
        return False


async def get_container_version(container_name: str, version_cmd: List[str]) -> Optional[str]:
    """Get version info from a scanner container."""
    try:
        returncode, stdout, stderr = await docker_exec_async(
            container_name,
            version_cmd,
            timeout=30
        )
        if returncode == 0:
            return stdout.strip() or stderr.strip()
        return None
    except Exception as e:
        logger.error(f"Failed to get container version: {str(e)}")
        return None


async def copy_to_container(container_name: str, local_path: str, container_path: str) -> bool:
    """Copy a file from host to container."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "cp", local_path, f"{container_name}:{container_path}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.error(f"Failed to copy to container: {stderr.decode()}")
            return False
        return True
    except Exception as e:
        logger.error(f"Docker cp failed: {str(e)}")
        return False


async def copy_from_container(container_name: str, container_path: str, local_path: str) -> bool:
    """Copy a file from container to host."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "cp", f"{container_name}:{container_path}", local_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.error(f"Failed to copy from container: {stderr.decode()}")
            return False
        return True
    except Exception as e:
        logger.error(f"Docker cp failed: {str(e)}")
        return False


# Container names from environment
NUCLEI_CONTAINER = os.getenv("NUCLEI_CONTAINER", "linkload-nuclei")
WAPITI_CONTAINER = os.getenv("WAPITI_CONTAINER", "linkload-wapiti")


class DockerNucleiRunner:
    """Runner for executing Nuclei scans via Docker container."""
    
    def __init__(self, container_name: Optional[str] = None):
        self.container_name = container_name or NUCLEI_CONTAINER
        self.templates_path = os.getenv("NUCLEI_TEMPLATES_PATH", "/root/nuclei-templates")
    
    async def is_available(self) -> bool:
        """Check if Nuclei container is available."""
        return await check_container_running(self.container_name)
    
    async def get_version(self) -> Optional[str]:
        """Get Nuclei version."""
        return await get_container_version(self.container_name, ["nuclei", "-version"])
    
    async def run_scan(
        self,
        target_url: str,
        output_file: str = "/results/scan.json",
        templates: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        timeout: int = 600
    ) -> Tuple[int, str, str]:
        """
        Run a Nuclei scan on the target URL.
        
        Args:
            target_url: URL to scan
            output_file: Output file path inside container
            templates: List of template paths/tags to use
            severity: List of severity levels to include
            timeout: Scan timeout in seconds
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        cmd = [
            "nuclei",
            "-u", target_url,
            "-json-export", output_file,
            "-silent"
        ]
        
        if templates:
            for template in templates:
                cmd.extend(["-t", template])
        else:
            # Use default templates
            cmd.extend(["-t", self.templates_path])
        
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        
        return await docker_exec_async(self.container_name, cmd, timeout=timeout)


class DockerWapitiRunner:
    """Runner for executing Wapiti scans via Docker container."""
    
    def __init__(self, container_name: Optional[str] = None):
        self.container_name = container_name or WAPITI_CONTAINER
    
    async def is_available(self) -> bool:
        """Check if Wapiti container is available."""
        return await check_container_running(self.container_name)
    
    async def get_version(self) -> Optional[str]:
        """Get Wapiti version."""
        return await get_container_version(self.container_name, ["wapiti", "--version"])
    
    async def run_scan(
        self,
        target_url: str,
        output_file: str = "/results/scan.json",
        modules: Optional[List[str]] = None,
        timeout: int = 3600
    ) -> Tuple[int, str, str]:
        """
        Run a Wapiti scan on the target URL.
        
        Args:
            target_url: URL to scan
            output_file: Output file path inside container
            modules: List of modules to use
            timeout: Scan timeout in seconds
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        cmd = [
            "wapiti",
            "-u", target_url,
            "-f", "json",
            "-o", output_file
        ]
        
        if modules:
            cmd.extend(["-m", ",".join(modules)])
        
        return await docker_exec_async(self.container_name, cmd, timeout=timeout)
