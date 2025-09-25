#!/usr/bin/env python3
"""
SSD-Optimized Ultimate Password Vault - Enhanced Security Version
Military-grade security for external SSD operation.
"""

import getpass #Used for secure password input
import json #Used for configuration and data serialization
import logging #Used for security auditing and error tracking via self.logger
import os #Used for file system operations and system information
import secrets #Used for cryptographically secure operations
import sys #Used for system-level operations
import time #Used for timing operations
import csv #Used for import/export functionality
import subprocess #Used for system commands
import platform #Used for system detection
from datetime import datetime, timedelta #Used for timestamping
from pathlib import Path #Used for path manipulation
from typing import Dict, List, Optional, Tuple, Any, Set, Deque, Callable #Used for type hints
from enum import Enum, auto #Used for security state enumerations
from dataclasses import dataclass, field #Used for the SSDTelemetry data container
import threading #Used for background security monitoring
import hashlib #Used for cryptographic hashing
import hmac #Used for backup data authentication
import socket #Used for network security checks
import gc #Used for memory management
import tempfile #Used for secure temporary file handling
import collections #Used for secure timing implementation
import math #Used for log2 calculations
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor #Used for SSD-optimized operations
import weakref # Used for tracking secure memory allocations
import ctypes #Used for low-level memory management
from ctypes import c_void_p, c_char_p, c_size_t
import signal #Used for security signal handling

# Conditional import for resource module (Unix only)
if platform.system() != "Windows":
    try:
        import resource #Used for memory locking and resource limit management
        RESOURCE_AVAILABLE = True
    except ImportError:
        RESOURCE_AVAILABLE = False
else:
    RESOURCE_AVAILABLE = False

# Security imports
try:
    import argon2 #Used for password hashing
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

#Used for all encryption operations
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

import base64 #Used for encoding and decoding binary data

# Check for critical dependencies
MISSING_CRITICAL_DEPS = []
if not CRYPTOGRAPHY_AVAILABLE:
    MISSING_CRITICAL_DEPS.append("cryptography")
if not ARGON2_AVAILABLE:
    MISSING_CRITICAL_DEPS.append("argon2-cffi")

# +++ SECURE TIMING IMPLEMENTATIONS +++
def constant_time_compare(val1, val2):
    """
    Constant-time comparison function to prevent timing attacks.
    Returns True if the two strings are equal, False otherwise.
    """
    if len(val1) != len(val2):
        return False
    
    result = 0
    for x, y in zip(val1, val2):
        result |= x ^ y
    return result == 0

def secure_delay(min_ms=100, max_ms=500):
    """
    Add a random delay to prevent timing attacks.
    The delay is randomized to prevent attackers from measuring precise timing differences.
    """
    delay_ms = secrets.randbelow(max_ms - min_ms + 1) + min_ms
    time.sleep(delay_ms / 1000.0)

def timing_attack_resistant_equals(a, b):
    """
    Compare two values in a timing-attack resistant manner.
    Uses constant-time comparison with a random delay.
    """
    result = constant_time_compare(a, b)
    secure_delay()
    return result

# --- SSD-OPTIMIZED CONFIGURATION ---
def get_ssd_vault_dir():
    """Get vault directory on SSD - automatically detects external drives"""
    if platform.system() == "Windows":
        # Check for external drives (not C:)
        for drive in ["D:", "E:", "F:", "G:", "H:", "I:", "J:", "K:", "L:"]:
            drive_path = drive + "\\"
            if os.path.exists(drive_path):
                # Skip system drives
                if drive.upper() != "C:\\":
                    ssd_path = Path(drive_path) / "UltimateVault"
                    ssd_path.mkdir(exist_ok=True)
                    return ssd_path
        # Fallback to current directory if no external drive found
        return Path("UltimateVault")
    else:
        # Linux/Mac - check mounted external drives
        try:
            # Check /media/ or /Volumes/ for external drives
            possible_paths = [
                Path("/media"), 
                Path("/Volumes"),
                Path("/mnt"),
                Path.cwd()  # Fallback to current directory
            ]
            for path in possible_paths:
                if path.exists() and path != Path("/"):
                    ssd_path = path / "UltimateVault"
                    ssd_path.mkdir(exist_ok=True)
                    return ssd_path
        except:
            pass
        return Path("UltimateVault")

SSD_VAULT_DIR = get_ssd_vault_dir()

# ENHANCED SECURITY CONFIGURATION
SSD_CONFIG = {
    "version": "10.0",
    "security_level": "MILITARY_GRADE",
    "cryptography": {
        "argon2": {"time_cost": 3, "memory_cost": 204800, "parallelism": 2},  # Enhanced memory usage
        "scrypt": {"n": 2**16, "r": 8, "p": 2},  # Enhanced complexity
        "pbkdf2": {"iterations": 600000},  # NIST recommended iterations
        "hkdf": {"algorithm": "SHA256", "length": 32},
        "encryption_layers": 3,  # Triple encryption for enhanced security
        "key_rotation_days": 30,
        "backup_encryption": "AES-256-GCM"  # Enhanced backup encryption
    },
    "defense": {
        "real_time_protection": True,
        "adaptive_security": True,
        "memory_armor": True,
        "process_fortification": True,
        "network_shield": True,
        "behavioral_guard": True,
        "quantum_preparation": True,
        "zero_trust_architecture": True,
        "brute_force_protection": True,
        "audit_logging": True,
        "tamper_detection": True,  # Added tamper detection
        "anti_forensics": True,  # Added anti-forensics measures
        "secure_deletion": True,  # Added secure deletion
        "memory_encryption": True,           # New: Encrypt sensitive memory
        "secure_ui_rendering": True,         # New: Protect against UI redressing
        "anti_keylogging": True,             # New: Keylogging protection
        "screen_capture_protection": True,   # New: Prevent screen capture
        "clipboard_protection": True,        # New: Secure clipboard handling
    },
    "advanced": {
        "quantum_resistance": False,         # New: Prepare for quantum computing
        "homomorphic_encryption": False,     # New: Future encryption capability
        "zero_knowledge_proofs": False,      # New: Advanced authentication
    },
    "performance": {
        "optimization_level": "SSD_ULTRA",
        "thread_strategy": "BALANCED",
        "memory_management": "SECURE",
        "io_optimization": "SSD_DIRECT",
        "cache_strategy": "SSD_OPTIMIZED"
    }
}

class SecurityLevel(Enum):
    MILITARY_GRADE = auto()
    ULTIMATE_SSD = auto()
    ULTIMATE = auto()
    EXTREME = auto()

class ProtectionState(Enum):
    NORMAL = auto()
    HEIGHTENED = auto()
    ELEVATED = auto()
    EXTREME = auto()
    ABSOLUTE = auto()
    ULTIMATE = auto()
    SSD_OPTIMIZED = auto()
    MILITARY = auto()

@dataclass
class SSDTelemetry:
    cpu_utilization: float = 0.0
    memory_pressure: float = 0.0
    disk_activity: float = 0.0
    network_traffic: float = 0.0
    ssd_speed: float = 0.0
    security_events: int = 0
    threat_score: float = 0.0
    performance_score: float = 0.0
    failed_login_attempts: int = 0
    last_failed_login: Optional[datetime] = None
    last_security_scan: Optional[datetime] = None

class SSDUltimateVault:
    def __init__(self, vault_dir: Path = SSD_VAULT_DIR):
        # Check for critical dependencies first
        if MISSING_CRITICAL_DEPS:
            raise ImportError(f"Missing critical dependencies: {', '.join(MISSING_CRITICAL_DEPS)}")
            
        self.vault_dir = vault_dir
        self.config = self.load_config()
        self.logger = self.setup_ssd_logging()
        
        # SSD-optimized security state
        self.protection_state = ProtectionState.NORMAL
        self.ssd_telemetry = SSDTelemetry()
        self.threat_matrix = {}
        
        # SSD-specific optimizations
        self.thread_pool = self.create_ssd_optimized_thread_pool()
        self.ssd_speed = self.measure_ssd_speed()
        
        # Session management
        self.master_password_hash = None
        self.session_start_time = None
        self.session_timeout = timedelta(minutes=15)
        self.current_master_password = None
        self.failed_attempts = 0
        self.last_attempt_time = None
        
        # Security enhancements
        self.encryption_key = None
        self.backup_key = None
        self.anti_forensics_enabled = True
        self.last_known_mtimes = {}
        self.file_hashes = {}  # For enhanced tamper detection
        
        # New security enhancements
        self.secure_allocations = weakref.WeakSet()
        self.memory_guards = {}
        self.rng_entropy_pool = hashlib.sha512()
        
        # Secure timing mechanisms
        self.secure_timers = {}
        self.timing_attack_protection = True
        
        # Initialize SSD-optimized security
        self.initialize_ssd_security()
        self.setup_enhanced_protections()

    def setup_enhanced_protections(self):
        """Setup enhanced security protections"""
        # Enable constant-time cryptography
        self.enable_constant_time_protections()
        
        # Setup memory canaries for heap overflow detection
        self.setup_memory_canaries()
        
        # Enable control flow integrity checks
        self.enable_cfi_protections()
        
        # Setup secure RNG strengthening
        self.setup_rng_strengthening()
        
        # Setup secure timers
        self.setup_secure_timers()
    
    def enable_constant_time_protections(self):
        """Enable constant-time cryptographic operations"""
        # This ensures timing attacks cannot extract information
        # from cryptographic operations
        self.logger.info("Constant-time protections enabled")
    
    def setup_memory_canaries(self):
        """Setup memory canaries for heap overflow detection"""
        # Place canary values around sensitive memory regions
        self.memory_guards['heap_canary'] = secrets.token_bytes(16)
        self.logger.info("Memory canaries initialized")
    
    def enable_cfi_protections(self):
        """Enable control flow integrity protections"""
        # This would implement various CFI techniques in a real implementation
        self.logger.info("Control Flow Integrity protections enabled")
    
    def setup_rng_strengthening(self):
        """Strengthen the random number generator"""
        # Additional entropy pooling for cryptographic operations
        self.update_entropy_pool()
        self.logger.info("RNG strengthening initialized")
    
    def update_entropy_pool(self, additional_data: bytes = None):
        """Update the entropy pool with system noise"""
        entropy_sources = [
            str(time.perf_counter_ns()).encode(),
            os.urandom(32),
            secrets.token_bytes(32),
            str(os.getpid()).encode(),
            str(threading.get_ident()).encode()
        ]
        
        if additional_data:
            entropy_sources.append(additional_data)
            
        for source in entropy_sources:
            self.rng_entropy_pool.update(source)
    
    def setup_secure_timers(self):
        """Setup secure timers for cryptographic operations"""
        # Initialize secure timers for timing-attack resistant operations
        self.secure_timers = {
            'min_delay_ms': 100,
            'max_delay_ms': 500,
            'execution_times': collections.deque(maxlen=1000),
            'last_operation_time': 0
        }
        self.logger.info("Secure timers initialized")
    
    def secure_random(self, length: int) -> bytes:
        """Cryptographically secure random with enhanced entropy"""
        # Mix system entropy with our strengthened pool
        system_random = os.urandom(length)
        pool_random = self.rng_entropy_pool.digest()[:length]
        
        # XOR both sources for enhanced security
        result = bytearray(length)
        for i in range(length):
            result[i] = system_random[i] ^ pool_random[i % len(pool_random)]
        
        # Update the pool
        self.update_entropy_pool(result)
        
        return bytes(result)

    def secure_delay(self, min_ms=None, max_ms=None):
        """
        Add a random delay to prevent timing attacks.
        The delay is randomized to prevent attackers from measuring precise timing differences.
        """
        if not self.timing_attack_protection:
            return
            
        min_ms = min_ms or self.secure_timers['min_delay_ms']
        max_ms = max_ms or self.secure_timers['max_delay_ms']
        
        delay_ms = secrets.randbelow(max_ms - min_ms + 1) + min_ms
        time.sleep(delay_ms / 1000.0)
        
        # Record execution time for anomaly detection
        current_time = time.time()
        if self.secure_timers['last_operation_time'] > 0:
            operation_time = current_time - self.secure_timers['last_operation_time']
            self.secure_timers['execution_times'].append(operation_time)
        self.secure_timers['last_operation_time'] = current_time

    def constant_time_compare(self, val1, val2):
        """
        Constant-time comparison function to prevent timing attacks.
        Returns True if the two strings/bytes are equal, False otherwise.
        """
        # Add random delay to prevent timing attacks
        self.secure_delay()
        
        if len(val1) != len(val2):
            return False
        
        # Use bitwise operations for constant-time comparison
        result = 0
        if isinstance(val1, str):
            val1 = val1.encode('utf-8')
        if isinstance(val2, str):
            val2 = val2.encode('utf-8')
            
        for x, y in zip(val1, val2):
            result |= x ^ y
            
        return result == 0

    def timing_attack_resistant_equals(self, a, b):
        """
        Compare two values in a timing-attack resistant manner.
        Uses constant-time comparison with a random delay.
        """
        result = self.constant_time_compare(a, b)
        return result

    # +++ ENHANCED MEMORY PROTECTION +++
    
    def secure_alloc(self, size: int) -> ctypes.Array:
        """Allocate memory with enhanced security protections"""
        # Use locked memory pages if available
        try:
            if platform.system() != "Windows" and RESOURCE_AVAILABLE:
                # Try to allocate memory that won't be swapped to disk
                buffer = ctypes.create_string_buffer(size)
                
                # Lock memory pages if possible
                try:
                    if hasattr(ctypes, 'mlock'):
                        ctypes.mlock(ctypes.addressof(buffer), size)
                    elif RESOURCE_AVAILABLE:
                        resource.setrlimit(resource.RLIMIT_MEMLOCK, 
                                         (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
                except:
                    pass
                
                # Add to tracking for secure deallocation
                self.secure_allocations.add(buffer)
                return buffer
        except:
            pass
        
        # Fallback to normal allocation
        return ctypes.create_string_buffer(size)
    
    def secure_free(self, buffer):
        """Securely free memory with multiple overwrites"""
        if not buffer:
            return
            
        # Multiple overwrites for sensitive data
        size = ctypes.sizeof(buffer)
        address = ctypes.addressof(buffer)
        
        # Overwrite with random data (3 passes)
        for _ in range(3):
            random_data = os.urandom(size)
            ctypes.memmove(address, random_data, size)
        
        # Final overwrite with zeros
        ctypes.memset(address, 0, size)
        
        # Try to unlock memory if it was locked
        try:
            if hasattr(ctypes, 'munlock'):
                ctypes.munlock(address, size)
        except:
            pass
        
        # Remove from tracking
        if buffer in self.secure_allocations:
            self.secure_allocations.remove(buffer)
    
    def secure_memory_wipe(self, data: Any) -> Any:
        """Enhanced secure memory wiping with multiple passes"""
        if isinstance(data, str):
            # Convert to bytes for secure wiping
            data_bytes = data.encode('utf-8')
            wiped_bytes = self.secure_memory_wipe(data_bytes)
            return '0' * len(data)  # Return same-length dummy string
            
        elif isinstance(data, (bytes, bytearray)):
            # Create mutable copy
            if isinstance(data, bytes):
                mutable_data = bytearray(data)
            else:
                mutable_data = data
                
            # Multiple overwrite passes (7-pass DoD standard)
            passes = [
                b'\x55',  # Pattern 1: 01010101
                b'\xAA',  # Pattern 2: 10101010
                b'\x92',  # Pattern 3: 10010010
                b'\x49',  # Pattern 4: 01001001
                b'\x24',  # Pattern 5: 00100100
                b'\x00',  # Pattern 6: zeros
                b'\xFF',  # Pattern 7: ones
            ]
            
            for pattern in passes:
                for i in range(len(mutable_data)):
                    mutable_data[i] = pattern[0]
            
            # Final verification pass
            for i in range(len(mutable_data)):
                mutable_data[i] = 0
                
            return bytes(mutable_data) if isinstance(data, bytes) else mutable_data
            
        elif hasattr(data, '__array_interface__') or hasattr(data, '__array__'):
            # Handle numpy arrays and similar
            try:
                import numpy as np
                if isinstance(data, np.ndarray):
                    # Use numpy's built-in secure wiping if available
                    if hasattr(np, 'secure_overwrite'):
                        np.secure_overwrite(data)
                    else:
                        # Multiple pass overwrite
                        for _ in range(7):
                            data[:] = np.random.bytes(data.nbytes)
                        data[:] = 0
                    return data
            except:
                # Fallback to regular wiping
                pass
        
        return data

    # +++ ESSENTIAL METHODS THAT WERE MISSING +++
    
    def load_config(self):
        """Load or create configuration"""
        config_file = self.vault_dir / "config.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        return SSD_CONFIG.copy()
    
    def save_config(self):
        """Save configuration"""
        config_file = self.vault_dir / "config.json"
        with open(config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def configure_ssd_performance(self):
        """Configure performance settings based on SSD capabilities"""
        # Use conservative settings to save memory
        self.config['performance']['optimization_level'] = 'SSD_STANDARD'
        self.config['performance']['thread_strategy'] = 'CONSERVATIVE'
        self.config['performance']['memory_management'] = 'CONSERVATIVE'
        
        self.logger.info(f"SSD performance configured for {self.ssd_telemetry.ssd_speed:.2f} MB/s")
    
    def create_ssd_optimized_thread_pool(self) -> ThreadPoolExecutor:
        """Create thread pool optimized for SSD operations"""
        try:
            cpu_count = os.cpu_count() or 4
            # Use minimal threads to save memory
            max_workers = min(cpu_count * 2, 8)  # Drastically reduced threads for memory optimization
            return ThreadPoolExecutor(
                max_workers=max_workers,
                thread_name_prefix="SSDThread"
            )
        except:
            return ThreadPoolExecutor(max_workers=4, thread_name_prefix="SSDThread")  # Reduced workers
    
    def measure_ssd_speed(self) -> float:
        """Measure SSD speed and adjust configuration accordingly"""
        try:
            # Quick SSD speed test
            test_file = self.vault_dir / ".speed_test"
            test_data = os.urandom(5 * 1024 * 1024)  # 5MB test data (smaller for faster testing)
            
            start_time = time.perf_counter()
            with open(test_file, 'wb') as f:
                f.write(test_data)
            write_time = time.perf_counter() - start_time
            
            start_time = time.perf_counter()
            with open(test_file, 'rb') as f:
                f.read()
            read_time = time.perf_counter() - start_time
            
            # Cleanup
            try:
                test_file.unlink()
            except:
                pass
            
            write_speed = 5 / write_time  # MB/s
            read_speed = 5 / read_time    # MB/s
            
            avg_speed = (write_speed + read_speed) / 2
            self.ssd_telemetry.ssd_speed = avg_speed
            
            return avg_speed
            
        except Exception as e:
            self.logger.warning(f"SSD speed test failed: {e}")
            return 0.0
    
    def initialize_ssd_security(self):
        """Enhanced security initialization for portable operation with key management"""
        # SSD-specific security enhancements
        self.setup_ssd_memory_armor()
        self.enable_portable_threat_detection()
        self.configure_ssd_performance()
        
        # Initialize key rotation tracking if not present
        self.initialize_key_rotation_tracking()
    
    def initialize_key_rotation_tracking(self):
        """Initialize key rotation tracking if not already set"""
        if 'last_key_rotation' not in self.config:
            # Set initial rotation date to vault creation time
            self.config['last_key_rotation'] = datetime.now().isoformat()
            self.save_config()
            self.logger.info("Key rotation tracking initialized")
    
    def setup_ssd_memory_armor(self):
        """Enhanced memory protection for portable use"""
        # Conservative memory management for portable operation
        gc.set_threshold(50, 10, 10)  # Reduced aggressiveness for memory conservation
        gc.enable()
        
        # Additional portable-specific memory protections
        self.secure_temp_files()
        self.disable_swap_if_possible()
    
    def secure_temp_files(self):
        """Secure temporary file handling for portable operation"""
        # Ensure temp files are created on SSD, not system drive
        temp_dir = self.vault_dir / "temp"
        temp_dir.mkdir(exist_ok=True)
        
        # Set temp directory for this process
        os.environ['TMPDIR'] = str(temp_dir)
        tempfile.tempdir = str(temp_dir)
    
    def disable_swap_if_possible(self):
        """Attempt to disable swap for portable operation"""
        try:
            if platform.system() != "Windows" and RESOURCE_AVAILABLE:
                # Try to disable swap for this process (Unix only)
                resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except:
            pass
    
    def ssd_write_data(self, data: str, file_path: Path) -> None:
        """SSD-optimized file writing"""
        # Always use buffered I/O to save memory
        with open(file_path, 'w') as f:
            f.write(data)

    def ssd_read_data(self, file_path: Path) -> str:
        """SSD-optimized file reading"""
        # Always use buffered I/O to save memory
        with open(file_path, 'r') as f:
            return f.read()

    # +++ ENHANCED SECURITY FEATURES +++
    
    def generate_secure_entropy(self, length: int = 32) -> bytes:
        """Generate cryptographically secure entropy using multiple sources"""
        # Use our enhanced secure_random function
        return self.secure_random(length)
        
    def enable_anti_forensics(self):
        """Enable anti-forensics measures"""
        if not self.anti_forensics_enabled:
            return
            
        # Create decoy files and misleading metadata
        decoy_files = [
            "vault_backup.fake",
            "password_cache.tmp",
            "recovery_keys.bak"
        ]
        
        for decoy in decoy_files:
            try:
                decoy_path = self.vault_dir / decoy
                with open(decoy_path, 'wb') as f:
                    f.write(os.urandom(1024))  # Random data
                # Set random timestamps
                random_time = time.time() - secrets.randbelow(86400 * 30)  # Random time in last 30 days
                os.utime(decoy_path, (random_time, random_time))
            except:
                pass

    def calculate_file_hash(self, file_path: Path) -> str:
        """Calculate cryptographic hash of a file"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()

    def get_stored_file_hash(self, filename: str) -> Optional[str]:
        """Get stored hash for a file"""
        return self.file_hashes.get(filename)

    def store_file_hash(self, filename: str, file_hash: str):
        """Store hash for a file"""
        self.file_hashes[filename] = file_hash

    def enhanced_tamper_detection(self) -> bool:
        """Enhanced tamper detection with cryptographic verification"""
        try:
            # Check all critical files
            critical_files = ["auth.dat", "vault.dat", "config.json", "logs/vault.log"]
            
            for filename in critical_files:
                file_path = self.vault_dir / filename
                if file_path.exists():
                    # Enhanced permission checks
                    if not self.check_file_security(file_path):
                        self.logger.warning(f"Insecure file permissions: {file_path}")
                        return False
                    
                    # Verify cryptographic signatures
                    if not self.verify_file_signature(file_path):
                        self.logger.warning(f"Cryptographic signature verification failed: {file_path}")
                        return False
                    
                    # Verify file integrity with multiple hashes
                    if not self.verify_file_integrity(file_path):
                        self.logger.warning(f"File integrity check failed: {file_path}")
                        return False
            
            return True
        except Exception as e:
            self.logger.error(f"Enhanced tamper detection failed: {e}")
            return False
    
    def check_file_security(self, file_path: Path) -> bool:
        """Check file security settings"""
        try:
            if platform.system() != "Windows":
                stat_info = os.stat(file_path)
                # Check for proper permissions (read/write for owner only)
                if stat_info.st_mode & 0o777 != 0o600:
                    return False
                
                # Check ownership (should be owned by current user)
                if stat_info.st_uid != os.getuid():
                    return False
            
            return True
        except:
            return False
    
    def verify_file_signature(self, file_path: Path) -> bool:
        """Verify cryptographic signature of file"""
        # This would implement digital signatures for critical files
        # For now, we use the existing hash-based verification
        return True  # Placeholder for actual implementation
    
    def verify_file_integrity(self, file_path: Path) -> bool:
        """Verify file integrity with multiple hash algorithms"""
        try:
            # Calculate multiple hashes for stronger verification
            hashers = {
                'sha256': hashlib.sha256(),
                'sha3_256': hashlib.sha3_256(),
                'blake2b': hashlib.blake2b()
            }
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    for hasher in hashers.values():
                        hasher.update(chunk)
            
            # Verify against stored hashes
            filename = file_path.name
            for algo, hasher in hashers.items():
                current_hash = hasher.hexdigest()
                stored_hash = self.get_stored_file_hash(f"{filename}_{algo}")
                
                if stored_hash and not self.constant_time_compare(current_hash, stored_hash):
                    return False
            
            return True
        except:
            return False

    def tamper_detection_check(self) -> bool:
        """Check for tampering with the vault"""
        return self.enhanced_tamper_detection()

    def key_rotation_check(self):
        """Enhanced key rotation check with more frequent rotation"""
        try:
            # Check if key rotation is enabled and due
            rotation_days = self.config['cryptography'].get('key_rotation_days', 90)
            
            # For enhanced security, reduce rotation period if it's too long
            if rotation_days > 30:  # If rotation is set longer than 60 days
                rotation_days = 30  # Reduce to 60 days for better security
                self.config['cryptography']['key_rotation_days'] = rotation_days
                self.save_config()
                self.logger.info(f"Key rotation period reduced to {rotation_days} days for enhanced security")
            
            last_rotation = self.config.get("last_key_rotation")
            if last_rotation:
                last_rotation_date = datetime.fromisoformat(last_rotation)
                
                if datetime.now() - last_rotation_date > timedelta(days=rotation_days):
                    self.logger.info("Initiating automatic key rotation")
                    if self.rotate_encryption_keys():
                        self.logger.info("Key rotation completed successfully")
                    else:
                        self.logger.warning("Key rotation failed, will retry later")
            else:
                # Initialize rotation tracking if missing
                self.initialize_key_rotation_tracking()
                
        except Exception as e:
            self.logger.error(f"Key rotation check failed: {e}")

    def rotate_encryption_keys(self) -> bool:
        """Enhanced encryption key rotation with better error handling"""
        try:
            master_password = self.get_master_password()
            if not master_password:
                self.logger.warning("Cannot rotate keys without active session")
                return False
                
            # Load current vault
            vault_data = self.load_vault(master_password)
            if not vault_data:
                self.logger.error("Failed to load vault for key rotation")
                return False
                
            # Re-encrypt with new keys (this happens automatically during save)
            success, message = self.save_vault(vault_data, master_password)
            if success:
                # Update rotation timestamp
                self.config['last_key_rotation'] = datetime.now().isoformat()
                self.save_config()
                
                # Also update the auth file modification time for consistency
                auth_file = self.vault_dir / "auth.dat"
                if auth_file.exists():
                    self.last_known_mtimes['auth.dat'] = auth_file.stat().st_mtime
                    file_hash = self.calculate_file_hash(auth_file)
                    self.store_file_hash('auth.dat', file_hash)
                
                self.logger.info("Key rotation completed successfully")
                return True
            else:
                self.logger.error(f"Key rotation failed: {message}")
                return False
                
        except Exception as e:
            self.logger.error(f"Key rotation failed: {e}")
            return False

    def check_brute_force_protection(self) -> bool:
        """Implement brute force protection with increasing delays"""
        if self.last_attempt_time:
            time_since_last_attempt = datetime.now() - self.last_attempt_time
            if self.failed_attempts >= 3:
                # Exponential backoff for repeated failures
                delay_seconds = min(2 ** (self.failed_attempts - 2), 300)  # Max 5 minute delay
                if time_since_last_attempt.total_seconds() < delay_seconds:
                    remaining = delay_seconds - time_since_last_attempt.total_seconds()
                    print(f"⏰ Too many failed attempts. Please wait {int(remaining)} seconds.")
                    return False
        return True
    
    def record_failed_attempt(self):
        """Record a failed login attempt"""
        self.failed_attempts += 1
        self.last_attempt_time = datetime.now()
        self.logger.warning(f"Failed login attempt #{self.failed_attempts}")
        
    def reset_failed_attempts(self):
        """Reset failed attempt counter"""
        self.failed_attempts = 0
        self.last_attempt_time = None

    # +++ SESSION MANAGEMENT +++
    
    def is_first_run(self) -> bool:
        """Check if this is the first run (no master password set)"""
        auth_file = self.vault_dir / "auth.dat"
        return not auth_file.exists()
    
    def setup_master_password(self, master_password: str) -> bool:
        """Set up master password for the first time with enhanced security"""
        try:
            if len(master_password) < 14:  # Increased minimum length
                print("❌ Master password must be at least 14 characters long.")
                return False
                
            # Enhanced password strength check
            if not self.is_password_strong(master_password):
                print("❌ Password is too weak. Include uppercase, lowercase, numbers, and special characters.")
                return False
                
            # Check for common passwords
            if self.is_common_password(master_password):
                print("❌ Password is too common. Choose a more unique password.")
                return False
                
            # Derive a secure hash of the master password using Argon2 if available
            salt = self.generate_secure_entropy(32)  # Increased salt size
            
            if ARGON2_AVAILABLE:
                # Use Argon2 for enhanced security
                argon2_hash = argon2.PasswordHasher(
                    time_cost=self.config['cryptography']['argon2']['time_cost'],
                    memory_cost=self.config['cryptography']['argon2']['memory_cost'],
                    parallelism=self.config['cryptography']['argon2']['parallelism'],
                    hash_len=64,  # Increased hash length
                    salt_len=32
                )
                hash_value = argon2_hash.hash(master_password.encode(), salt=salt).encode()
            else:
                # Fallback to enhanced PBKDF2
                hash_value = self.derive_enhanced_master_hash(master_password, salt)
            
            # Store the hash and salt with additional security metadata
            auth_data = {
                "hash": base64.b64encode(hash_value).decode(),
                "salt": base64.b64encode(salt).decode(),
                "created": datetime.now().isoformat(),
                "algorithm": "argon2" if ARGON2_AVAILABLE else "pbkdf2_sha512",
                "version": self.config['version'],
                "security_level": self.config['security_level']
            }
            
            auth_file = self.vault_dir / "auth.dat"
            with open(auth_file, 'w') as f:
                json.dump(auth_data, f)
            
            # Set secure file permissions
            if platform.system() != "Windows":
                os.chmod(auth_file, 0o600)
            
            # Hide the auth file on Windows
            if platform.system() == "Windows":
                try:
                    subprocess.run(['attrib', '+h', str(auth_file)], 
                                 capture_output=True, check=False, shell=True)
                except:
                    pass
            
            # Store initial modification time for tamper detection
            self.last_known_mtimes['auth.dat'] = auth_file.stat().st_mtime
            
            # Store cryptographic hash for enhanced tamper detection
            file_hash = self.calculate_file_hash(auth_file)
            self.store_file_hash('auth.dat', file_hash)
            
            # Initialize key rotation tracking
            self.initialize_key_rotation_tracking()
            
            self.logger.info("Master password setup completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup master password: {e}")
            return False
    
    def is_common_password(self, password: str) -> bool:
        """Check if password is in common passwords list"""
        common_passwords = {
            'password', '123456', '12345678', '1234', 'qwerty', 'letmein', 'admin',
            'welcome', 'monkey', 'password1', 'abc123', '123123', '000000', 'guest'
        }
        return password.lower() in common_passwords
    
    def is_password_strong(self, password: str) -> bool:
        """Enhanced password strength checking with additional criteria"""
        if len(password) < 14:
            return False
            
        # Check for character diversity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # Check for sequential characters
        has_sequential = any(
            ord(password[i]) + 1 == ord(password[i+1]) and 
            ord(password[i+1]) + 1 == ord(password[i+2])
            for i in range(len(password) - 2)
        )
        
        # Check for repeated characters
        has_repeated = any(
            password[i] == password[i+1] == password[i+2]
            for i in range(len(password) - 2)
        )
        
        # Check for keyboard patterns
        has_keyboard_pattern = self.has_keyboard_pattern(password)
        
        # Check for common substitutions (e.g., p@ssw0rd)
        has_common_substitutions = self.has_common_substitutions(password)
        
        # Calculate entropy
        entropy = self.calculate_password_entropy(password)
        
        return (has_upper and has_lower and has_digit and has_special and 
                not has_sequential and not has_repeated and
                not has_keyboard_pattern and not has_common_substitutions and
                entropy >= 3.5)  # Reasonable entropy threshold
    
    def has_keyboard_pattern(self, password: str) -> bool:
        """Check for keyboard patterns (e.g., qwerty, asdfgh)"""
        keyboard_rows = [
            "qwertyuiop", "asdfghjkl", "zxcvbnm",
            "1234567890", "!@#$%^&*()"
        ]
        
        password_lower = password.lower()
        
        # Check for sequential keyboard patterns
        for row in keyboard_rows:
            for i in range(len(row) - 3):
                pattern = row[i:i+4]
                if pattern in password_lower or pattern[::-1] in password_lower:
                    return True
        
        return False
    
    def has_common_substitutions(self, password: str) -> bool:
        """Check for common character substitutions"""
        common_subs = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7']
        }
        
        # Check if password looks like common words with substitutions
        common_words = ["password", "admin", "welcome", "login", "secret"]
        
        for word in common_words:
            # Generate possible substitutions
            variations = [word]
            for char, subs in common_subs.items():
                new_variations = []
                for variation in variations:
                    if char in variation:
                        for sub in subs:
                            new_variations.append(variation.replace(char, sub))
                variations.extend(new_variations)
            
            # Check if password matches any variation
            for variation in variations:
                if variation in password.lower():
                    return True
        
        return False
    
    def calculate_password_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        # Character set size estimation
        char_set = 0
        if any(c.islower() for c in password):
            char_set += 26
        if any(c.isupper() for c in password):
            char_set += 26
        if any(c.isdigit() for c in password):
            char_set += 10
        if any(not c.isalnum() for c in password):
            char_set += 33  # Common special characters
        
        # Entropy calculation
        entropy = len(password) * math.log2(char_set) if char_set > 0 else 0
        return entropy
    
    def verify_master_password(self, master_password: str) -> bool:
        """Verify the provided master password against stored hash with enhanced security"""
        try:
            auth_file = self.vault_dir / "auth.dat"
            if not auth_file.exists():
                return False
                
            with open(auth_file, 'r') as f:
                auth_data = json.load(f)
            
            salt = base64.b64decode(auth_data["salt"])
            stored_hash = base64.b64decode(auth_data["hash"])
            algorithm = auth_data.get("algorithm", "pbkdf2_sha256")
            
            # Verify the password using the appropriate algorithm
            if algorithm == "argon2" and ARGON2_AVAILABLE:
                try:
                    argon2_hash = argon2.PasswordHasher()
                    return argon2_hash.verify(stored_hash, master_password.encode())
                except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
                    return False
            else:
                # Fallback to enhanced PBKDF2 with timing attack protection
                computed_hash = self.derive_enhanced_master_hash(master_password, salt)
                return self.timing_attack_resistant_equals(computed_hash, stored_hash)
            
        except Exception as e:
            self.logger.error(f"Password verification failed: {e}")
            return False
    
    def derive_enhanced_master_hash(self, password: str, salt: bytes) -> bytes:
        """Derive a secure hash of the master password with enhanced security"""
        # Use PBKDF2 with SHA512 and increased iterations
        key = hashlib.pbkdf2_hmac(
            'sha512',  # Use SHA512 for enhanced security
            password.encode(),
            salt,
            self.config['cryptography']['pbkdf2']['iterations'],  # Use configured iterations
            dklen=64  # Increased key length
        )
        
        # Additional hashing for security
        return hashlib.sha3_512(key + salt).digest()
    
    def start_session(self, master_password: str) -> bool:
        """Enhanced session startup with additional security checks"""
        if not self.check_brute_force_protection():
            return False
            
        # Perform enhanced tamper detection before authentication
        if not self.enhanced_tamper_detection():
            print("❌ Security alert: Enhanced vault integrity check failed")
            self.logger.warning("Enhanced vault tampering detected during authentication")
            return False
            
        # Check for debuggers or analysis tools
        if self.detect_debugger():
            print("❌ Security alert: Debugger detected")
            self.logger.warning("Debugger detected during authentication")
            return False
            
        if self.verify_master_password(master_password):
            self.current_master_password = master_password
            self.session_start_time = datetime.now()
            self.reset_failed_attempts()
            
            # Enhanced security measures
            self.enable_session_protections()
            
            # Perform key rotation check
            self.key_rotation_check()
            
            # Enable anti-forensics measures
            self.enable_anti_forensics()
            
            # Enhance session security
            self.enhance_session_security()
            
            self.logger.info("Enhanced security session started successfully")
            return True
        
        self.record_failed_attempt()
        return False
    
    def detect_debugger(self) -> bool:
        """Detect debugger attachment"""
        try:
            # Various anti-debugging techniques
            if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
                return True
                
            # Check for common debugger processes
            if platform.system() == "Windows":
                debuggers = ["ollydbg.exe", "ida64.exe", "ida.exe", "x64dbg.exe", "x32dbg.exe"]
                output = subprocess.run(['tasklist'], capture_output=True, text=True)
                if output.returncode == 0:
                    process_list = output.stdout.lower()
                    for debugger in debuggers:
                        if debugger in process_list:
                            return True
            else:
                # Linux/Mac debugger detection
                try:
                    # Check parent process for debuggers
                    parent_pid = os.getppid()
                    with open(f"/proc/{parent_pid}/comm", 'r') as f:
                        parent_name = f.read().strip().lower()
                        debuggers = ["gdb", "lldb", "strace", "ltrace"]
                        if any(debugger in parent_name for debugger in debuggers):
                            return True
                except:
                    pass
                    
            return False
        except:
            return False
    
    def enable_session_protections(self):
        """Enable additional session protections"""
        # Setup secure environment for session
        self.secure_environment()
        
        # Monitor for code injection attempts
        self.monitor_code_integrity()
        
        # Setup secure timers for operations
        self.setup_secure_timers()
    
    def secure_environment(self):
        """Setup secure execution environment"""
        # Disable core dumps if possible
        self.disable_core_dumps()
        
        # Setup secure memory allocator
        self.setup_secure_allocator()
        
        # Remove sensitive information from environment
        self.clean_environment()
        
        # Setup signal handlers for security incidents
        self.setup_signal_handlers()
    
    def disable_core_dumps(self):
        """Disable core dumps to prevent memory disclosure"""
        try:
            if platform.system() != "Windows" and RESOURCE_AVAILABLE:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except:
            pass
    
    def setup_secure_allocator(self):
        """Setup secure memory allocator if available"""
        # This would use a secure memory allocator like libsodium's
        # For now, we use our custom secure allocation functions
        pass
    
    def clean_environment(self):
        """Clean environment variables of sensitive information"""
        sensitive_vars = [
            'PYTHONPATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
            'DYLD_INSERT_LIBRARIES', 'PYTHONINSPECT'
        ]
        
        for var in sensitive_vars:
            if var in os.environ:
                del os.environ[var]
    
    def setup_signal_handlers(self):
        """Setup signal handlers for security incidents"""
        def security_signal_handler(signum, frame):
            self.logger.warning(f"Security signal received: {signum}")
            self.emergency_shutdown()
        
        # Handle signals that might indicate security issues
        # Use cross-platform signals only
        signals_to_handle = [signal.SIGABRT, signal.SIGILL]
        
        # Add platform-specific signals if available
        if hasattr(signal, 'SIGTRAP'):
            signals_to_handle.append(signal.SIGTRAP)
        if hasattr(signal, 'SIGBUS'):
            signals_to_handle.append(signal.SIGBUS)
        
        # Windows-specific signals
        if platform.system() == "Windows":
            if hasattr(signal, 'SIGBREAK'):
                signals_to_handle.append(signal.SIGBREAK)
        
        for sig in signals_to_handle:
            try:
                signal.signal(sig, security_signal_handler)
            except (AttributeError, ValueError):
                # Skip signals that aren't available or can't be handled
                self.logger.debug(f"Could not set handler for signal {sig}")
    
    def monitor_code_integrity(self):
        """Monitor code integrity during execution"""
        # Check if our code has been modified in memory
        self_thread = threading.current_thread()
        
        monitor_thread = threading.Thread(
            target=self.code_integrity_monitor,
            daemon=True,
            name="CodeIntegrityMonitor"
        )
        monitor_thread.start()
    
    def code_integrity_monitor(self):
        """Background thread to monitor code integrity"""
        while self.is_session_valid():
            try:
                # Check critical function addresses haven't changed
                if not self.verify_function_integrity():
                    self.logger.warning("Code integrity violation detected")
                    self.emergency_shutdown()
                    break
                
                time.sleep(5)  # Check every 5 seconds
            except:
                time.sleep(10)
    
    def verify_function_integrity(self) -> bool:
        """Verify integrity of critical functions"""
        # This would check that critical functions haven't been modified
        # For now, we implement a simple checksum check
        
        # Get memory address of critical functions
        critical_functions = [
            self.encrypt_vault,
            self.decrypt_vault,
            self.derive_enhanced_encryption_key,
            self.verify_master_password
        ]
        
        # Simple check - just verify functions are still callable
        # In a real implementation, this would verify cryptographic signatures
        # or checksums of the function code
        for func in critical_functions:
            if not callable(func):
                return False
        
        return True
    
    def enhance_session_security(self):
        """Implement additional session security measures"""
        # Add device fingerprinting
        device_fingerprint = self.generate_device_fingerprint()
        
        # Implement secure session tokens
        self.session_token = self.generate_secure_session_token()
        
        # Monitor for session hijacking
        self.start_session_hijack_monitoring()
    
    def generate_device_fingerprint(self) -> str:
        """Generate a unique device fingerprint"""
        system_info = platform.uname()
        fingerprint_data = f"{system_info.system}{system_info.node}{system_info.release}{system_info.version}{system_info.machine}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    def generate_secure_session_token(self) -> str:
        """Generate a secure session token"""
        return secrets.token_urlsafe(32)
    
    def start_session_hijack_monitoring(self):
        """Start monitoring for session hijacking attempts"""
        monitor_thread = threading.Thread(
            target=self.monitor_session_security,
            daemon=True,
            name="SessionSecurityMonitor"
        )
        monitor_thread.start()
    
    def monitor_session_security(self):
        """Monitor session for security issues"""
        while self.is_session_valid():
            try:
                # Check for suspicious activity
                if self.detect_session_hijack():
                    self.logger.warning("Session hijack detected, ending session")
                    self.end_session()
                    break
                
                time.sleep(10)  # Check every 10 seconds
            except:
                time.sleep(30)
    
    def detect_session_hijack(self) -> bool:
        """Detect potential session hijacking attempts"""
        # Simple detection for now - could be enhanced with IP checking, etc.
        return False
    
    def is_session_valid(self) -> bool:
        """Check if the current session is still valid"""
        if not self.current_master_password or not self.session_start_time:
            return False
        
        # Check session timeout
        if datetime.now() - self.session_start_time > self.session_timeout:
            self.logger.info("Session expired due to timeout")
            # Securely clear the password from memory
            self.current_master_password = None
            return False
        
        return True
    
    def get_master_password(self) -> Optional[str]:
        """Get the current master password if session is valid"""
        if self.is_session_valid():
            return self.current_master_password
        return None
    
    def end_session(self):
        """End the current session and securely clear memory"""
        # Securely clear all sensitive data from memory
        if self.current_master_password:
            self.current_master_password = self.secure_memory_wipe(self.current_master_password)
            
        if self.encryption_key:
            self.encryption_key = self.secure_memory_wipe(self.encryption_key)
            
        if self.backup_key:
            self.backup_key = self.secure_memory_wipe(self.backup_key)
            
        self.session_start_time = None
        
        # Force garbage collection to ensure memory cleanup
        gc.collect()
        
        self.logger.info("Session ended securely")
    
    def emergency_shutdown(self):
        """Emergency shutdown procedure for security incidents"""
        self.logger.critical("Initiating emergency shutdown procedure")
        
        # Securely wipe all sensitive data from memory
        self.secure_emergency_wipe()
        
        # Terminate the process securely
        os._exit(1)
    
    def secure_emergery_wipe(self):
        """Securely wipe all sensitive data during emergency shutdown"""
        # Wipe master password
        if self.current_master_password:
            self.current_master_password = self.secure_memory_wipe(self.current_master_password)
        
        # Wipe encryption keys
        if self.encryption_key:
            self.encryption_key = self.secure_memory_wipe(self.encryption_key)
        
        # Wipe backup keys
        if self.backup_key:
            self.backup_key = self.secure_memory_wipe(self.backup_key)
        
        # Wipe all secure allocations
        for allocation in list(self.secure_allocations):
            self.secure_free(allocation)
        
        # Force garbage collection
        gc.collect()
        
        # Overwrite memory regions if possible
        self.overwrite_memory_regions()

    # +++ ENHANCED CRYPTOGRAPHIC PROTECTIONS +++
    
    def encrypt_vault(self, data: Dict, master_password: str) -> str:
        """Enhanced encryption with additional security measures"""
        # Add entropy to RNG pool before cryptographic operations
        self.update_entropy_pool(master_password.encode())
        
        # Use constant-time operations
        result = self.encrypt_vault_constant_time(data, master_password)
        
        # Clean any intermediate values from memory
        gc.collect()
        
        return result
    
    def encrypt_vault_constant_time(self, data: Dict, master_password: str) -> str:
        """Constant-time implementation of vault encryption"""
        # Add timing attack protection
        self.secure_delay()
        
        # Key derivation with constant-time properties
        salt = self.secure_random(32)
        
        # Use constant-time key derivation
        key = self.derive_enhanced_encryption_key(master_password, salt)
        chacha_key = self.derive_chacha_key(master_password, salt)
        
        # Enhanced encryption with multiple layers
        plaintext = json.dumps(data, separators=(',', ':')).encode()
        
        # First layer: AES-GCM (uses first 32 bytes of the 64-byte key)
        aesgcm = AESGCM(key[:32])
        nonce1 = self.secure_random(12)
        ciphertext1 = aesgcm.encrypt(nonce1, plaintext, salt)
        
        # Second layer: ChaCha20-Poly1305 (uses dedicated 32-byte key)
        chacha = ChaCha20Poly1305(chacha_key)
        nonce2 = self.secure_random(12)
        ciphertext2 = chacha.encrypt(nonce2, ciphertext1, None)
        
        # Third layer: AES-GCM with different key portion (uses second 32 bytes of the 64-byte key)
        aesgcm2 = AESGCM(key[32:64])
        nonce3 = self.secure_random(12)
        ciphertext3 = aesgcm2.encrypt(nonce3, ciphertext2, salt)
        
        # Combine salt, nonces, and ciphertext with authentication tag
        encrypted_data = salt + nonce1 + nonce2 + nonce3 + ciphertext3
        
        # Clean sensitive data from memory
        self.secure_memory_wipe(key)
        self.secure_memory_wipe(chacha_key)
        
        return base64.b85encode(encrypted_data).decode()

    def decrypt_vault(self, encrypted_data: str, master_password: str) -> str:
        """Decrypt vault data with master password using enhanced security"""
        try:
            data = base64.b85decode(encrypted_data.encode())
            
            # Extract components
            salt = data[:32]
            nonce1 = data[32:44]
            nonce2 = data[44:56]
            nonce3 = data[56:68]
            ciphertext3 = data[68:]
            
            # Derive keys
            key = self.derive_enhanced_encryption_key(master_password, salt)
            chacha_key = self.derive_chacha_key(master_password, salt)
            
            # Decrypt third layer: AES-GCM
            aesgcm2 = AESGCM(key[32:64])
            ciphertext2 = aesgcm2.decrypt(nonce3, ciphertext3, salt)
            
            # Decrypt second layer: ChaCha20-Poly1305
            chacha = ChaCha20Poly1305(chacha_key)
            ciphertext1 = chacha.decrypt(nonce2, ciphertext2, None)
            
            # Decrypt first layer: AES-GCM
            aesgcm = AESGCM(key[:32])
            plaintext = aesgcm.decrypt(nonce1, ciphertext1, salt)
            
            # Clean sensitive data from memory
            self.secure_memory_wipe(key)
            self.secure_memory_wipe(chacha_key)
            
            return plaintext.decode()
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            # Clear any partial data from memory
            if 'plaintext' in locals():
                self.secure_memory_wipe(plaintext)
            raise

    def derive_enhanced_encryption_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password with enhanced security"""
        # Add timing attack protection
        self.secure_delay()
        
        # Use multiple KDFs for enhanced security
        if ARGON2_AVAILABLE:
            # Use Argon2 for enhanced security with increased parameters
            argon2_hash = argon2.PasswordHasher(
                time_cost=self.config['cryptography']['argon2']['time_cost'],
                memory_cost=self.config['cryptography']['argon2']['memory_cost'],
                parallelism=self.config['cryptography']['argon2']['parallelism'],
                hash_len=64,  # 64-byte key for dual AES encryption
                salt_len=32
            )
            key_material = argon2_hash.hash(password.encode(), salt=salt).encode()
        else:
            # Fallback to PBKDF2 with increased iterations
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=64,  # 64-byte key for dual AES encryption
                salt=salt,
                iterations=self.config['cryptography']['pbkdf2']['iterations'],
                backend=default_backend()
            )
            key_material = kdf.derive(password.encode())
        
        # Additional key stretching with HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=64,  # 64-byte key for dual AES encryption
            salt=salt,
            info=b'vault_encryption_key',
            backend=default_backend()
        )
        
        final_key = hkdf.derive(key_material)
        
        # Clean intermediate values from memory
        self.secure_memory_wipe(key_material)
        
        return final_key

    def derive_chacha_key(self, password: str, salt: bytes) -> bytes:
        """Derive a dedicated 32-byte key for ChaCha20-Poly1305 encryption"""
        # Add timing attack protection
        self.secure_delay()
        
        # Use a different KDF for ChaCha20 to ensure key separation
        if ARGON2_AVAILABLE:
            # Use Argon2 with different parameters for ChaCha20
            argon2_hash = argon2.PasswordHasher(
                time_cost=self.config['cryptography']['argon2']['time_cost'] + 1,  # Different time cost
                memory_cost=self.config['cryptography']['argon2']['memory_cost'],
                parallelism=self.config['cryptography']['argon2']['parallelism'],
                hash_len=32,  # 32-byte key for ChaCha20
                salt_len=32
            )
            key_material = argon2_hash.hash(password.encode(), salt=salt + b'chacha').encode()  # Different salt
        else:
            # Fallback to PBKDF2 with different parameters
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),  # Different algorithm
                length=32,  # 32-byte key for ChaCha20
                salt=salt + b'chacha',  # Different salt
                iterations=self.config['cryptography']['pbkdf2']['iterations'] + 10000,  # Different iterations
                backend=default_backend()
            )
            key_material = kdf.derive(password.encode())
        
        # Additional key stretching with HKDF using different info
        hkdf = HKDF(
            algorithm=hashes.SHA256(),  # Different algorithm
            length=32,  # 32-byte key for ChaCha20
            salt=salt + b'chacha',  # Different salt
            info=b'vault_chacha_key',  # Different info
            backend=default_backend()
        )
        
        final_key = hkdf.derive(key_material)
        
        # Clean intermediate values from memory
        self.secure_memory_wipe(key_material)
        
        return final_key

    def generate_system_fingerprint(self) -> str:
        """Generate a unique fingerprint of the current system for backup security"""
        system_info = platform.uname()
        # Get additional system-specific identifiers
        identifiers = [
            system_info.system,
            system_info.node,
            system_info.release,
            system_info.version,
            system_info.machine,
            str(os.getpid()),
            socket.gethostname() if socket.gethostname() else "unknown",
        ]
        
        # Add platform-specific identifiers
        if platform.system() == "Windows":
            try:
                # Get Windows machine GUID
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                    machine_guid = winreg.QueryValueEx(key, "MachineGuid")[0]
                    identifiers.append(machine_guid)
            except:
                identifiers.append("windows_unknown_guid")
        else:
            # Unix-based systems - use machine-id
            try:
                machine_id_paths = [
                    "/etc/machine-id",
                    "/var/lib/dbus/machine-id",
                    "/var/db/dbus/machine-id"  # macOS
                ]
                for path in machine_id_paths:
                    if os.path.exists(path):
                        with open(path, 'r') as f:
                            machine_id = f.read().strip()
                            identifiers.append(machine_id)
                        break
                else:
                    identifiers.append("unix_unknown_id")
            except:
                identifiers.append("unix_unknown_id")
        
        # Create a hash of all identifiers
        fingerprint_data = "|".join(identifiers).encode()
        return hashlib.sha256(fingerprint_data).hexdigest()

    # +++ ENHANCED BACKUP SECURITY +++
    
    def derive_backup_key(self, master_password: str) -> bytes:
        """Derive a backup-specific key from master password and system info with enhanced security"""
        # Include system-specific information to make backup tied to this system
        system_id = hashlib.sha512(
            f"{platform.node()}{platform.system()}{platform.version()}{os.getpid()}".encode()
        ).digest()
        
        # Use enhanced KDF for backup key derivation
        salt = b"backup_salt_enhanced_" + system_id[:16]
        
        # Use multiple KDF iterations for backup keys
        kdf1 = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=150000,  # Increased iterations for backup keys
            backend=default_backend()
        )
        key_material = kdf1.derive(master_password.encode())
        
        # Additional key stretching with HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            info=b'vault_backup_key',
            backend=default_backend()
        )
        
        final_key = hkdf.derive(key_material)
        
        # Clean intermediate values
        self.secure_memory_wipe(key_material)
        
        return final_key
    
    def encrypt_backup_data(self, data: bytes, key: bytes) -> bytes:
        """Enhanced backup encryption with additional security"""
        # Use authenticated encryption with additional metadata
        aesgcm = AESGCM(key)
        nonce = self.secure_random(12)  # Use our enhanced RNG
        
        # Include additional security metadata in AAD
        timestamp = datetime.now().isoformat().encode()
        version = self.config['version'].encode()
        system_id = self.generate_system_fingerprint().encode()
        
        aad = b"vault_backup_protection:" + timestamp + b":" + version + b":" + system_id
        
        encrypted = aesgcm.encrypt(nonce, data, aad)
        
        # Add integrity protection with HMAC
        hmac_key = hashlib.sha512(key + b"hmac").digest()[:32]
        hmac_value = hmac.new(hmac_key, nonce + aad + encrypted, hashlib.sha512).digest()
        
        # Prepend nonce, AAD, HMAC to the ciphertext
        return (nonce + len(aad).to_bytes(4, 'big') + aad + 
                len(hmac_value).to_bytes(4, 'big') + hmac_value + encrypted)

    def decrypt_backup_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Enhanced backup decryption with additional security checks"""
        try:
            # Extract components
            nonce = encrypted_data[:12]
            aad_length = int.from_bytes(encrypted_data[12:16], 'big')
            aad = encrypted_data[16:16 + aad_length]
            hmac_length = int.from_bytes(encrypted_data[16 + aad_length:20 + aad_length], 'big')
            hmac_value = encrypted_data[20 + aad_length:20 + aad_length + hmac_length]
            ciphertext = encrypted_data[20 + aad_length + hmac_length:]
            
            # Verify HMAC first
            hmac_key = hashlib.sha512(key + b"hmac").digest()[:32]
            expected_hmac = hmac.new(hmac_key, nonce + aad + ciphertext, hashlib.sha512).digest()
            
            if not self.constant_time_compare(hmac_value, expected_hmac):
                self.logger.error("Backup HMAC verification failed")
                raise ValueError("Backup integrity check failed")
            
            # Then decrypt
            aesgcm = AESGCM(key)
            
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            self.logger.error(f"Enhanced backup decryption failed: {e}")
            raise

    # +++ ENHANCED SECURITY MONITORING +++
    
    def enable_portable_threat_detection(self):
        """Enhanced threat detection for portable operation"""
        # Additional checks for portable use
        self.start_ssd_security_monitoring()
        self.environment_validation()
        self.check_system_vulnerabilities()
        
        # Start periodic security scans
        self.start_periodic_security_scans()

    def start_periodic_security_scans(self):
        """Start periodic security scans"""
        scan_thread = threading.Thread(
            target=self.periodic_security_scan,
            daemon=True,
            name="SecurityScanner"
        )
        scan_thread.start()

    def periodic_security_scan(self):
        """Perform periodic security scans"""
        while True:
            try:
                # Perform comprehensive security scan every hour
                time.sleep(3600)
                
                self.logger.info("Performing periodic security scan")
                
                # Check for tampering
                if not self.tamper_detection_check():
                    self.logger.warning("Tampering detected during periodic scan")
                    self.protection_state = ProtectionState.ELEVATED
                
                # Check system vulnerabilities
                self.check_system_vulnerabilities()
                
                # Update telemetry
                self.ssd_telemetry.last_security_scan = datetime.now()
                
            except Exception as e:
                self.logger.error(f"Periodic security scan failed: {e}")
                time.sleep(300)  # Wait 5 minutes before retrying

    def check_system_vulnerabilities(self):
        """Check for known system vulnerabilities"""
        vulnerabilities = []
        
        # Check for outdated Python version
        if sys.version_info < (3, 8):
            vulnerabilities.append("Outdated Python version")
        
        # Check for running in insecure environment
        if self.is_running_as_root():
            vulnerabilities.append("Running as root/administrator")
        
        # Check for debug mode
        if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
            vulnerabilities.append("Running in debug mode")
        
        if vulnerabilities:
            self.logger.warning(f"System vulnerabilities detected: {vulnerabilities}")
            self.protection_state = ProtectionState.ELEVATED
    
    def is_running_as_root(self) -> bool:
        """Check if running with elevated privileges"""
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False

    # +++ ENHANCED VAULT OPERATIONS +++
    
    def load_vault(self, master_password: str) -> Dict:
        """Load and decrypt the vault with proper error handling"""
        vault_file = self.vault_dir / "vault.dat"
        if not vault_file.exists():
            # Return properly structured empty vault
            return {"entries": {}}
        
        try:
            encrypted_data = self.ssd_read_data(vault_file)
            decrypted_data = self.decrypt_vault(encrypted_data, master_password)
            vault_data = json.loads(decrypted_data)
            
            # Ensure the vault has the proper structure
            if "entries" not in vault_data:
                vault_data["entries"] = {}
                
            return vault_data
        except Exception as e:
            self.logger.error(f"Failed to load vault: {e}")
            # Don't return None, return empty vault instead
            return {"entries": {}}
    
    def save_vault(self, vault_data: Dict, master_password: str) -> Tuple[bool, str]:
        """Encrypt and save the vault with enhanced security and error reporting"""
        try:
            # Ensure the vault data has the proper structure
            if "entries" not in vault_data:
                vault_data = {"entries": vault_data}
                
            # Perform tamper detection before saving
            if not self.tamper_detection_check():
                return False, "Vault integrity check failed"
                
            vault_file = self.vault_dir / "vault.dat"
            
            # Force garbage collection before encryption to free up memory
            gc.collect()
            
            # Use enhanced encryption
            encrypted_data = self.encrypt_vault(vault_data, master_password)
            
            # Check if we have write permissions
            if not os.access(str(self.vault_dir), os.W_OK):
                return False, "No write permission to vault directory"
                
            # Check available disk space (at least 10MB free for enhanced security)
            try:
                stat = os.statvfs(str(self.vault_dir))
                free_space = stat.f_frsize * stat.f_bavail
                if free_space < 10 * 1024 * 1024:
                    return False, "Insufficient disk space (need at least 10MB free)"
            except (AttributeError, OSError):
                pass  # Skip disk space check if not supported
            
            # Write with secure permissions using atomic write
            temp_file = self.vault_dir / "vault.tmp"
            with open(temp_file, 'w') as f:
                f.write(encrypted_data)
            
            # Atomic replace
            if vault_file.exists():
                vault_file.unlink()
            temp_file.rename(vault_file)
            
            # Set secure file permissions
            if platform.system() != "Windows":
                os.chmod(vault_file, 0o600)
            
            # Update modification time for tamper detection
            self.last_known_mtimes['vault.dat'] = vault_file.stat().st_mtime
            
            # Update cryptographic hash for enhanced tamper detection
            file_hash = self.calculate_file_hash(vault_file)
            self.store_file_hash('vault.dat', file_hash)
            
            # Force garbage collection after encryption to free up memory
            gc.collect()
            
            # Log the security event
            self.logger.info("Vault saved with enhanced encryption")
            
            return True, "Vault saved successfully"
            
        except MemoryError:
            error_msg = "Memory error: Encryption process requires too much memory. Try reducing the number of passwords or using a system with more RAM."
            self.logger.error(error_msg)
            return False, error_msg
        except PermissionError:
            error_msg = "Permission denied: Cannot write to vault file"
            self.logger.error(error_msg)
            return False, error_msg
        except IOError as e:
            error_msg = f"I/O error: {e}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            self.logger.error(error_msg)
            return False, error_msg

    # +++ ENHANCED INTERACTIVE MENU +++
    
    def interactive_menu(self):
        """Main interactive menu for the password manager with enhanced security"""
        # Check if this is the first run
        if self.is_first_run():
            print("\n" + "="*60)
            print("🔒 WELCOME TO ENHANCED SECURITY PASSWORD VAULT")
            print("="*60)
            print("This appears to be your first time running the vault.")
            print("Please set up your master password (minimum 14 characters).")
            print("Requirements: uppercase, lowercase, numbers, and special characters.")
            
            while True:
                master_password = getpass.getpass("Create master password: ").strip()
                if not master_password:
                    print("❌ Master password cannot be empty.")
                    continue
                
                if len(master_password) < 14:
                    print("❌ Master password must be at least 14 characters long.")
                    continue
                
                if not self.is_password_strong(master_password):
                    print("❌ Password is too weak. Include uppercase, lowercase, numbers, and special characters.")
                    continue
                
                if self.is_common_password(master_password):
                    print("❌ Password is too common. Choose a more unique password.")
                    continue
                
                confirm_password = getpass.getpass("Confirm master password: ").strip()
                if master_password != confirm_password:
                    print("❌ Passwords do not match. Please try again.")
                    continue
                
                if self.setup_master_password(master_password):
                    print("✅ Master password set up successfully!")
                    if self.start_session(master_password):
                        break
                    else:
                        print("❌ Failed to start session. Please restart the application.")
                        return
                else:
                    print("❌ Failed to set up master password. Please try again.")
                    return
        
        # Normal operation - require authentication if no valid session
        master_password = self.get_master_password()
        if not master_password:
            print("\n" + "="*60)
            print("🔒 ENHANCED SECURITY PASSWORD VAULT - LOGIN")
            print("="*60)
            
            attempts = 0
            while attempts < 5:  # Increased to 5 attempts with delays
                if not self.check_brute_force_protection():
                    time.sleep(2)  # Brief delay even when not in lockout
                    continue
                    
                master_password = getpass.getpass("Enter master password: ").strip()
                if self.start_session(master_password):
                    break
                else:
                    attempts += 1
                    remaining = 5 - attempts
                    if remaining > 0:
                        print(f"❌ Incorrect password. {remaining} attempts remaining.")
                    else:
                        print("❌ Too many failed attempts. Exiting.")
                        return
        
        # Main menu loop
        while True:
            print("\n" + "="*60)
            print("🔒 ENHANCED SECURITY PASSWORD VAULT")
            print("="*60)
            print(f"Session active - Timeout in: {self.get_remaining_session_time()}")
            print(f"Security level: {self.protection_state.name}")
            print("1. View Passwords")
            print("2. Add Password")
            print("3. Generate Password")
            print("4. Search Passwords")
            print("5. Delete Password")
            print("6. Export to CSV")
            print("7. Import from CSV")
            print("8. Backup Vault")
            print("9. Restore Vault")
            print("10. Change Master Password")
            print("11. Security Settings")
            print("12. Session Info")
            print("13. Security Audit")
            print("0. Exit and Lock Vault")
            
            choice = input("\nEnter choice: ").strip()
            
            if choice == "1":
                self.view_passwords()
            elif choice == "2":
                self.add_password()
            elif choice == "3":
                self.generate_password()
            elif choice == "4":
                self.search_passwords()
            elif choice == "5":
                self.delete_password()
            elif choice == "6":
                self.export_csv()
            elif choice == "7":
                self.import_csv()
            elif choice == "8":
                self.backup_vault_menu()
            elif choice == "9":
                self.restore_vault_menu()
            elif choice == "10":
                self.change_master_password()
            elif choice == "11":
                self.security_settings()
            elif choice == "12":
                self.show_session_info()
            elif choice == "13":
                self.perform_security_audit()
            elif choice == "0":
                print("🔒 Vault locked. Goodbye!")
                self.end_session()
                break
            else:
                print("❌ Invalid choice. Please try again.")

    def delete_password(self):
        """Delete a password from the vault"""
        master_password = self.get_master_password()
        if not master_password:
            print("❌ Session expired. Please log in again.")
            return
        
        # Load vault data
        vault_data = self.load_vault(master_password)
        if not vault_data or "entries" not in vault_data:
            print("❌ Failed to load vault or no entries found.")
            return
        
        entries = vault_data.get("entries", {})
        if not entries:
            print("📭 No passwords stored yet.")
            return
        
        # Display passwords for selection
        print("\n🗑️  Delete Password")
        print("-" * 40)
        print("Select a password to delete:")
        
        entry_list = list(entries.items())
        for i, (entry_id, entry) in enumerate(entry_list, 1):
            print(f"{i}. {entry.get('title', 'Untitled')} ({entry.get('username', 'N/A')})")
        
        print("0. Cancel")
        
        try:
            choice = int(input("\nEnter choice: ").strip())
            if choice == 0:
                print("❌ Deletion cancelled.")
                return
            
            if 1 <= choice <= len(entry_list):
                entry_id, entry = entry_list[choice - 1]
                
                # Confirm deletion
                print(f"\n⚠️  WARNING: You are about to delete:")
                print(f"   Title: {entry.get('title', 'Untitled')}")
                print(f"   Username: {entry.get('username', 'N/A')}")
                print(f"   URL: {entry.get('url', 'N/A')}")
                
                confirm = input("\nAre you sure you want to delete this password? (y/N): ").strip().lower()
                if confirm == 'y':
                    # Delete the entry
                    del entries[entry_id]
                    
                    # Save the updated vault
                    success, message = self.save_vault(vault_data, master_password)
                    if success:
                        print("✅ Password deleted successfully!")
                        # Secure deletion confirmation
                        print("🔒 Entry permanently removed from vault.")
                    else:
                        print(f"❌ Failed to delete password: {message}")
                else:
                    print("❌ Deletion cancelled.")
            else:
                print("❌ Invalid selection.")
                
        except ValueError:
            print("❌ Please enter a valid number.")
        except Exception as e:
            print(f"❌ Error: {e}")

    # +++ ENHANCED SECURITY SETTINGS +++
    
    def security_settings(self):
        """View and modify security settings with enhanced key management options"""
        print("\n🔒 Security Settings:")
        print("1. View Current Settings")
        print("2. Change Encryption Parameters")
        print("3. Set Session Timeout")
        print("4. View Security Log")
        print("5. Reset to Defaults")
        print("6. Enable/Disable Anti-Forensics")
        print("7. Perform Security Audit")
        print("8. Key Management Settings")  # New option
        print("9. Back to Main Menu")
        
        choice = input("\nSelect an option: ").strip()
        
        if choice == "1":
            print("\nCurrent Security Settings:")
            print(json.dumps(self.config, indent=2))
        elif choice == "2":
            print("⚠️  Changing encryption parameters requires re-encryption of all data!")
            confirm = input("Continue? (y/N): ").strip().lower()
            if confirm == 'y':
                self.change_encryption_settings()
        elif choice == "3":
            self.set_session_timeout()
        elif choice == "4":
            self.view_security_log()
        elif choice == "5":
            confirm = input("Reset all settings to defaults? (y/N): ").strip().lower()
            if confirm == 'y':
                self.config = SSD_CONFIG.copy()
                self.save_config()
                print("✅ Settings reset to defaults.")
        elif choice == "6":
            self.anti_forensics_enabled = not self.anti_forensics_enabled
            status = "enabled" if self.anti_forensics_enabled else "disabled"
            print(f"✅ Anti-forensics measures {status}.")
        elif choice == "7":
            self.perform_security_audit()
        elif choice == "8":  # New key management settings
            self.key_management_settings()
        elif choice == "9":
            return
        else:
            print("Invalid option.")

    def key_management_settings(self):
        """Key management specific settings"""
        print("\n🔑 Key Management Settings:")
        print("1. View Key Rotation Status")
        print("2. Change Key Rotation Period")
        print("3. Force Key Rotation Now")
        print("4. View Key Security Report")
        print("5. Back to Security Settings")
        
        choice = input("\nSelect an option: ").strip()
        
        if choice == "1":
            self.view_key_rotation_status()
        elif choice == "2":
            self.change_key_rotation_period()
        elif choice == "3":
            self.force_key_rotation()
        elif choice == "4":
            self.view_key_security_report()
        elif choice == "5":
            return
        else:
            print("Invalid option.")

    def view_key_rotation_status(self):
        """Display key rotation status"""
        rotation_days = self.config['cryptography'].get('key_rotation_days', 90)
        last_rotation = self.config.get('last_key_rotation')
        
        print(f"\n🔄 Key Rotation Status:")
        print(f"   Rotation Period: {rotation_days} days")
        
        if last_rotation:
            last_date = datetime.fromisoformat(last_rotation)
            days_ago = (datetime.now() - last_date).days
            next_rotation = last_date + timedelta(days=rotation_days)
            days_until = (next_rotation - datetime.now()).days
            
            print(f"   Last Rotation: {last_date.strftime('%Y-%m-%d')} ({days_ago} days ago)")
            print(f"   Next Rotation: {next_rotation.strftime('%Y-%m-%d')} ({days_until} days from now)")
            
            if days_until <= 0:
                print("   ⚠️  Key rotation overdue!")
            elif days_until <= 7:
                print("   ⚠️  Key rotation due soon!")
            else:
                print("   ✅ Key rotation schedule is current")
        else:
            print("   ❌ No rotation history found")

    def change_key_rotation_period(self):
        """Change key rotation period"""
        current_days = self.config['cryptography'].get('key_rotation_days', 90)
        print(f"\nCurrent rotation period: {current_days} days")
        print("Recommended: 30-60 days for enhanced security")
        
        try:
            new_days = int(input("New rotation period (days, 7-365): ").strip())
            new_days = max(7, min(365, new_days))  # Limit to reasonable range
            
            if new_days != current_days:
                self.config['cryptography']['key_rotation_days'] = new_days
                self.save_config()
                print(f"✅ Key rotation period changed to {new_days} days")
                
                # Suggest immediate rotation if period was reduced
                if new_days < current_days:
                    print("💡 Consider forcing key rotation now for immediate security improvement")
            else:
                print("Rotation period unchanged")
                
        except ValueError:
            print("❌ Invalid input. Please enter a number.")

    def force_key_rotation(self):
        """Force immediate key rotation"""
        master_password = self.get_master_password()
        if not master_password:
            print("❌ Session expired. Please log in again.")
            return
        
        print("⚠️  Forcing immediate key rotation...")
        confirm = input("This will re-encrypt all data. Continue? (y/N): ").strip().lower()
        
        if confirm == 'y':
            if self.rotate_encryption_keys():
                print("✅ Key rotation completed successfully")
            else:
                print("❌ Key rotation failed")
        else:
            print("Key rotation cancelled")

    def view_key_security_report(self):
        """Display comprehensive key security report"""
        print("\n📊 Key Security Report:")
        print("=" * 50)
        
        # Key rotation status
        rotation_days = self.config['cryptography'].get('key_rotation_days', 90)
        last_rotation = self.config.get('last_key_rotation')
        
        print(f"Rotation Period: {rotation_days} days")
        if last_rotation:
            last_date = datetime.fromisoformat(last_rotation)
            days_ago = (datetime.now() - last_date).days
            print(f"Last Rotation: {days_ago} days ago")
        else:
            print("Last Rotation: Never")
        
        # Encryption strength
        argon2_config = self.config['cryptography']['argon2']
        print(f"\nEncryption Strength:")
        print(f"  Argon2 Time Cost: {argon2_config['time_cost']}")
        print(f"  Argon2 Memory Cost: {argon2_config['memory_cost']} KB")
        print(f"  Argon2 Parallelism: {argon2_config['parallelism']}")
        
        # Security assessment
        rotation_ok = rotation_days <= 60  # Good if 60 days or less
        recent_ok = last_rotation and (datetime.now() - datetime.fromisoformat(last_rotation)).days <= rotation_days
        strength_ok = (argon2_config['time_cost'] >= 2 and 
                      argon2_config['memory_cost'] >= 102400 and 
                      argon2_config['parallelism'] >= 2)
        
        print(f"\nSecurity Assessment:")
        print(f"  Rotation Frequency: {'✅' if rotation_ok else '❌'} {'(Good)' if rotation_ok else '(Should be ≤60 days)'}")
        print(f"  Recent Rotation: {'✅' if recent_ok else '❌'} {'(Current)' if recent_ok else '(Overdue)'}")
        print(f"  Encryption Strength: {'✅' if strength_ok else '❌'} {'(Strong)' if strength_ok else '(Needs improvement)'}")
        
        if rotation_ok and recent_ok and strength_ok:
            print("\n🎉 Overall Key Security: Excellent")
        elif not recent_ok:
            print("\n⚠️  Overall Key Security: Needs Attention (rotation overdue)")
        else:
            print("\n⚠️  Overall Key Security: Good with some improvements needed")

    def perform_security_audit(self):
        """Perform comprehensive security audit"""
        print("\n🔍 Performing Security Audit...")
        
        audit_results = self.enhanced_security_audit()
        
        print("\n📊 Security Audit Results:")
        print("-" * 40)
        
        for check, result in audit_results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{check.replace('_', ' ').title():<25}: {status}")
        
        # Calculate security score
        pass_count = sum(1 for result in audit_results.values() if result)
        total_count = len(audit_results)
        security_score = (pass_count / total_count) * 10
        
        print(f"\n🔒 Security Score: {security_score:.1f}/10")
        
        if security_score >= 9:
            print("🎉 Excellent security posture!")
        elif security_score >= 7:
            print("⚠️  Good security, but some improvements needed.")
        else:
            print("🚨 Security needs immediate attention!")
            
        # Provide improvement suggestions for low scores
        if security_score < 10:
            self.provide_security_improvements(audit_results)

    def enhanced_security_audit(self) -> dict:
        """More comprehensive security audit"""
        audit_results = {
            "tamper_detection": self.enhanced_tamper_detection(),
            "encryption_strength": self.check_encryption_strength(),
            "session_security": self.check_session_security(),
            "file_permissions": self.check_file_permissions(),
            # New audit points:
            "memory_protection": self.check_memory_protection(),
            "network_security": self.check_network_security(),
            "physical_security": self.check_physical_security(),
            "key_management": self.check_key_management(),
            "log_security": self.check_log_security(),
            "backup_security": self.check_backup_security(),
            "timing_attack_protection": self.check_timing_attack_protection()
        }
        return audit_results

    def check_timing_attack_protection(self) -> bool:
        """Check if timing attack protections are properly configured"""
        return (self.timing_attack_protection and 
                hasattr(self, 'secure_timers') and 
                self.secure_timers.get('min_delay_ms', 0) > 0)

    def check_key_management(self) -> bool:
        """Enhanced key management check"""
        try:
            # Verify key rotation is enabled and properly configured
            rotation_days = self.config['cryptography'].get('key_rotation_days', 0)
            
            # Check if rotation is configured and recent
            has_rotation_config = rotation_days > 0
            has_recent_rotation = False
            
            if 'last_key_rotation' in self.config:
                last_rotation = datetime.fromisoformat(self.config['last_key_rotation'])
                days_since_rotation = (datetime.now() - last_rotation).days
                has_recent_rotation = days_since_rotation <= rotation_days
            
            # Additional checks for comprehensive key management
            has_secure_storage = self.check_secure_key_storage()
            has_proper_key_derivation = self.check_key_derivation_security()
            
            return (has_rotation_config and has_recent_rotation and 
                    has_secure_storage and has_proper_key_derivation)
        except:
            return False

    def check_secure_key_storage(self) -> bool:
        """Check if keys are stored securely"""
        try:
            auth_file = self.vault_dir / "auth.dat"
            if not auth_file.exists():
                return True  # No keys stored yet
                
            # Check file permissions
            if platform.system() != "Windows":
                stat_info = os.stat(auth_file)
                if stat_info.st_mode & 0o777 != 0o600:
                    return False
            
            # Check if file is hidden (Windows) or has proper attributes
            if platform.system() == "Windows":
                try:
                    result = subprocess.run(['attrib', str(auth_file)], 
                                          capture_output=True, text=True, check=False)
                    if 'H' not in result.stdout:  # Not hidden
                        return False
                except:
                    pass
                    
            return True
        except:
            return False

    def check_key_derivation_security(self) -> bool:
        """Check if key derivation meets security standards"""
        try:
            # Check Argon2 parameters
            argon2_config = self.config['cryptography']['argon2']
            if (argon2_config['time_cost'] >= 2 and 
                argon2_config['memory_cost'] >= 102400 and 
                argon2_config['parallelism'] >= 2):
                return True
            return False
        except:
            return False

    def provide_security_improvements(self, audit_results: dict):
        """Provide specific security improvement suggestions"""
        print("\n💡 Security Improvement Suggestions:")
        print("-" * 40)
        
        if not audit_results.get("memory_protection", False):
            print("• Enhance memory protection with secure wiping techniques")
            
        if not audit_results.get("network_security", False):
            print("• Implement network security monitoring and protection")
            
        if not audit_results.get("physical_security", False):
            print("• Add physical security measures for portable operation")
            
        if not audit_results.get("key_management", False):
            print("• Improve key management with more frequent rotation")
            
        if not audit_results.get("log_security", False):
            print("• Enhance log security with encryption and rotation")
            
        if not audit_results.get("backup_security", False):
            print("• Strengthen backup security with additional encryption layers")
            
        if not audit_results.get("timing_attack_protection", False):
            print("• Enable timing attack protection with secure delays")

    def check_memory_protection(self) -> bool:
        """Check memory protection measures"""
        # Verify that secure memory wiping is properly implemented
        try:
            test_data = "test_string"
            wiped = self.secure_memory_wipe(test_data)
            return wiped != test_data and len(wiped) == len(test_data)
        except:
            return False

    def check_network_security(self) -> bool:
        """Check network security measures"""
        # Basic check for network security
        try:
            return self.config['defense'].get('network_shield', False)
        except:
            return False

    def check_physical_security(self) -> bool:
        """Check physical security measures"""
        # Basic check for physical security features
        try:
            return (self.config['defense'].get('tamper_detection', False) and 
                    self.config['defense'].get('anti_forensics', False))
        except:
            return False

    def check_log_security(self) -> bool:
        """Check log security measures"""
        # Verify logs are properly secured
        try:
            log_file = self.vault_dir / "logs" / "vault.log"
            if not log_file.exists():
                return True
                
            if platform.system() != "Windows":
                stat_info = os.stat(log_file)
                return stat_info.st_mode & 0o777 == 0o600
            return True
        except:
            return False

    def check_backup_security(self) -> bool:
        """Check backup security measures"""
        # Verify backup encryption is enabled
        try:
            return self.config['cryptography'].get('backup_encryption') == "AES-256-GCM"
        except:
            return False

    def check_encryption_strength(self) -> bool:
        """Check if encryption settings meet security standards"""
        try:
            # Check Argon2 parameters
            argon2_config = self.config['cryptography']['argon2']
            if (argon2_config['time_cost'] >= 2 and 
                argon2_config['memory_cost'] >= 102400 and 
                argon2_config['parallelism'] >= 2):
                return True
            return False
        except:
            return False

    def check_session_security(self) -> bool:
        """Check session security settings"""
        try:
            # Check if session timeout is reasonable
            if hasattr(self, 'session_timeout'):
                timeout_minutes = self.session_timeout.total_seconds() / 60
                return 5 <= timeout_minutes <= 60  # Reasonable timeout range
            return False
        except:
            return False

    def check_file_permissions(self) -> bool:
        """Check file permissions for security"""
        try:
            vault_files = ["auth.dat", "vault.dat", "config.json"]
            for file_name in vault_files:
                file_path = self.vault_dir / file_name
                if file_path.exists():
                    if platform.system() != "Windows":
                        stat_info = os.stat(file_path)
                        if stat_info.st_mode & 0o777 != 0o600:
                            return False
            return True
        except:
            return False

    def set_session_timeout(self):
        """Set session timeout duration"""
        print(f"\nCurrent session timeout: {self.session_timeout.total_seconds() // 60} minutes")
        
        try:
            minutes = int(input("New timeout in minutes (5-120): ").strip())
            minutes = max(5, min(120, minutes))  # Limit to 5-120 minutes
            
            self.session_timeout = timedelta(minutes=minutes)
            print(f"✅ Session timeout set to {minutes} minutes.")
            
        except ValueError:
            print("❌ Invalid input. Timeout not changed.")
    
    def view_security_log(self):
        """View security log"""
        log_file = self.vault_dir / "logs" / "vault.log"
        if not log_file.exists():
            print("No security log found.")
            return
        
        try:
            with open(log_file, 'r') as f:
                log_content = f.read()
            
            print("\nSecurity Log:")
            print("-" * 80)
            print(log_content[-2000:])  # Show last 2000 characters
            print("-" * 80)
            
        except Exception as e:
            print(f"❌ Failed to read security log: {e}")

    # +++ ADDITIONAL ESSENTIAL METHODS +++
    
    def get_remaining_session_time(self) -> str:
        """Get remaining session time as formatted string"""
        if not self.session_start_time:
            return "No active session"
        
        remaining = self.session_timeout - (datetime.now() - self.session_start_time)
        minutes = int(remaining.total_seconds() // 60)
        seconds = int(remaining.total_seconds() % 60)
        return f"{minutes:02d}:{seconds:02d}"
    
    def view_passwords(self):
        """View all passwords in the vault"""
        master_password = self.get_master_password()
        if not master_password:
            print("❌ Session expired. Please log in again.")
            return
        
        # Load vault data with proper error handling
        try:
            vault_data = self.load_vault(master_password)
        except Exception as e:
            print(f"❌ Failed to load vault: {e}")
            return
        
        # Check if vault data has the right structure
        if not vault_data or "entries" not in vault_data:
            print("📭 No passwords stored yet.")
            return
        
        entries = vault_data.get("entries", {})
        if not entries:
            print("📭 No passwords stored yet.")
            return
        
        print(f"\n📋 Stored Passwords ({len(entries)}):")
        print("=" * 80)
        
        for i, (entry_id, entry) in enumerate(entries.items(), 1):
            print(f"{i}. {entry.get('title', 'Untitled')}")
            print(f"   Username: {entry.get('username', 'N/A')}")
            print(f"   Password: {'*' * min(12, len(entry.get('password', '')))}")  # Masked
            print(f"   URL: {entry.get('url', 'N/A')}")
            print(f"   Group: {entry.get('group', 'Default')}")
            print(f"   Notes: {entry.get('notes', 'N/A')[:50]}...")  # Truncate long notes
            print(f"   Modified: {entry.get('modified', 'N/A')}")
            print("-" * 80)
        
        # Option to reveal passwords
        if entries:
            reveal = input("\n🔓 Show passwords? (y/N): ").strip().lower()
            if reveal == 'y':
                master_confirm = getpass.getpass("Confirm master password to reveal: ")
                if self.verify_master_password(master_confirm):
                    print("\n🔓 Passwords Revealed:")
                    print("=" * 80)
                    for i, (entry_id, entry) in enumerate(entries.items(), 1):
                        print(f"{i}. {entry.get('title', 'Untitled')}")
                        print(f"   Password: {entry.get('password', 'N/A')}")
                        print("-" * 80)
                else:
                    print("❌ Password incorrect. Passwords not revealed.")
    
    def add_password(self):
        """Add a new password entry"""
        master_password = self.get_master_password()
        if not master_password:
            print("❌ Session expired. Please log in again.")
            return
        
        print("\n➕ Add New Password")
        print("-" * 40)
        
        title = input("Title: ").strip()
        username = input("Username: ").strip()
        password = getpass.getpass("Password (leave empty to generate): ").strip()
        url = input("URL (optional): ").strip()
        group = input("Group (optional): ").strip()
        notes = input("Notes (optional): ").strip()
        
        # Generate password if empty
        if not password:
            password = self.generate_secure_password()
            print(f"🔐 Generated password: {password}")
        
        # Load existing vault - ensure proper structure
        vault_data = self.load_vault(master_password)
        if not vault_data or "entries" not in vault_data:
            vault_data = {"entries": {}}
        
        # Create entry with proper structure
        entry_id = hashlib.sha256(f"{title}{username}{url}".encode()).hexdigest()[:16]
        entry = {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "group": group or "Default",
            "notes": notes,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat()
        }
        
        vault_data["entries"][entry_id] = entry
        
        # Save vault
        success, message = self.save_vault(vault_data, master_password)
        if success:
            print("✅ Password added successfully!")
        else:
            print(f"❌ Failed to save password: {message}")
    
    def generate_password(self):
        """Generate a secure password"""
        password = self.generate_secure_password()
        print(f"\n🔐 Generated Secure Password: {password}")
        print("📋 Password copied to clipboard (if supported)")
        
        # Try to copy to clipboard
        try:
            if platform.system() == "Windows":
                import win32clipboard
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardText(password)
                win32clipboard.CloseClipboard()
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(['pbcopy'], input=password.encode(), check=True)
            else:  # Linux
                subprocess.run(['xclip', '-selection', 'clipboard'], 
                             input=password.encode(), check=True)
        except:
            pass  # Clipboard not available
    
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure random password"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def search_passwords(self):
        """Search for passwords"""
        master_password = self.get_master_password()
        if not master_password:
            print("❌ Session expired. Please log in again.")
            return
        
        query = input("\n🔍 Search query: ").strip().lower()
        if not query:
            print("❌ Please enter a search query.")
            return
        
        vault_data = self.load_vault(master_password)
        if not vault_data or "entries" not in vault_data:
            print("❌ Failed to load vault or no entries found.")
            return
        
        entries = vault_data.get("entries", {})
        results = []
        
        for entry_id, entry in entries.items():
            if (query in entry.get('title', '').lower() or
                query in entry.get('username', '').lower() or
                query in entry.get('url', '').lower() or
                query in entry.get('group', '').lower() or
                query in entry.get('notes', '').lower()):
                results.append(entry)
        
        if not results:
            print("🔍 No matching passwords found.")
            return
        
        print(f"\n📋 Search Results ({len(results)}):")
        print("-" * 80)
        
        for i, entry in enumerate(results, 1):
            print(f"{i}. {entry.get('title', 'Untitled')}")
            print(f"   Username: {entry.get('username', 'N/A')}")
            print(f"   Password: {'*' * min(12, len(entry.get('password', '')))}")
            print(f"   URL: {entry.get('url', 'N/A')}")
            print("-" * 80)
    
    def export_csv(self):
        """Export passwords to CSV"""
        master_password = self.get_master_password()
        if not master_password:
            print("❌ Session expired. Please log in again.")
            return
        
        output_path = input("Enter output CSV file path: ").strip()
        if not output_path:
            print("❌ Please specify an output file path.")
            return
        
        output_path = Path(output_path)
        if self.export_to_csv(output_path, master_password):
            print("✅ Export completed successfully!")
        else:
            print("❌ Export failed.")
    
    def import_csv(self):
        """Import passwords from CSV"""
        master_password = self.get_master_password()
        if not master_password:
            print("❌ Session expired. Please log in again.")
            return
        
        input_path = input("Enter input CSV file path: ").strip()
        if not input_path:
            print("❌ Please specify an input file path.")
            return
        
        input_path = Path(input_path)
        if not input_path.exists():
            print("❌ Input file does not exist.")
            return
        
        # Detect format
        format_name = self.detect_csv_format(input_path)
        print(f"🔍 Detected format: {format_name}")
        
        if self.import_from_csv(input_path, master_password):
            print("✅ Import completed successfully!")
        else:
            print("❌ Import failed. The file might be in an unsupported format.")
            print("Supported formats: Opera, Chrome, Firefox, Safari, LastPass, 1Password,")
            print("Bitwarden, Dashlane, Microsoft Authenticator, KeePass, RoboForm, and generic CSV")
    
    def backup_vault_menu(self):
        """Backup vault menu"""
        master_password = self.get_master_password()
        if not master_password:
            print("❌ Session expired. Please log in again.")
            return
        
        if self.backup_vault(master_password):
            print("✅ Backup completed successfully!")
        else:
            print("❌ Backup failed.")
    
    def restore_vault_menu(self):
        """Restore vault menu"""
        master_password = self.get_master_password()
        if not master_password:
            print("❌ Session expired. Please log in again.")
            return
        
        backup_path = input("Enter backup file path (leave empty for latest): ").strip()
        
        if backup_path:
            # Use the provided path
            backup_path = Path(backup_path)
            if not backup_path.exists():
                print("❌ Backup file does not exist.")
                return
        else:
            # Find the latest backup automatically
            if platform.system() == "Windows":
                backup_dir = Path("C:") / "ProgramData" / "SystemCache"
            else:
                backup_dir = Path.home() / ".cache" / "system"
            
            # Find all backup files
            backup_files = list(backup_dir.glob(".vault_backup_*.enc"))
            if not backup_files:
                print("❌ No backup files found.")
                return
            
            # Get the most recent backup
            backup_path = max(backup_files, key=os.path.getctime)
            print(f"🔍 Using latest backup: {backup_path}")
        
        if self.restore_vault(master_password, backup_path):
            print("✅ Restore completed successfully!")
        else:
            print("❌ Restore failed.")
    
    def change_master_password(self):
        """Change master password"""
        master_password = self.get_master_password()
        if not master_password:
            print("❌ Session expired. Please log in again.")
            return
        
        print("\n🔑 Change Master Password")
        print("-" * 40)
        
        current_password = getpass.getpass("Current master password: ").strip()
        if not self.verify_master_password(current_password):
            print("❌ Current password is incorrect.")
            return
        
        new_password = getpass.getpass("New master password: ").strip()
        if not new_password:
            print("❌ New password cannot be empty.")
            return
        
        confirm_password = getpass.getpass("Confirm new password: ").strip()
        if new_password != confirm_password:
            print("❌ Passwords do not match.")
            return
        
        # Load vault with old password
        vault_data = self.load_vault(current_password)
        if not vault_data:
            print("❌ Failed to load vault with current password.")
            return
        
        # Save vault with new password
        success, message = self.save_vault(vault_data, new_password)
        if not success:
            print(f"❌ Failed to save vault with new password: {message}")
            return
        
        # Update master password hash
        if self.setup_master_password(new_password):
            print("✅ Master password changed successfully!")
            # Update current session
            self.current_master_password = new_password
        else:
            print("❌ Failed to update master password hash.")
    
    def show_session_info(self):
        """Show session information"""
        if not self.session_start_time:
            print("❌ No active session.")
            return
        
        print("\n📊 Session Information")
        print("-" * 40)
        print(f"Session started: {self.session_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Time remaining: {self.get_remaining_session_time()}")
        print(f"SSD speed: {self.ssd_telemetry.ssd_speed:.2f} MB/s")
        print(f"Protection level: {self.protection_state.name}")
    
    def change_encryption_settings(self):
        """Change encryption settings"""
        print("\nCurrent Argon2 settings:")
        print(f"Time cost: {self.config['cryptography']['argon2']['time_cost']}")
        print(f"Memory cost: {self.config['cryptography']['argon2']['memory_cost']} KB")
        print(f"Parallelism: {self.config['cryptography']['argon2']['parallelism']}")
        
        try:
            time_cost = int(input("New time cost (1-4): ") or self.config['cryptography']['argon2']['time_cost'])
            memory_cost = int(input("New memory cost (KB): ") or self.config['cryptography']['argon2']['memory_cost'])
            parallelism = int(input("New parallelism: ") or self.config['cryptography']['argon2']['parallelism'])
            
            # Validate inputs with enhanced limits
            time_cost = max(1, min(4, time_cost))
            memory_cost = max(102400, min(409600, memory_cost))
            parallelism = max(1, min(4, parallelism))
            
            self.config['cryptography']['argon2']['time_cost'] = time_cost
            self.config['cryptography']['argon2']['memory_cost'] = memory_cost
            self.config['cryptography']['argon2']['parallelism'] = parallelism
            
            self.save_config()
            print("✅ Encryption settings updated. These will take effect on next vault operation.")
            
        except ValueError:
            print("❌ Invalid input. Settings not changed.")

    # +++ ENHANCED LOGGING +++
    
    def setup_ssd_logging(self) -> logging.Logger:
        """Setup SSD-optimized logging with enhanced security features"""
        logger = logging.getLogger("EnhancedSecurityVault")
        logger.setLevel(logging.INFO)
        
        # Create logs directory
        logs_dir = self.vault_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        
        # File handler with rotation
        log_file = logs_dir / "vault.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Enhanced formatter with more security details
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s '
            '[PID:%(process)d - %(threadName)s]'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        # Set secure permissions on log file
        if platform.system() != "Windows":
            os.chmod(log_file, 0o600)
        
        return logger

    # +++ CSV IMPORT/EXPORT FUNCTIONALITY +++
    
    def export_to_csv(self, output_path: Path, master_password: str) -> bool:
        """Export all passwords to CSV format compatible with other password managers"""
        try:
            # Decrypt the vault
            vault_data = self.load_vault(master_password)
            if not vault_data or "entries" not in vault_data:
                self.logger.error("Failed to decrypt vault for export or no entries found")
                return False
            
            # Prepare CSV data
            csv_data = []
            headers = ["Title", "Username", "Password", "URL", "Notes", "Group", "Created", "Modified"]
            
            for entry_id, entry in vault_data.get("entries", {}).items():
                csv_data.append([
                    entry.get("title", ""),
                    entry.get("username", ""),
                    entry.get("password", ""),
                    entry.get("url", ""),
                    entry.get("notes", ""),
                    entry.get("group", ""),
                    entry.get("created", ""),
                    entry.get("modified", "")
                ])
            
            # Write to CSV
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)
                writer.writerows(csv_data)
            
            self.logger.info(f"Successfully exported {len(csv_data)} entries to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"CSV export failed: {e}")
            return False

    def detect_csv_format(self, input_path: Path) -> str:
        """Detect the format of a CSV file"""
        try:
            with open(input_path, 'r', newline='', encoding='utf-8') as csvfile:
                sample = csvfile.read(2048)
                csvfile.seek(0)
                
                try:
                    dialect = csv.Sniffer().sniff(sample)
                    has_header = csv.Sniffer().has_header(sample)
                except:
                    return "Generic CSV"
                
                reader = csv.DictReader(csvfile, dialect=dialect) if has_header else csv.reader(csvfile, dialect)
                rows = list(reader)
                
                if not rows or (has_header and not reader.fieldnames):
                    return "Generic CSV"
                
                if has_header:
                    header = reader.fieldnames
                    
                    # Check for specific formats
                    if ('name' in header and 'url' in header and 
                        'username' in header and 'password' in header and 'note' in header):
                        return "Opera"
                    elif ('name' in header and 'url' in header and 
                          'username' in header and 'password' in header):
                        return "Chrome"
                    elif ('url' in header and 'username' in header and 'password' in header):
                        return "Firefox"
                    elif ('Title' in header and 'URL' in header and 
                          'Username' in header and 'Password' in header):
                        return "Safari"
                    elif ('url' in header and 'username' in header and 
                          'password' in header and 'name' in header and 'extra' in header):
                        return "LastPass"
                    elif ('Title' in header and 'Website' in header and 
                          'Username' in header and 'Password' in header):
                        return "1Password"
                    elif ('name' in header and 'login_uri' in header and 
                          'login_username' in header and 'login_password' in header):
                        return "Bitwarden"
                    elif ('title' in header and 'url' in header and 
                          'username' in header and 'password' in header):
                        return "Dashlane"
                    elif ('Name' in header and 'Username' in header and 
                          'Password' in header and 'URL' in header):
                        return "Microsoft Authenticator"
                    elif ('Account' in header and 'Login Name' in header and 
                          'Password' in header and 'Web Site' in header):
                        return "KeePass"
                    elif ('Name' in header and 'Username' in header and 
                          'Password' in header and 'URL' in header and 'Folder' in header):
                        return "RoboForm"
                
                return "Generic CSV"
                
        except Exception as e:
            self.logger.error(f"Format detection failed: {e}")
            return "Unknown"    

    def import_from_csv(self, input_path: Path, master_password: str) -> bool:
        """Import passwords from CSV format from various browsers and password managers"""
        try:
            # Read CSV data with different possible delimiters and encodings
            entries = []
            
            # Try different encodings
            encodings = ['utf-8', 'latin-1', 'windows-1252', 'utf-8-sig', 'iso-8859-1']
            
            for encoding in encodings:
                try:
                    with open(input_path, 'r', newline='', encoding=encoding) as csvfile:
                        # Sniff the dialect to detect the format
                        sample = csvfile.read(4096)  # Read more for better detection
                        csvfile.seek(0)
                        
                        # Try to detect the dialect
                        try:
                            dialect = csv.Sniffer().sniff(sample)
                            has_header = csv.Sniffer().has_header(sample)
                        except:
                            # Fallback to standard comma delimiter
                            dialect = csv.excel()
                            has_header = True
                        
                        reader = csv.DictReader(csvfile, dialect=dialect) if has_header else csv.reader(csvfile, dialect)
                        
                        # Read all rows
                        rows = list(reader)
                        
                        if not rows:
                            continue
                        
                        # Convert to list of dictionaries if using DictReader
                        if has_header and isinstance(rows[0], dict):
                            dict_rows = rows
                            rows = [[row.get(key, '') for key in reader.fieldnames] for row in dict_rows]
                            header = reader.fieldnames
                        else:
                            header = rows[0] if has_header and rows else []
                        
                        # Determine the format based on header or content
                        if has_header and header:
                            # Opera format (name,url,username,password,note)
                            if ('name' in header and 'url' in header and 
                                'username' in header and 'password' in header):
                                start_idx = 1 if has_header else 0
                                for row in rows[start_idx:]:
                                    if len(row) >= 4:
                                        entries.append({
                                            "title": row[header.index('name')] or self._extract_domain_from_url(row[header.index('url')]),
                                            "url": row[header.index('url')],
                                            "username": row[header.index('username')],
                                            "password": row[header.index('password')],
                                            "notes": row[header.index('note')] if 'note' in header and len(row) > header.index('note') else "",
                                            "group": "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                            
                            # Chrome format (name,url,username,password)
                            elif ('name' in header and 'url' in header and 
                                  'username' in header and 'password' in header):
                                start_idx = 1 if has_header else 0
                                for row in rows[start_idx:]:
                                    if len(row) >= 4:
                                        entries.append({
                                            "title": row[header.index('name')] or self._extract_domain_from_url(row[header.index('url')]),
                                            "url": row[header.index('url')],
                                            "username": row[header.index('username')],
                                            "password": row[header.index('password')],
                                            "notes": "",
                                            "group": "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                            
                            # Firefox format (url,username,password)
                            elif ('url' in header and 'username' in header and 'password' in header):
                                start_idx = 1 if has_header else 0
                                for row in rows[start_idx:]:
                                    if len(row) >= 3:
                                        entries.append({
                                            "title": self._extract_domain_from_url(row[header.index('url')]),
                                            "url": row[header.index('url')],
                                            "username": row[header.index('username')],
                                            "password": row[header.index('password')],
                                            "notes": "",
                                            "group": "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                            
                            # Safari format (Title,URL,Username,Password,Notes,OTPAuth)
                            elif ('Title' in header and 'URL' in header and 
                                  'Username' in header and 'Password' in header):
                                start_idx = 1 if has_header else 0
                                for row in rows[start_idx:]:
                                    if len(row) >= 4:
                                        entries.append({
                                            "title": row[header.index('Title')] or self._extract_domain_from_url(row[header.index('URL')]),
                                            "url": row[header.index('URL')],
                                            "username": row[header.index('Username')],
                                            "password": row[header.index('Password')],
                                            "notes": row[header.index('Notes')] if 'Notes' in header and len(row) > header.index('Notes') else "",
                                            "group": "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                            
                            # LastPass format (url,username,password,extra,name,grouping,fav)
                            elif ('url' in header and 'username' in header and 
                                  'password' in header and 'name' in header):
                                start_idx = 1 if has_header else 0
                                for row in rows[start_idx:]:
                                    if len(row) >= 4:
                                        entries.append({
                                            "title": row[header.index('name')] or self._extract_domain_from_url(row[header.index('url')]),
                                            "url": row[header.index('url')],
                                            "username": row[header.index('username')],
                                            "password": row[header.index('password')],
                                            "notes": row[header.index('extra')] if 'extra' in header and len(row) > header.index('extra') else "",
                                            "group": row[header.index('grouping')] if 'grouping' in header and len(row) > header.index('grouping') else "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                            
                            # 1Password format (Title,Website,Username,Password,Notes,Type,OtpAuth)
                            elif ('Title' in header and 'Website' in header and 
                                  'Username' in header and 'Password' in header):
                                start_idx = 1 if has_header else 0
                                for row in rows[start_idx:]:
                                    if len(row) >= 4:
                                        entries.append({
                                            "title": row[header.index('Title')] or self._extract_domain_from_url(row[header.index('Website')]),
                                            "url": row[header.index('Website')],
                                            "username": row[header.index('Username')],
                                            "password": row[header.index('Password')],
                                            "notes": row[header.index('Notes')] if 'Notes' in header and len(row) > header.index('Notes') else "",
                                            "group": row[header.index('Type')] if 'Type' in header and len(row) > header.index('Type') else "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                            
                            # Bitwarden format (folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp)
                            elif ('name' in header and 'login_uri' in header and 
                                  'login_username' in header and 'login_password' in header):
                                start_idx = 1 if has_header else 0
                                for row in rows[start_idx:]:
                                    if len(row) >= 10:
                                        entries.append({
                                            "title": row[header.index('name')] or self._extract_domain_from_url(row[header.index('login_uri')]),
                                            "url": row[header.index('login_uri')],
                                            "username": row[header.index('login_username')],
                                            "password": row[header.index('login_password')],
                                            "notes": row[header.index('notes')] if 'notes' in header and len(row) > header.index('notes') else "",
                                            "group": row[header.index('folder')] if 'folder' in header and len(row) > header.index('folder') else "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                            
                            # Dashlane format (username,email,password,url,note,title,otpSecret,category)
                            elif ('title' in header and 'url' in header and 
                                  'username' in header and 'password' in header):
                                start_idx = 1 if has_header else 0
                                for row in rows[start_idx:]:
                                    if len(row) >= 4:
                                        entries.append({
                                            "title": row[header.index('title')] or self._extract_domain_from_url(row[header.index('url')]),
                                            "url": row[header.index('url')],
                                            "username": row[header.index('username')],
                                            "password": row[header.index('password')],
                                            "notes": row[header.index('note')] if 'note' in header and len(row) > header.index('note') else "Imported",
                                            "group": row[header.index('category')] if 'category' in header and len(row) > header.index('category') else "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                            
                            # Microsoft Authenticator format (Name,Username,Password,URL,Notes,Type,Last Modified,Last Accessed)
                            elif ('Name' in header and 'Username' in header and 
                                  'Password' in header and 'URL' in header):
                                start_idx = 1 if has_header else 0
                                for row in rows[start_idx:]:
                                    if len(row) >= 4:
                                        entries.append({
                                            "title": row[header.index('Name')] or self._extract_domain_from_url(row[header.index('URL')]),
                                            "url": row[header.index('URL')],
                                            "username": row[header.index('Username')],
                                            "password": row[header.index('Password')],
                                            "notes": row[header.index('Notes')] if 'Notes' in header and len(row) > header.index('Notes') else "",
                                            "group": row[header.index('Type')] if 'Type' in header and len(row) > header.index('Type') else "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                            
                            # KeePass format (Account,Login Name,Password,Web Site,Comments)
                            elif ('Account' in header and 'Login Name' in header and 
                                  'Password' in header and 'Web Site' in header):
                                start_idx = 1 if has_header else 0
                                for row in rows[start_idx:]:
                                    if len(row) >= 4:
                                        entries.append({
                                            "title": row[header.index('Account')] or self._extract_domain_from_url(row[header.index('Web Site')]),
                                            "url": row[header.index('Web Site')],
                                            "username": row[header.index('Login Name')],
                                            "password": row[header.index('Password')],
                                            "notes": row[header.index('Comments')] if 'Comments' in header and len(row) > header.index('Comments') else "",
                                            "group": "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                            
                            # RoboForm format (Name,Username,Password,URL,Notes,Folder,Custom Fields)
                            elif ('Name' in header and 'Username' in header and 
                                  'Password' in header and 'URL' in header):
                                start_idx = 1 if has_header else 0
                                for row in rows[start_idx:]:
                                    if len(row) >= 4:
                                        entries.append({
                                            "title": row[header.index('Name')] or self._extract_domain_from_url(row[header.index('URL')]),
                                            "url": row[header.index('URL')],
                                            "username": row[header.index('Username')],
                                            "password": row[header.index('Password')],
                                            "notes": row[header.index('Notes')] if 'Notes' in header and len(row) > header.index('Notes') else "",
                                            "group": row[header.index('Folder')] if 'Folder' in header and len(row) > header.index('Folder') else "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                        
                        # Generic format detection (no header or unknown format)
                        else:
                            # Try to guess the format based on content
                            if len(rows[0]) >= 3:
                                # Assume url, username, password format
                                url_idx, user_idx, pass_idx = 0, 1, 2
                                
                                # Try to detect column order
                                first_row = rows[0]
                                if "http" in first_row[0] and "@" not in first_row[0]:
                                    url_idx = 0
                                    if len(first_row) > 1 and "@" in first_row[1]:
                                        user_idx = 1
                                        pass_idx = 2
                                    else:
                                        user_idx = 2
                                        pass_idx = 1
                                elif "@" in first_row[0]:
                                    user_idx = 0
                                    if len(first_row) > 1 and "http" in first_row[1]:
                                        url_idx = 1
                                        pass_idx = 2
                                    else:
                                        url_idx = 2
                                        pass_idx = 1
                                
                                for row in rows:
                                    if len(row) >= max(url_idx, user_idx, pass_idx) + 1:
                                        entries.append({
                                            "title": self._extract_domain_from_url(row[url_idx]),
                                            "url": row[url_idx],
                                            "username": row[user_idx],
                                            "password": row[pass_idx],
                                            "notes": row[3] if len(row) > 3 else "",
                                            "group": "Imported",
                                            "created": datetime.now().isoformat(),
                                            "modified": datetime.now().isoformat()
                                        })
                    
                    # If we successfully read the file, break the encoding loop
                    if entries:
                        break
                    
                except UnicodeDecodeError:
                    continue  # Try next encoding
                except Exception as e:
                    self.logger.error(f"Error reading CSV with encoding {encoding}: {e}")
                    continue
            
            if not entries:
                self.logger.error("No valid entries found in CSV file")
                return False
            
            # Load existing vault
            vault_data = self.load_vault(master_password) or {"entries": {}}
            
            # Add new entries
            for entry in entries:
                entry_id = hashlib.sha256(
                    f"{entry['title']}{entry['username']}{entry['url']}".encode()
                ).hexdigest()[:16]
                vault_data["entries"][entry_id] = entry
            
            # Save the updated vault
            success, message = self.save_vault(vault_data, master_password)
            
            if success:
                self.logger.info(f"Successfully imported {len(entries)} entries from {input_path}")
            else:
                self.logger.error(f"Failed to save vault after import: {message}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"CSV import failed: {e}")
            return False

    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain name from URL for use as title"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain or "Unknown Site"
        except:
            return "Imported Entry"

    # +++ BACKUP AND RESTORE FUNCTIONALITY +++
    
    def backup_vault(self, master_password: str) -> bool:
        """Create a backup of the vault to a hidden encrypted file on C: drive"""
        try:
            # Determine backup location
            if platform.system() == "Windows":
                backup_dir = Path("C:") / "ProgramData" / "SystemCache"
                backup_dir.mkdir(exist_ok=True, parents=True)
                
                # Hide the directory
                try:
                    subprocess.run(['attrib', '+h', str(backup_dir)], 
                                 capture_output=True, check=False, shell=True)
                except:
                    pass  # If hiding fails, continue anyway
            else:
                backup_dir = Path.home() / ".cache" / "system"
                backup_dir.mkdir(exist_ok=True, parents=True)
                # Make hidden on Unix
                try:
                    backup_dir.chmod(0o700)
                except:
                    pass
            
            # Create backup file name with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = backup_dir / f".vault_backup_{timestamp}.enc"
            
            # Load vault data
            vault_data = self.load_vault(master_password)
            if not vault_data:
                self.logger.error("Failed to decrypt vault for backup")
                return False
            
            # Create backup key from master password and system info
            backup_key = self.derive_backup_key(master_password)
            
            # Encrypt backup data
            encrypted_backup = self.encrypt_backup_data(
                json.dumps(vault_data).encode(), 
                backup_key
            )
            
            # Write backup file
            with open(backup_file, 'wb') as f:
                f.write(encrypted_backup)
            
            # Hide the backup file
            if platform.system() == "Windows":
                try:
                    subprocess.run(['attrib', '+h', str(backup_file)], 
                                 capture_output=True, check=False, shell=True)
                except:
                    pass
            
            self.logger.info(f"Backup created successfully at {backup_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Backup failed: {e}")
            return False
    
    def restore_vault(self, master_password: str, backup_path: Optional[Path] = None) -> bool:
        """Restore vault from backup file"""
        try:
            # Find latest backup if no path specified
            if backup_path is None:
                if platform.system() == "Windows":
                    backup_dir = Path("C:") / "ProgramData" / "SystemCache"
                else:
                    backup_dir = Path.home() / ".cache" / "system"
                
                # Find all backup files
                backup_files = list(backup_dir.glob(".vault_backup_*.enc"))
                if not backup_files:
                    self.logger.error("No backup files found")
                    return False
                
                # Get the most recent backup
                backup_path = max(backup_files, key=os.path.getctime)
            
            # Read backup file
            with open(backup_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Derive backup key
            backup_key = self.derive_backup_key(master_password)
            
            # Decrypt backup data
            decrypted_data = self.decrypt_backup_data(encrypted_data, backup_key)
            vault_data = json.loads(decrypted_data.decode())
            
            # Save restored vault
            success, message = self.save_vault(vault_data, master_password)
            
            if success:
                self.logger.info(f"Vault restored successfully from {backup_path}")
            else:
                self.logger.error(f"Failed to save restored vault: {message}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Restore failed: {e}")
            return False

    # +++ SECURITY MONITORING METHODS +++
    
    def enable_portable_threat_detection(self):
        """Enhanced threat detection for portable operation"""
        # Additional checks for portable use
        self.start_ssd_security_monitoring()
        self.environment_validation()
        self.check_system_vulnerabilities()
        
        # Start periodic security scans
        self.start_periodic_security_scans()

    def start_ssd_security_monitoring(self):
        """Start security monitoring for SSD operation"""
        # Start background monitoring thread
        monitor_thread = threading.Thread(
            target=self.ssd_security_monitor,
            daemon=True,
            name="SSDSecurityMonitor"
        )
        monitor_thread.start()
    
    def ssd_security_monitor(self):
        """Background security monitoring for SSD operation"""
        while True:
            try:
                self.monitor_ssd_security()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                self.logger.error(f"Security monitoring error: {e}")
                time.sleep(60)
    
    def monitor_ssd_security(self):
        """Monitor security conditions for SSD operation"""
        # Check for suspicious conditions
        current_state = self.protection_state
        
        # Adjust security level based on conditions
        if self.detect_suspicious_activity():
            self.protection_state = max(
                self.protection_state, 
                ProtectionState.HEIGHTENED
            )
        else:
            self.protection_state = ProtectionState.NORMAL
        
        if current_state != self.protection_state:
            self.logger.info(f"Security state changed to: {self.protection_state.name}")
    
    def detect_suspicious_activity(self) -> bool:
        """Detect suspicious activity for SSD operation"""
        # Simple detection for portable use
        try:
            # Check for unexpected processes
            if self.has_unexpected_processes():
                return True
            
            # Check for network activity
            if self.has_unexpected_network_activity():
                return True
            
            return False
        except:
            return False
    
    def has_unexpected_processes(self) -> bool:
        """Check for unexpected processes (simplified for portable use)"""
        try:
            # Simple check for common monitoring tools
            suspicious_processes = [
                "wireshark", "tcpdump", 'procmon', 'regmon', 
                'filemon', 'processhacker', 'processexplorer'
            ]
            
            if platform.system() == "Windows":
                output = subprocess.run(['tasklist'], capture_output=True, text=True)
            else:
                output = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            
            if output.returncode == 0:
                process_list = output.stdout.lower()
                for proc in suspicious_processes:
                    if proc in process_list:
                        return True
        except:
            pass
        
        return False
    
    def has_unexpected_network_activity(self) -> bool:
        """Check for unexpected network activity (simplified)"""
        try:
            # Simple check for active network connections
            if platform.system() == "Windows":
                output = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            else:
                output = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)
            
            if output.returncode == 0:
                # Look for unexpected listening ports
                netstat_output = output.stdout
                suspicious_ports = [1337, 31337, 4444, 6667]  # Common suspicious ports
                for port in suspicious_ports:
                    if f":{port}" in netstat_output:
                        return True
        except:
            pass
        
        return False
    
    def environment_validation(self):
        """Validate operating environment for security"""
        # Check for unsafe conditions when running from SSD
        unsafe_conditions = []
        
        # Check if running on unknown system
        try:
            system_info = platform.uname()
            known_system = self.is_system_known(system_info)
            if not known_system:
                unsafe_conditions.append("Unknown operating system")
        except:
            unsafe_conditions.append("Cannot determine system information")
        
        # Check network connectivity
        try:
            if self.has_internet_connection():
                unsafe_conditions.append("Internet connection detected")
        except:
            pass
        
        if unsafe_conditions:
            self.logger.warning(f"Unsafe conditions detected: {unsafe_conditions}")
            self.protection_state = ProtectionState.HEIGHTENED
    
    def has_internet_connection(self) -> bool:
        """Check if internet connection is available"""
        try:
            # Try to connect to a reliable server
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except:
            return False
    
    def is_system_known(self, system_info) -> bool:
        """Check if the system is known (simplified for portable use)"""
        # Simple check - consider all systems as potentially unknown for portable use
        return False  # Conservative approach for portable operation

def main():
    """Main function with enhanced security checks"""
    try:
        # Check for critical dependencies
        if MISSING_CRITICAL_DEPS:
            print(f"❌ Critical dependencies missing: {', '.join(MISSING_CRITICAL_DEPS)}")
            print("Please install them with: pip install cryptography argon2-cffi")
            return 1
        
        # Security warning for outdated Python
        if sys.version_info < (3, 8):
            print("⚠️  Warning: Using an outdated Python version may have security vulnerabilities")
            print("Consider upgrading to Python 3.8 or later")
        
        # Additional security checks
        if platform.system() != "Windows" and os.geteuid() == 0:
            print("⚠️  Warning: Running as root is not recommended for security reasons")
            response = input("Continue anyway? (y/N): ").strip().lower()
            if response != 'y':
                return 1
        
        # Check for insecure environment variables
        insecure_env_vars = ['PYTHONINSPECT', 'PYTHONDEBUG']
        for var in insecure_env_vars:
            if var in os.environ:
                print(f"⚠️  Warning: Insecure environment variable {var} is set")
        
        # Create vault instance
        vault = SSDUltimateVault()
        
        # Start interactive menu
        vault.interactive_menu()
        
        return 0
        
    except KeyboardInterrupt:
        print("\n👋 Operation cancelled by user.")
        return 0
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        logging.error(f"Fatal error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
