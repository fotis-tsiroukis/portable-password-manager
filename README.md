Portable, Offline Password Manager

My goal with this script was to design a portable, military-grade password manager that will be able to run from an external SSD with speed of 350 MB/s or more. I tried to provide defense in depth by implementing multiple, redundant layers of security to protect against a wide array of attacks, including physical theft of the SSD it's stored on.

The script is structured around a single main class, called SSDUltimateVault.

When the __init__ function is launched, the script:
1. Checks for Critical Dependencies and it immediately fails if cryptography and argon2 are missing, as they are fundamental to its security.
2. Finds the Vault Location with the get_ssd_vault_dir() function, which searches on Windows for drives D: through L:; on Linux/macOS, for /media, /Volumes, etc. to automatically detect the external SSD and creates an UltimateVault directory there. If no external drive is found, it falls back to a local directory. This makes the vault portable.
3. It loads or creates a config.json file that defines its security parameters (encryption algorithms, iteration counts, defense features to enable, etc.).
4. It writes logs to a file with secure permissions.
5. It sets up the following security attributes:
- protection_state: The current threat level (Normal, Heightened, Elevated, etc.).
- ssd_telemetry: Tracks performance and security metrics.
- thread_pool: Creates an optimized pool of worker threads for SSD operations.
- secure_allocations, memory_guards, rng_entropy_pool: Core components for advanced memory protection.
- secure_timers: Used to implement timing-attack resistant delays.
6. It calls security setup routines initialize_ssd_security() and setup_enhanced_protections() to activate the various defense mechanisms.

Regarding security practices the following choices were made:
1. The Argon2 algorithm was chosen for key derivation but a fallback to PBKDF2-HMAC-SHA512 with a high iteration count of 600,000 iterations was created in case Argon2 fails to be imported.
2. Three layers of encryption were used through the encrypt_vault_constant_time() method:
- Layer 1: AES-GCM (using the first 32 bytes of a 64-byte key).
- Layer 2: ChaCha20-Poly1305 (using a separately derived key).
- Layer 3: AES-GCM again (using the last 32 bytes of the 64-byte key).
This means an attacker would need to break all three layers to get the data.
3. Different keys are derived for different purposes (e.g., derive_enhanced_encryption_key() for the main vault, derive_chacha_key() for the second layer, derive_backup_key() for backups) using unique salts and context strings. This prevents a compromise of one key from affecting others.
4. Resistance to Timing Attacks: A timing attack involves measuring how long an operation takes to glean information about secrets. I have tried with this script to avoid this in the following ways.
- Constant-Time Comparison: The constant_time_compare() function compares two strings/bytes using XOR operations and a fixed number of iterations. It always takes the same amount of time to return a result, whether the comparison succeeds or fails.
- Random Delays: The secure_delay() function adds a random delay (100-500ms) before returning from security-critical functions, making it impossible for an attacker to get precise timing measurements.
5. Secure Memory Management: The script assumes that an attacker can read the process's memory (RAM). It fights this with:
- Secure Wiping: The secure_memory_wipe() function overwrites sensitive data in memory (like passwords and keys) multiple times with different patterns (following the DoD 7-pass standard) before freeing it. This prevents data remnants from being scooped out of memory.
- Locked Memory Pages: On Unix systems, it tries to use mlock() to prevent sensitive data from being swapped to disk, where it could be recovered later.
- Secure Allocator: The secure_alloc() and secure_free() functions handle the allocation and wiping of sensitive memory regions.
6. Tamper and Forensics Detection was achieved with:
- File Integrity Checks: It stores cryptographic hashes (SHA256, SHA3-256, BLAKE2b) of critical files (auth.dat, vault.dat, config.json). On startup and before operations, it recalculates these hashes and compares them to the stored values using constant-time comparison. Any change triggers a warning.
- Anti-Forensics Measures: When enabled, enable_anti_forensics() creates decoy files with random data and timestamps to mislead forensic analysis.
- File Permission Checks: It verifies that critical files have strict permissions (e.g., 600 on Unix, meaning only the owner can read/write).
7. Key Management and Rotation was achieved with:
- Automatic Key Rotation: The key_rotation_check() method runs during session start. If the encryption keys are older than the configured period, 30 days by default, it triggers the rotate_encryption_keys() function. This function decrypts the entire vault with the old key and immediately re-encrypts it with a newly derived key, rendering any previously stolen encrypted vault data useless.

User interaction with the script

The first time the script runs:
1. The is_first_run() function sees no auth.dat file.
2. The user is prompted to create a master password with minimum 14 characters. The master password must include uppercase, lowercase, digits, special characters, and must not be a common password or a keyboard pattern.
3. A cryptographically random salt is generated.
4. A hash of the master password + salt is created using Argon2/PBKDF2.
5. The hash, salt, and metadata are stored in auth.dat.

Normal Operation / Login:
1. The user enters their master password.
2. Brute Force Protection: The check_brute_force_protection() function implements exponential backoff. After 3 failed attempts, it forces the user to wait (2^(attempts-2) seconds, up to 5 minutes).
3. Tamper Detection: Before verifying the password, enhanced_tamper_detection() runs to ensure the vault hasn't been modified.
4. Password Verification: The stored salt is retrieved, the hash of the provided password is computed, and compared to the stored hash using timing_attack_resistant_equals().
5. Session Start: If successful, a session begins. The master password is kept in memory for the session duration, by default 15 minutes. A timer counts down, and the session automatically expires, wiping the master password from memory.

Passwords Operations:
- Viewing: The load_vault() function decrypts the vault.dat file using the master password in memory. Passwords are displayed masked. The user can choose to reveal them by re-entering the master password.
- Adding/Editing: New entries are added to the decrypted data structure in memory. The save_vault() function is called, which encrypts the entire data structure (using the layered encryption) and writes it back to vault.dat.
- Deleting: Entries are removed from the in-memory structure, and the vault is re-saved.

Advanced Features
- Import/Export from CSV: The import_from_csv() and export_to_csv() functions can auto-detect the format of exported files from the most common password managers, like Chrome, Firefox, LastPass, 1Password, Bitwarden, etc., and parse them correctly, making migration easy.
- Backup and Restore: The backup_vault() function creates an encrypted backup file. The backup file is encrypted with a key derived from both the master password and a system fingerprint (hostname, machine ID, etc.). This means the backup can only be restored on the same machine it was created on, protecting against an attacker stealing the backup file and trying to decrypt it elsewhere.
- Security Audit: The perform_security_audit() and enhanced_security_audit() functions run a comprehensive check on the system's security posture (encryption settings, file permissions, key rotation status, etc.) and provide a score and improvement suggestions.
- Continuous Monitoring: Background threads constantly run to monitor for debuggers (detect_debugger()), check for code injection (monitor_code_integrity()) and look for suspicious processes or network activity (ssd_security_monitor()).

The Data Lifecycle
1. At Rest (on SSD): Data in vault.dat is protected by multiple layers of encryption (AES-GCM + ChaCha20-Poly1305). The key to decrypt it is derived from the user's master password and a salt.
2. In Use (in RAM): The master password is used to decrypt the vault into memory. While in memory, sensitive data is held in locked or securely wiped pages. All operations on this data (comparisons, encryption) are done in constant-time.
3. In Transit (Backups): Backups are encrypted with a separate, system-tied key, making them useless on any other computer.
4. Destruction: When the program exits or data is no longer needed, it is not just deleted; it is securely wiped from memory using multiple overwrites.
