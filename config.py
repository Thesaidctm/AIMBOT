# config.py - Configuration settings with anti-detection measures
import json
import os
import random
import time
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Config:
    def __init__(self):
        # Aimbot settings with more aggressive defaults
        self.fov_limit = 10.0                           # Increased FOV to find more targets
        self.smoothing = 1.2                            # Lower smoothing for more noticeable aim
        self.use_mouse_movement = True                  # Force mouse movement method
        self.mouse_sensitivity = 1.5                    # Increased mouse sensitivity
        self.target_bone = "body"                       # Target body (larger target)
        self.check_visibility = False                   # Disable visibility checks
        self.recoil_control = True                      # Enable recoil control
        self.recoil_scale = 2.0                         # Standard recoil scale
        
        # Anti-detection settings
        self.randomize_aim = True                # Add human-like randomization to aim
        self.aim_path_complexity = random.uniform(0.8, 1.2)  # Bezier curve complexity
        self.target_switch_delay = random.uniform(0.1, 0.3)  # Delay when switching targets
        self.max_consecutive_aims = random.randint(3, 7)     # Max aims before forced break
        self.forced_break_duration = random.uniform(0.5, 1.5) # Duration of forced breaks
        self.jitter_amount = random.uniform(0.05, 0.15)      # Amount of aim jitter
        self.use_dynamic_smoothing = True        # Adjust smoothing based on distance/FOV
        self.memory_access_randomization = True  # Randomize memory access patterns
        self.handle_rotation_interval = random.uniform(20, 40)  # Seconds between handle rotations
        self.obfuscate_strings = True           # Use obfuscated terminology in UI
        self.monitor_detection = True           # Check for monitoring software
        
        # Key bindings with randomized defaults
        key_options = ["alt", "ctrl", "shift", "capslock", "tab"]
        exit_options = ["end", "home", "delete", "insert", "pageup", "pagedown"]
        self.toggle_key = random.choice(key_options)     # Key to toggle aimbot
        self.exit_key = random.choice(exit_options)      # Key to exit program
        
        # Encryption settings
        self.encryption_key = None
        self.generate_encryption_key()
        
        # Try to load from file
        self.load_config()
    
    def generate_encryption_key(self):
        """Generate encryption key based on hardware identifiers"""
        try:
            # Create a unique but reproducible key based on system info
            # This way we don't need to store the key, but can regenerate it
            system_info = self._get_system_info()
            salt = b'static_salt_value_for_cs_helper'  # Static salt
            
            # Generate key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            
            # Derive key from system info
            key = base64.urlsafe_b64encode(kdf.derive(system_info.encode()))
            self.encryption_key = key
        except:
            # Fallback to a static key if generation fails
            self.encryption_key = b'9szh_PvPRIpUFVj6gCpGZQQqEDlSKqTYu2oA7RiQnvE='
    
    def _get_system_info(self):
        """Get unique but consistent system information"""
        try:
            # Get some system-specific information that's unlikely to change
            # but unique enough to create a device-specific key
            import platform
            
            # Combine system information
            system_info = (
                platform.node() +  # Computer name
                platform.system() +  # OS name
                platform.processor()  # Processor info
            )
            
            # Hash it to make it more uniform
            return hashlib.sha256(system_info.encode()).hexdigest()
        except:
            # Fallback if we can't get system info
            return "default_system_info_fallback_value"
    
    def _encrypt_data(self, data):
        """Encrypt configuration data"""
        try:
            if not self.encryption_key:
                self.generate_encryption_key()
                
            # Create Fernet cipher
            cipher = Fernet(self.encryption_key)
            
            # Convert data to JSON and encrypt
            json_data = json.dumps(data).encode()
            encrypted_data = cipher.encrypt(json_data)
            
            # Encode as base64 string for storage
            return base64.b64encode(encrypted_data).decode()
        except:
            # Fallback to JSON if encryption fails
            return json.dumps(data)
    
    def _decrypt_data(self, encrypted_str):
        """Decrypt configuration data"""
        try:
            # Decode from base64
            encrypted_data = base64.b64decode(encrypted_str)
            
            # Create Fernet cipher
            cipher = Fernet(self.encryption_key)
            
            # Decrypt and parse JSON
            decrypted_data = cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except:
            # Try to parse as plain JSON if decryption fails
            try:
                return json.loads(encrypted_str)
            except:
                return {}
    
    def _get_config_filename(self):
        """Get obfuscated config filename"""
        # Use different filenames to avoid detection
        options = [
            "system_preferences.dat",
            "user_settings.cfg",
            "app_config.dat",
            "display_settings.json",
            "input_config.dat"
        ]
        
        # Use a deterministic but non-obvious choice
        # This ensures we use the same filename each time on the same system
        system_info = self._get_system_info()
        index = sum(ord(c) for c in system_info) % len(options)
        return options[index]
    
    def load_config(self):
        """Load configuration from file with anti-detection measures"""
        try:
            filename = self._get_config_filename()
            
            if os.path.exists(filename):
                # Add random delay to simulate file reading
                time.sleep(random.uniform(0.05, 0.2))
                
                with open(filename, "r") as f:
                    encrypted_data = f.read()
                    
                # Decrypt data
                data = self._decrypt_data(encrypted_data)
                
                if data:
                    # Update config with loaded values
                    for key, value in data.items():
                        if hasattr(self, key):
                            setattr(self, key, value)
                    
                    # Print debug message with loaded settings
                    print("Config loaded successfully")
                    print(f"FOV limit: {self.fov_limit}")
                    print(f"Smoothing: {self.smoothing}")
                    print(f"Mouse movement: {self.use_mouse_movement}")
                    print(f"Mouse sensitivity: {self.mouse_sensitivity}")
                    print(f"Target bone: {self.target_bone}")
                    print(f"Check visibility: {self.check_visibility}")
                    print(f"Recoil control: {self.recoil_control}")
        except Exception as e:
            # Print error for debugging
            print(f"Error loading config: {str(e)}")
    
    def save_config(self):
        """Save configuration to file with anti-detection measures"""
        try:
            # Convert config to dict, excluding encryption key
            config_dict = {}
            for key, value in self.__dict__.items():
                if key != 'encryption_key':  # Don't save the encryption key
                    config_dict[key] = value
            
            # Encrypt the configuration
            encrypted_data = self._encrypt_data(config_dict)
            
            # Use obfuscated filename
            filename = self._get_config_filename()
            print(f"Saving config to file: {filename}")
            
            # Add random delay to simulate file writing
            time.sleep(random.uniform(0.05, 0.2))
            
            with open(filename, "w") as f:
                f.write(encrypted_data)
                
            print("Config saved successfully")
            print(f"Current settings:")
            print(f"FOV limit: {self.fov_limit}")
            print(f"Smoothing: {self.smoothing}")
            print(f"Mouse movement: {self.use_mouse_movement}")
            print(f"Mouse sensitivity: {self.mouse_sensitivity}")
            print(f"Target bone: {self.target_bone}")
            print(f"Check visibility: {self.check_visibility}")
            print(f"Recoil control: {self.recoil_control}")
        except Exception as e:
            # Print error for debugging
            print(f"Error saving config: {str(e)}")
    
    def randomize_settings(self):
        """Slightly randomize settings to avoid detection patterns"""
        # Randomize FOV limit by ±5%
        self.fov_limit *= random.uniform(0.95, 1.05)
        
        # Randomize smoothing by ±10%
        self.smoothing *= random.uniform(0.9, 1.1)
        
        # Randomize mouse sensitivity by ±5%
        self.mouse_sensitivity *= random.uniform(0.95, 1.05)
        
        # Randomize recoil scale by ±10%
        self.recoil_scale *= random.uniform(0.9, 1.1)
        
        # Occasionally switch target bone (5% chance)
        if random.random() < 0.05:
            self.target_bone = "body" if self.target_bone == "head" else "head"
        
        # Randomize anti-detection settings
        self.aim_path_complexity = random.uniform(0.8, 1.2)
        self.target_switch_delay = random.uniform(0.1, 0.3)
        self.max_consecutive_aims = random.randint(3, 7)
        self.forced_break_duration = random.uniform(0.5, 1.5)
        self.jitter_amount = random.uniform(0.05, 0.15)
        self.handle_rotation_interval = random.uniform(20, 40)
