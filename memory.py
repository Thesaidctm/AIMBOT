# memory.py - Memory reading/writing functionality with anti-detection measures
from pymem import Pymem
from pymem.process import module_from_name
import time
import psutil
import sys
import random
import ctypes
import os
from ctypes import wintypes
import threading

# Windows API constants and functions for stealthier memory access
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400

# Define Windows API functions
ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

class MemoryManager:
    def __init__(self):
        self.process = None
        self.client_module = None
        self.engine_module = None
        self.handle_rotation_time = 30  # Seconds before rotating handle
        self.last_handle_rotation = time.time()
        self.handle = None
        self.pid = None
        self.access_jitter = True  # Add timing jitter to memory access
        self.connect_to_game()
        # Start handle rotation thread
        self.handle_thread = threading.Thread(target=self._handle_rotation_thread, daemon=True)
        self.handle_thread.start()
        
    def _handle_rotation_thread(self):
        """Thread to periodically rotate process handles"""
        while True:
            time.sleep(random.uniform(25, 35))  # Randomize rotation time
            try:
                self._rotate_handle()
            except:
                pass  # Silently fail
        
    def _rotate_handle(self):
        """Rotate process handle to avoid detection"""
        if not self.process:
            return
            
        # Only rotate if enough time has passed
        current_time = time.time()
        if current_time - self.last_handle_rotation < self.handle_rotation_time:
            return
            
        # Get a fresh handle with minimal permissions
        try:
            # Close old handle first if it exists
            if self.handle:
                kernel32.CloseHandle(self.handle)
                
            # Get a new handle with minimal required access
            access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
            self.handle = kernel32.OpenProcess(access, False, self.pid)
            self.last_handle_rotation = current_time
            
            # Randomize next rotation time (20-40 seconds)
            self.handle_rotation_time = random.uniform(20, 40)
        except:
            pass  # Silently fail
        
    def connect_to_game(self):
        """Find and connect to CS 1.6 process with stealth measures"""
        # Randomize connection message to avoid signature detection
        connect_messages = [
            "Initializing...",
            "Starting up...",
            "Preparing environment...",
            "Setting up components..."
        ]
        print(random.choice(connect_messages))
        
        # Common process names for CS 1.6 with some decoys to confuse signature detection
        process_names = ["hl.exe", "cstrike.exe", "cs.exe"]
        decoy_names = ["steam.exe", "Discord.exe", "chrome.exe"]
        
        # Add some random timing before searching
        time.sleep(random.uniform(0.1, 0.5))
        
        # Try to find the process with randomized search order
        all_procs = list(psutil.process_iter(['name', 'pid']))
        random.shuffle(all_procs)  # Randomize search order
        
        for proc in all_procs:
            # Occasionally check a decoy process to mask behavior pattern
            if random.random() < 0.1:
                continue
                
            if proc.info['name'] in process_names:
                try:
                    # Add slight delay before connection attempt
                    time.sleep(random.uniform(0.05, 0.2))
                    
                    self.process = Pymem(proc.info['name'])
                    self.pid = proc.info['pid']
                    
                    # Get a handle with minimal permissions
                    access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
                    self.handle = kernel32.OpenProcess(access, False, self.pid)
                    
                    # Don't print connected message to avoid detection
                    break
                except Exception:
                    pass
        
        # If process not found
        if not self.process:
            print("Required component not found. Please check your setup.")
            
            # Keep trying to connect with randomized retry timing
            retry_count = 0
            max_retries = random.randint(25, 35)  # Randomize max retries
            
            while not self.process and retry_count < max_retries:
                sleep_time = random.uniform(0.8, 1.2)  # Randomize sleep time
                time.sleep(sleep_time)
                retry_count += 1
                
                # Shuffle process list each time
                random.shuffle(all_procs)
                
                for proc in all_procs:
                    if proc.info['name'] in process_names:
                        try:
                            self.process = Pymem(proc.info['name'])
                            self.pid = proc.info['pid']
                            
                            # Get a handle with minimal permissions
                            access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
                            self.handle = kernel32.OpenProcess(access, False, self.pid)
                            break
                        except Exception:
                            pass
            
            if not self.process:
                print("Setup incomplete. Please verify your environment.")
                sys.exit(1)
        
        # Get modules with obfuscated approach and multiple fallback options
        try:
            # Add random delay before module access
            time.sleep(random.uniform(0.1, 0.3))
            
            # Try multiple possible client module names
            client_module_names = ["client.dll", "mp.dll", "cstrike.dll", "valve.dll"]
            self.client_module = None
            
            print("Searching for client module...")
            for client_name in client_module_names:
                try:
                    print(f"Trying client module: {client_name}")
                    self.client_module = module_from_name(self.process.process_handle, client_name).lpBaseOfDll
                    print(f"Found client module: {client_name} at address {hex(self.client_module)}")
                    break
                except Exception as e:
                    print(f"Failed to find client module {client_name}: {str(e)}")
                    continue
            
            if not self.client_module:
                print("Client module not found. Please verify game installation.")
                sys.exit(1)
            
            # Add jitter between module accesses
            time.sleep(random.uniform(0.05, 0.15))
            
            # Try multiple possible engine module names
            engine_module_names = ["hw.dll", "sw.dll", "engine.dll", "hl.dll"]
            self.engine_module = None
            
            print("Searching for engine module...")
            for engine_name in engine_module_names:
                try:
                    print(f"Trying engine module: {engine_name}")
                    self.engine_module = module_from_name(self.process.process_handle, engine_name).lpBaseOfDll
                    print(f"Found engine module: {engine_name} at address {hex(self.engine_module)}")
                    break
                except Exception as e:
                    print(f"Failed to find engine module {engine_name}: {str(e)}")
                    continue
            
            if not self.engine_module:
                print("Engine module not found. Please verify game installation.")
                sys.exit(1)

            # 👇👇👇 ADIÇÃO: pegar o módulo principal (exe)
            # pymem normalmente expõe o módulo principal em process_base
            self.game_module = None
            try:
                # tentativa 1: jeito direto do pymem
                if hasattr(self.process, "process_base") and self.process.process_base:
                    self.game_module = self.process.process_base.lpBaseOfDll
            except:
                pass

            # tentativa 2: procurar pelo nome do executável
            if not self.game_module:
                main_exe_names = ["hl.exe", "cs.exe", "cstrike.exe"]
                for exe_name in main_exe_names:
                    try:
                        mod = module_from_name(self.process.process_handle, exe_name)
                        if mod:
                            self.game_module = mod.lpBaseOfDll
                            print(f"Found game module: {exe_name} at address {hex(self.game_module)}")
                            break
                    except:
                        continue

            # fallback: se mesmo assim não achar, usa o client.dll como base
            if not self.game_module:
                self.game_module = self.client_module
                print("Game module not found, falling back to client module as base.")

            self.main_module = self.game_module
            # não imprime mensagem de sucesso pra não dar padrão
        except Exception as e:
            print("Configuration issue detected. Make sure Counter-Strike is running.")
            sys.exit(1)
    
    def _add_access_jitter(self):
        """Add random timing jitter to memory access"""
        if self.access_jitter and random.random() < 0.3:  # 30% chance to add jitter
            time.sleep(random.uniform(0.001, 0.005))
    
    def read_int(self, address):
        """Read 4-byte integer from memory with anti-detection measures"""
        self._add_access_jitter()
        
        # Occasionally rotate handle
        if random.random() < 0.01:  # 1% chance per read
            self._rotate_handle()
            
        try:
            # Use different read methods randomly to avoid pattern detection
            if random.random() < 0.7:  # 70% chance to use pymem
                return self.process.read_int(address)
            else:  # 30% chance to use direct WinAPI
                buffer = ctypes.c_int()
                bytes_read = ctypes.c_size_t()
                ReadProcessMemory(self.handle, address, ctypes.byref(buffer), 
                                 ctypes.sizeof(buffer), ctypes.byref(bytes_read))
                return buffer.value
        except Exception:
            return 0
    
    def read_float(self, address):
        """Read 4-byte float from memory with anti-detection measures"""
        self._add_access_jitter()
        
        # Occasionally rotate handle
        if random.random() < 0.01:  # 1% chance per read
            self._rotate_handle()
            
        try:
            # Use different read methods randomly
            if random.random() < 0.7:  # 70% chance to use pymem
                return self.process.read_float(address)
            else:  # 30% chance to use direct WinAPI
                buffer = ctypes.c_float()
                bytes_read = ctypes.c_size_t()
                ReadProcessMemory(self.handle, address, ctypes.byref(buffer), 
                                 ctypes.sizeof(buffer), ctypes.byref(bytes_read))
                return buffer.value
        except Exception:
            return 0.0
    
    def read_bytes(self, address, size):
        """Read bytes from memory with anti-detection measures"""
        self._add_access_jitter()
        
        # Occasionally rotate handle
        if random.random() < 0.01:  # 1% chance per read
            self._rotate_handle()
            
        try:
            # Use different read methods randomly
            if random.random() < 0.7:  # 70% chance to use pymem
                return self.process.read_bytes(address, size)
            else:  # 30% chance to use direct WinAPI
                buffer = ctypes.create_string_buffer(size)
                bytes_read = ctypes.c_size_t()
                ReadProcessMemory(self.handle, address, buffer, size, ctypes.byref(bytes_read))
                return buffer.raw
        except Exception:
            return b'\x00' * size
    
    def write_int(self, address, value):
        """Write 4-byte integer to memory with anti-detection measures"""
        self._add_access_jitter()
        
        # Occasionally rotate handle
        if random.random() < 0.02:  # 2% chance per write
            self._rotate_handle()
            
        try:
            # Use different write methods randomly
            if random.random() < 0.6:  # 60% chance to use pymem
                self.process.write_int(address, value)
            else:  # 40% chance to use direct WinAPI
                data = ctypes.c_int(value)
                bytes_written = ctypes.c_size_t()
                WriteProcessMemory(self.handle, address, ctypes.byref(data), 
                                  ctypes.sizeof(data), ctypes.byref(bytes_written))
            return True
        except Exception:
            return False
    
    def write_float(self, address, value):
        """Write 4-byte float to memory with anti-detection measures"""
        self._add_access_jitter()
        
        # Occasionally rotate handle
        if random.random() < 0.02:  # 2% chance per write
            self._rotate_handle()
            
        try:
            # Use different write methods randomly
            if random.random() < 0.6:  # 60% chance to use pymem
                self.process.write_float(address, value)
            else:  # 40% chance to use direct WinAPI
                data = ctypes.c_float(value)
                bytes_written = ctypes.c_size_t()
                WriteProcessMemory(self.handle, address, ctypes.byref(data), 
                                  ctypes.sizeof(data), ctypes.byref(bytes_written))
            return True
        except Exception:
            return False
    
    def write_bytes(self, address, value):
        """Write bytes to memory with anti-detection measures"""
        self._add_access_jitter()
        
        # Occasionally rotate handle
        if random.random() < 0.02:  # 2% chance per write
            self._rotate_handle()
            
        try:
            # Use different write methods randomly
            if random.random() < 0.6:  # 60% chance to use pymem
                self.process.write_bytes(address, value, len(value))
            else:  # 40% chance to use direct WinAPI
                buffer = ctypes.create_string_buffer(value)
                bytes_written = ctypes.c_size_t()
                WriteProcessMemory(self.handle, address, buffer, len(value), 
                                  ctypes.byref(bytes_written))
            return True
        except Exception:
            return False
