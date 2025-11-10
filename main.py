# main.py - Main entry point for CS 1.6 aimbot with anti-detection measures
import time
import keyboard
import os
import sys
import random
import threading
import psutil
from memory import MemoryManager
from offsets import Offsets
from entity import Player
from aimbot import Aimbot
from config import Config
from vector import Vector3

# Global variables for anti-detection
STATUS_UPDATE_INTERVAL = random.uniform(2.0, 5.0)  # Randomized status update interval
PROCESS_CHECK_INTERVAL = random.uniform(10.0, 20.0)  # Check for monitoring processes
last_status_update = 0
last_process_check = 0
suspicious_processes = [
    "wireshark", "procmon", "processhacker", "ollydbg", "x64dbg", "ida", 
    "immunity", "cheatengine", "httpdebugger", "fiddler", "charles"
]

def clear_console():
    """Clear console screen with randomized method"""
    # Occasionally use different clearing methods to avoid detection patterns
    if random.random() < 0.2:  # 20% chance
        print("\n" * 100)  # Simple newline-based clearing
    else:
        os.system('cls' if os.name == 'nt' else 'clear')

def print_status(aimbot, fps=0):
    """Print current status with obfuscated terminology"""
    # Don't clear console to preserve debug messages
    # clear_console()
    
    # Use different header texts randomly
    headers = [
        "=== Performance Monitor ===",
        "=== System Utility ===",
        "=== Game Assistant ===",
        "=== CS Helper ===",
        "=== FPS Optimizer ==="
    ]
    
    print(random.choice(headers))
    
    # Use obfuscated terminology
    status_terms = ["RUNNING", "ENABLED"] if aimbot.is_active else ["STANDBY", "DISABLED"]
    print(f"Status: {random.choice(status_terms)}")
    print(f"Performance: {fps:.1f}")
    print(f"Sensitivity: {aimbot.config.fov_limit}°")
    print(f"Response: {aimbot.config.smoothing}x")
    print(f"Mode: {aimbot.config.target_bone}")
    
    print("\nControls:")
    print(f"  {aimbot.config.toggle_key.upper()}: Toggle assistant")
    print(f"  {aimbot.config.exit_key.upper()}: Exit program")
    
    # Use obfuscated target terminology
    target_terms = ["TRACKING", "ACTIVE"] if aimbot.target_lock else ["IDLE", "SEARCHING"]
    print("\nFocus: " + random.choice(target_terms))

def check_for_monitoring():
    """Check for monitoring/analysis tools that might detect the aimbot"""
    try:
        # Get all running processes
        all_processes = [proc.info['name'].lower() for proc in psutil.process_iter(['name'])]
        
        # Check for suspicious processes
        for proc_name in suspicious_processes:
            if any(proc_name in p for p in all_processes):
                return True
                
        # Check for excessive CPU usage in analysis tools
        for proc in psutil.process_iter(['name', 'cpu_percent']):
            if proc.info['cpu_percent'] > 50:  # High CPU usage
                proc_name = proc.info['name'].lower()
                if any(s in proc_name for s in ["debug", "monitor", "wireshark", "analyze"]):
                    return True
                    
        return False
    except:
        return False  # Fail silently

def randomize_execution_pattern():
    """Add random timing variations to execution to avoid detection"""
    # Random sleep time between 0.5ms and 2ms
    time.sleep(random.uniform(0.0005, 0.002))
    
    # Occasionally perform dummy operations
    if random.random() < 0.05:  # 5% chance
        # Dummy operations that do nothing but change execution pattern
        dummy_list = [random.random() for _ in range(random.randint(5, 20))]
        dummy_list.sort()
        
        # Occasionally allocate and free memory
        if random.random() < 0.2:  # 20% chance of dummy allocations
            dummy_bytes = bytearray(random.randint(1024, 10240))
            for i in range(min(100, len(dummy_bytes))):
                dummy_bytes[i] = random.randint(0, 255)
            del dummy_bytes

def anti_detection_thread(aimbot):
    """Background thread for anti-detection measures"""
    while True:
        try:
            # Random sleep to avoid detection
            time.sleep(random.uniform(5.0, 15.0))
            
            # Occasionally update offsets
            if random.random() < 0.2:  # 20% chance
                Offsets.update_offsets()
                
            # Check for monitoring software
            if check_for_monitoring():
                # Temporarily disable aimbot if monitoring detected
                if aimbot.is_active:
                    aimbot.toggle()
                    # Wait a while before re-enabling
                    time.sleep(random.uniform(30.0, 60.0))
                    
            # Randomize memory access patterns
            aimbot.memory.access_jitter = not aimbot.memory.access_jitter
            
        except:
            # Silent failure
            pass

def main():
    try:
        # Use obfuscated startup messages
        startup_messages = [
            "Initializing system components...",
            "Starting performance monitor...",
            "Loading game assistant...",
            "Preparing environment...",
            "Setting up utilities..."
        ]
        print(random.choice(startup_messages))
        
        # Add random startup delay
        time.sleep(random.uniform(0.5, 1.5))
        
        # Initialize components
        config = Config()
        memory = None
        
        # Try to connect to game with better error handling
        try:
            print("Connecting to game process...")
            memory = MemoryManager()
            print("Game process found successfully.")
        except Exception as e:
            print("Initialization failed. Please make sure Counter-Strike is running.")
            print("Error details:", str(e))
            input("Press Enter to exit...")
            return
        
        try:
            print("Initializing aimbot...")
            aimbot = Aimbot(memory, config)
            aimbot.initialize()
            print("Aimbot initialized successfully.")
        except Exception as e:
            print("Aimbot initialization failed.")
            print("Error details:", str(e))
            input("Press Enter to exit...")
            return
        
        # Use obfuscated initialization messages
        init_messages = [
            "Components initialized successfully.",
            "System ready.",
            "Setup complete.",
            "Environment prepared."
        ]
        print(random.choice(init_messages))
        print(f"Press {config.toggle_key.upper()} to toggle assistant.")
        print(f"Press {config.exit_key.upper()} to exit.")
        
        # Register hotkeys with randomized delay
        time.sleep(random.uniform(0.1, 0.3))
        keyboard.add_hotkey(config.toggle_key, lambda: toggle_aimbot(aimbot))
        
        # Start anti-detection thread
        anti_detect_thread = threading.Thread(target=anti_detection_thread, args=(aimbot,), daemon=True)
        anti_detect_thread.start()
        
        # Main loop variables
        running = True
        frame_count = 0
        last_time = time.time()
        fps = 0
        
        # Variables for randomized execution
        next_player_scan = time.time()
        player_scan_interval = random.uniform(0.05, 0.15)  # 50-150ms
        
        while running:
            global STATUS_UPDATE_INTERVAL, PROCESS_CHECK_INTERVA
            # Add randomized execution pattern
            randomize_execution_pattern()
            
            # Check exit key with randomized polling
            if random.random() < 0.8:  # 80% chance to check each cycle
                if keyboard.is_pressed(config.exit_key):
                    print("Shutting down...")
                    break
                
            current_time = time.time()
            frame_count += 1
            
            # Calculate FPS and update status with randomized interval
            global last_status_update
            if current_time - last_status_update >= STATUS_UPDATE_INTERVAL:
                fps = frame_count / (current_time - last_time)
                frame_count = 0
                last_time = current_time
                last_status_update = current_time
                
                # Update status display
                print_status(aimbot, fps)
                
                # Randomize next status update interval (2-5 seconds)
                STATUS_UPDATE_INTERVAL = random.uniform(2.0, 5.0)
            
            # Check for monitoring processes periodically
            global last_process_check, PROCESS_CHECK_INTERVAL
            if current_time - last_process_check >= PROCESS_CHECK_INTERVAL:
                last_process_check = current_time
                
                # Randomize next check interval (10-20 seconds)
                PROCESS_CHECK_INTERVAL = random.uniform(10.0, 20.0)
                
                # If monitoring detected, temporarily disable
                if check_for_monitoring() and aimbot.is_active:
                    aimbot.toggle()
            
            if aimbot.is_active:
                try:
                    # Only scan for players at randomized intervals
                    if current_time >= next_player_scan:
                        # Get local player
                        local_player_addr = memory.client_module + Offsets.dwLocalPlayer
                        print(f"Local player address: {local_player_addr}")
                        
                        if local_player_addr:
                            local_player = Player(memory, local_player_addr)
                            print(f"Local player: Health={local_player.health}, Team={local_player.team}")
                            
                            if not local_player.is_valid():
                                print("Local player is not valid")
                                # Randomized sleep on invalid player
                                time.sleep(random.uniform(0.005, 0.015))
                                
                                # Set next scan time
                                next_player_scan = current_time + random.uniform(0.05, 0.15)
                                continue
                            else:
                                print("Local player is valid")
                            
                            # Get players with randomized scanning pattern
                            players = []
                            
                            # Randomize scanning order
                            indices = list(range(1, Offsets.MAX_PLAYERS))
                            random.shuffle(indices)
                            
                            print(f"Scanning for players (max: {Offsets.MAX_PLAYERS})")
                            
                            # Only scan a random subset of players each time (70-100%)
                            scan_count = int(len(indices) * random.uniform(0.7, 1.0))
                            print(f"Scanning {scan_count} player slots")
                            
                            for i in indices[:scan_count]:
                                entity_addr = memory.read_int(memory.client_module + Offsets.dwEntityList + i * 4)
                                print(f"Player slot {i}: Address {entity_addr}")
                                
                                if entity_addr and entity_addr != local_player_addr:
                                    print(f"Found player at slot {i}, address {entity_addr}")
                                    players.append(Player(memory, entity_addr))
                                    
                                    # Add small random delay between player scans
                                    if random.random() < 0.1:  # 10% chance
                                        time.sleep(random.uniform(0.0001, 0.0005))
                            
                            print(f"Found {len(players)} potential players")
                            
                            # Find and aim at best target
                            target = aimbot.get_best_target(local_player, players)
                            if target:
                                aimbot.aim_at_target(target, local_player)
                        
                        # Set next player scan time with jitter
                        next_player_scan = current_time + random.uniform(0.05, 0.15)
                
                except Exception as e:
                    # Print exception for debugging
                    print(f"Error in main loop: {str(e)}")
                    time.sleep(random.uniform(0.1, 0.3))  # Random delay on error
            
            # Variable sleep to reduce CPU usage and avoid detection
            sleep_time = random.uniform(0.0005, 0.002)  # 0.5-2ms
            time.sleep(sleep_time)
        
        # Save config on exit with randomized delay
        time.sleep(random.uniform(0.1, 0.3))
        config.save_config()
        
    except KeyboardInterrupt:
        print("Shutting down...")
    except Exception as e:
        # Print exception for debugging
        print(f"Unhandled exception: {str(e)}")
        input("Press Enter to exit...")

def toggle_aimbot(aimbot):
    status = aimbot.toggle()
    
    # Use obfuscated terminology
    status_terms = {
        True: ["Assistant enabled", "System active", "Monitoring started"],
        False: ["Assistant disabled", "System inactive", "Monitoring stopped"]
    }
    
    # Print random status message
    print(random.choice(status_terms[status]))

if __name__ == "__main__":
    main()
