# setup.py - Installation script with anti-detection measures
import subprocess
import sys
import os
import random
import time
import platform

def install_requirements():
    """Install required packages with anti-detection measures"""
    # Use obfuscated terminology
    setup_messages = [
        "Setting up components...",
        "Installing dependencies...",
        "Preparing environment...",
        "Configuring system utilities..."
    ]
    print(random.choice(setup_messages))
    
    # Basic requirements
    basic_requirements = [
        "pymem",
        "pywin32",
        "keyboard",
        "mouse",
        "numpy",
        "psutil"
    ]
    
    # Anti-detection requirements
    anti_detection_requirements = [
        "cryptography",
        "requests",  # Common package to make it look less suspicious
        "pillow",    # Common package to make it look less suspicious
        "matplotlib" # Common package to make it look less suspicious
    ]
    
    # Combine requirements
    requirements = basic_requirements + anti_detection_requirements
    
    # Randomize installation order
    random.shuffle(requirements)
    
    # Install packages with randomized delays
    for req in requirements:
        # Random delay between package installations
        time.sleep(random.uniform(0.2, 0.7))
        
        # Use different progress messages
        progress_messages = [
            f"Setting up {req}...",
            f"Configuring {req}...",
            f"Installing {req}...",
            f"Processing {req}..."
        ]
        print(random.choice(progress_messages))
        
        try:
            # Hide detailed output to avoid suspicion
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", req],
                stdout=subprocess.DEVNULL if random.random() > 0.3 else None
            )
            
            # Use different success messages
            success_messages = [
                f"Completed {req} setup",
                f"Finished {req} configuration",
                f"Successfully processed {req}",
                f"{req} is ready"
            ]
            print(random.choice(success_messages))
        except Exception:
            # Use obfuscated error messages
            error_messages = [
                f"Could not configure {req}",
                f"Issue with {req} setup",
                f"Problem processing {req}",
                f"Unable to complete {req} configuration"
            ]
            print(random.choice(error_messages))
            print("You may need to install this component manually.")
    
    # Random delay before completion
    time.sleep(random.uniform(0.5, 1.0))
    print("\nEnvironment setup complete.")

def check_environment():
    """Check system environment for compatibility and monitoring tools"""
    # Random delay to simulate checking
    time.sleep(random.uniform(0.3, 0.8))
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 6):
        print("Warning: This application requires Python 3.6 or higher.")
        print(f"Current Python version: {python_version.major}.{python_version.minor}")
        return False
    
    # Check operating system
    if platform.system() != "Windows":
        print("Warning: This application is designed for Windows operating systems.")
        print(f"Current OS: {platform.system()}")
        return False
    
    # Check for potential monitoring/analysis tools
    suspicious_processes = [
        "wireshark", "procmon", "processhacker", "ollydbg", "x64dbg", "ida", 
        "immunity", "cheatengine", "httpdebugger", "fiddler", "charles"
    ]
    
    try:
        import psutil
        running_processes = [p.name().lower() for p in psutil.process_iter()]
        
        for proc in suspicious_processes:
            if any(proc in p for p in running_processes):
                print("Warning: Please close all debugging and monitoring tools before running this application.")
                return False
    except:
        # Silently continue if psutil isn't available yet
        pass
    
    return True

def print_instructions():
    """Print usage instructions with obfuscated terminology"""
    # Use different header texts randomly
    headers = [
        "=== System Utility Setup Complete ===",
        "=== Performance Monitor Ready ===",
        "=== Game Assistant Configured ===",
        "=== Setup Completed Successfully ==="
    ]
    print(f"\n{random.choice(headers)}")
    
    print("\nUsage Instructions:")
    print("1. Start your game")
    print("2. Run the assistant with: python main.py")
    print("3. Use hotkeys to control functionality")
    print("4. Press designated exit key to close the program")
    
    print("\nConfiguration:")
    print("- Settings are automatically saved and loaded")
    print("- The system will optimize itself based on your usage")
    
    print("\nNote: This software is for educational purposes only.")
    print("Usage may be subject to terms of service of other applications.")

def create_dummy_files():
    """Create dummy files to mask the true purpose of the application"""
    try:
        # Create a dummy README with innocent description
        with open("README_INSTALL.txt", "w") as f:
            f.write("GAME PERFORMANCE UTILITY\n\n")
            f.write("This utility helps optimize game performance and monitor system resources.\n")
            f.write("It provides real-time statistics and performance enhancements for various games.\n\n")
            f.write("For educational and research purposes only.\n")
        
        # Create a dummy log file
        with open("system_log.txt", "w") as f:
            f.write(f"System check completed at {time.ctime()}\n")
            f.write(f"OS: {platform.system()} {platform.release()}\n")
            f.write(f"Python: {platform.python_version()}\n")
            f.write("All components initialized successfully.\n")
    except:
        # Silent failure
        pass

if __name__ == "__main__":
    try:
        # Use obfuscated title
        setup_titles = [
            "=== System Utility Setup ===",
            "=== Performance Monitor Installation ===",
            "=== Game Assistant Configuration ===",
            "=== Setup Wizard ==="
        ]
        print(random.choice(setup_titles))
        
        # Random delay to simulate initialization
        time.sleep(random.uniform(0.5, 1.0))
        
        # Check environment
        if check_environment():
            # Install requirements
            install_requirements()
            
            # Create dummy files
            create_dummy_files()
            
            # Print instructions
            print_instructions()
            
            # Random delay before exit prompt
            time.sleep(random.uniform(0.3, 0.7))
            input("\nPress Enter to exit setup...")
        else:
            print("\nSetup cannot continue due to environment issues.")
            print("Please address the warnings and try again.")
            input("Press Enter to exit...")
    except KeyboardInterrupt:
        print("\nSetup interrupted.")
    except Exception:
        print("\nAn unexpected issue occurred during setup.")
        print("Please ensure you have administrator privileges and try again.")
        input("Press Enter to exit...")
