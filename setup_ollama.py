"""
Ollama Setup Script
Checks for and installs Ollama if needed
"""
import os
import sys
import subprocess
import platform
import requests


def is_ollama_installed():
    """Check if Ollama is installed"""
    try:
        result = subprocess.run(['ollama', '--version'], 
                              capture_output=True, 
                              text=True,
                              timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def install_ollama_windows():
    """Provide instructions for Windows Ollama installation"""
    print("\n" + "="*70)
    print("OLLAMA INSTALLATION REQUIRED (Windows)")
    print("="*70)
    print("\nOllama is not installed. Please follow these steps:\n")
    print("1. Download Ollama from: https://ollama.ai/download")
    print("2. Run the installer (OllamaSetup.exe)")
    print("3. After installation, restart this terminal")
    print("4. Run this script again\n")
    print("="*70 + "\n")
    
    # Try to open download page
    try:
        import webbrowser
        webbrowser.open('https://ollama.ai/download')
        print("✓ Opened download page in your browser")
    except:
        pass
    
    return False


def install_ollama_linux():
    """Install Ollama on Linux"""
    print("\n" + "="*70)
    print("INSTALLING OLLAMA (Linux)")
    print("="*70 + "\n")
    
    try:
        # Download and run install script
        print("Downloading Ollama installer...")
        install_cmd = "curl -fsSL https://ollama.ai/install.sh | sh"
        
        result = subprocess.run(install_cmd, shell=True, check=True)
        
        if result.returncode == 0:
            print("\n✓ Ollama installed successfully!")
            return True
        else:
            print("\n✗ Ollama installation failed")
            return False
            
    except Exception as e:
        print(f"\n✗ Error installing Ollama: {e}")
        print("\nManual installation:")
        print("Run: curl -fsSL https://ollama.ai/install.sh | sh")
        return False


def install_ollama_mac():
    """Provide instructions for macOS Ollama installation"""
    print("\n" + "="*70)
    print("OLLAMA INSTALLATION REQUIRED (macOS)")
    print("="*70)
    print("\nOllama is not installed. Please follow these steps:\n")
    print("Option 1 (Recommended):")
    print("  1. Download from: https://ollama.ai/download")
    print("  2. Open the .dmg file and drag Ollama to Applications")
    print("\nOption 2 (Homebrew):")
    print("  brew install ollama\n")
    print("After installation, run this script again.\n")
    print("="*70 + "\n")
    
    try:
        import webbrowser
        webbrowser.open('https://ollama.ai/download')
        print("✓ Opened download page in your browser")
    except:
        pass
    
    return False


def ensure_ollama():
    """Ensure Ollama is installed"""
    if is_ollama_installed():
        print("✓ Ollama is already installed")
        return True
    
    print("⚠ Ollama not found")
    
    system = platform.system()
    
    if system == "Windows":
        return install_ollama_windows()
    elif system == "Linux":
        return install_ollama_linux()
    elif system == "Darwin":  # macOS
        return install_ollama_mac()
    else:
        print(f"⚠ Unsupported platform: {system}")
        print("Please install Ollama manually from: https://ollama.ai/download")
        return False


def pull_model(model_name="mistral"):
    """Pull the LLM model"""
    print(f"\nPulling model: {model_name}")
    print("This may take a few minutes (downloading ~4GB)...\n")
    
    try:
        result = subprocess.run(['ollama', 'pull', model_name], 
                              check=True,
                              text=True)
        
        if result.returncode == 0:
            print(f"\n✓ Model '{model_name}' pulled successfully!")
            return True
        else:
            print(f"\n✗ Failed to pull model '{model_name}'")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"\n✗ Error pulling model: {e}")
        return False


def list_models():
    """List installed models"""
    try:
        result = subprocess.run(['ollama', 'list'], 
                              capture_output=True,
                              text=True,
                              timeout=10)
        
        if result.returncode == 0:
            print("\nInstalled models:")
            print(result.stdout)
            return True
        return False
    except:
        return False


def start_ollama_service():
    """Attempt to start Ollama service"""
    system = platform.system()
    
    if system == "Windows":
        print("\nStarting Ollama service...")
        try:
            # On Windows, Ollama runs as a service
            subprocess.Popen(['ollama', 'serve'], 
                           creationflags=subprocess.CREATE_NEW_CONSOLE)
            print("✓ Ollama service started")
            return True
        except:
            print("⚠ Could not start Ollama service. It may already be running.")
            return True
    
    elif system == "Linux":
        print("\nStarting Ollama service...")
        try:
            # Try systemd
            subprocess.run(['sudo', 'systemctl', 'start', 'ollama'], 
                         check=False)
            return True
        except:
            print("⚠ Could not start via systemd. Try running 'ollama serve' manually.")
            return True
    
    return True


def main():
    """Main setup function"""
    print("\n" + "="*70)
    print("CTI AGENTIC SYSTEM - OLLAMA SETUP")
    print("="*70 + "\n")
    
    # Step 1: Ensure Ollama is installed
    if not ensure_ollama():
        print("\n⚠ Please install Ollama and run this script again.")
        sys.exit(1)
    
    # Step 2: Start Ollama service
    start_ollama_service()
    
    # Small delay for service to start
    import time
    time.sleep(2)
    
    # Step 3: Check for models
    print("\nChecking for installed models...")
    has_models = list_models()
    
    # Step 4: Pull model if needed
    if not has_models or input("\nPull/update the 'mistral' model? (y/n): ").lower() == 'y':
        pull_model("mistral")
    
    print("\n" + "="*70)
    print("SETUP COMPLETE!")
    print("="*70)
    print("\nYou can now run the CTI system:")
    print("  python main.py\n")


if __name__ == "__main__":
    main()
