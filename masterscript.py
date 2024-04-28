import psgscript
import pwgscript
import pwpsch
import sys
import os
import secrets
import ctypes

def secure_exit():
    """
    Securely clears sensitive data and exits the program.
    """
    # Clear the screen to prevent any sensitive data from being visible
    if sys.platform.startswith('win'):
        ctypes.windll.kernel32.GetModuleHandleW(None)
        ctypes.windll.kernel32.GetModuleHandleW.restype = ctypes.c_void_p
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
        sys.stdout.write("\033[H\033[J")
    
    # Generate a random sequence of bytes to overwrite sensitive data in memory
    num_bytes = 1024
    overwrite_data = secrets.token_bytes(num_bytes)
    
    # Securely overwrite sensitive data in memory
    sensitive_data_ptr = ctypes.cast(id(overwrite_data), ctypes.c_void_p)
    ctypes.memset(sensitive_data_ptr, 0, num_bytes)
    
    # Exit the program
    sys.exit(0)

# Update the main function to use secure_exit() for program termination
def main():
    while True:
        print("\nMenu:")
        print("1. Generate Passphrase\n")
        print("2. Generate Password\n")
        print("3. Check Password Strength\n")
        print("Press any other key to exit.\n")

        choice = input("Enter your choice: ")

        if choice == "1":
            psgscript.main()
            secure_exit() 
        elif choice == "2":
            pwgscript.main()
            secure_exit() 
        elif choice == "3":
            pwpsch.main()
            secure_exit() 
        else:
            print("\nExiting.")
            secure_exit()  # Use secure_exit() for program termination

if __name__ == "__main__":
    main()

# Clean up bytecode files after execution
if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
    # Running inside a virtual environment
    bytecode_dir = os.path.join(sys.prefix, 'lib', 'python' + sys.version[:3], '__pycache__')
else:
    # Running outside a virtual environment
    bytecode_dir = os.path.join(sys.prefix, 'lib', '__pycache__')

# Delete all bytecode files in the directory
for filename in os.listdir(bytecode_dir):
    if filename.endswith('.pyc'):
        os.remove(os.path.join(bytecode_dir, filename))