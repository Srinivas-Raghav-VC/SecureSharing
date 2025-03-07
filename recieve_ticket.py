import base64
import hashlib
import argparse
import subprocess
import os
import sys
import time
import platform
from cryptography.fernet import Fernet

def decrypt_ticket(encrypted_ticket, password):
    """Decrypt a sendme ticket using the provided password."""
    try:
        # Generate key from password
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
        cipher_suite = Fernet(key)
        
        # Decrypt the ticket
        decrypted_ticket = cipher_suite.decrypt(encrypted_ticket.encode()).decode()
        return decrypted_ticket
    except Exception as e:
        print(f"Error decrypting ticket: {e}")
        return None

def receive_file(ticket, destination_dir=None):
    """Receive a file using a decrypted ticket"""
    if not ticket:
        print("No valid ticket provided.")
        return False
        
    try:
        # Create destination directory if specified and doesn't exist
        if destination_dir and not os.path.exists(destination_dir):
            os.makedirs(destination_dir)
            print(f"Created directory: {destination_dir}")
        
        # Change to destination directory if specified
        original_dir = os.getcwd()
        if destination_dir:
            os.chdir(destination_dir)
            print(f"Changed to directory: {destination_dir}")
        
        # Run sendme receive command
        cmd = ["sendme", "receive", ticket]
        print(f"Running command: {' '.join(cmd)}")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            universal_newlines=True
        )
        
        # Print output in real-time
        for line in process.stdout:
            print(line.strip())
            
        # Wait for process to complete
        process.wait()
        
        # Change back to original directory
        if destination_dir:
            os.chdir(original_dir)
        
        # Check result
        if process.returncode != 0:
            print("Failed to receive file.")
            error_output = process.stderr.read()
            print(f"Error: {error_output}")
            return False
            
        print("File received successfully!")
        return True
        
    except Exception as e:
        print(f"Error receiving file: {e}")
        return False
        
def display_menu():
    """Display main menu options"""
    print("\n===== SECURE FILE TRANSFER TOOL =====")
    print("1. Decrypt a ticket")
    print("2. Receive a file")
    print("3. Exit")
    print("====================================")
    
    while True:
        try:
            choice = int(input("Enter your choice (1-3): ").strip())
            if 1 <= choice <= 3:
                return choice
            print("Please enter a number between 1 and 3.")
        except ValueError:
            print("Please enter a valid number.")

def main():
    """Main function with interactive menu"""
    print("Secure File Transfer - Decryption and Receive Tool")
    
    # Check if command-line arguments were provided
    if len(sys.argv) > 1:
        # Use argparse for command-line mode
        parser = argparse.ArgumentParser(description="Secure file transfer decryption tool")
        subparsers = parser.add_subparsers(dest="command", help="Command to execute")
        
        # Decrypt command
        decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a ticket")
        decrypt_parser.add_argument("encrypted_ticket", help="The encrypted sendme ticket")
        decrypt_parser.add_argument("password", help="The password for decryption")
        
        # Receive command
        receive_parser = subparsers.add_parser("receive", help="Receive a file using a ticket")
        receive_parser.add_argument("ticket", help="The sendme ticket")
        receive_parser.add_argument("--destination", "-d", help="Destination directory")
        
        args = parser.parse_args()
        
        if args.command == "decrypt":
            decrypted = decrypt_ticket(args.encrypted_ticket, args.password)
            if decrypted:
                print("Successfully decrypted ticket!")
                print("\nUse this command to receive the file:")
                print(f"sendme receive {decrypted}")
        elif args.command == "receive":
            receive_file(args.ticket, args.destination)
        else:
            parser.print_help()
    else:
        # Interactive menu mode
        while True:
            choice = display_menu()
            
            if choice == 1:  # Decrypt
                encrypted_ticket = input("Enter encrypted ticket: ").strip()
                password = input("Enter password: ").strip()
                decrypted = decrypt_ticket(encrypted_ticket, password)
                
                if decrypted:
                    print("\nSuccessfully decrypted ticket!")
                    print(f"Decrypted ticket: {decrypted}")
                    save_ticket = input("Save decrypted ticket for later use? (y/n): ").strip().lower()
                    if save_ticket == 'y':
                        with open("decrypted_ticket.txt", "w") as f:
                            f.write(decrypted)
                        print(f"Ticket saved to {os.path.abspath('decrypted_ticket.txt')}")
                    
                    receive_now = input("Do you want to receive the file now? (y/n): ").strip().lower()
                    if receive_now == 'y':
                        destination = input("Enter destination directory (or leave empty for current directory): ").strip()
                        destination = destination if destination else None
                        receive_file(decrypted, destination)
                
            elif choice == 2:  # Receive
                ticket_source = input("Do you have a (1) decrypted ticket or (2) need to decrypt one? Enter 1 or 2: ").strip()
                
                ticket = None
                if ticket_source == '1':
                    ticket = input("Enter the decrypted ticket: ").strip()
                elif ticket_source == '2':
                    encrypted_ticket = input("Enter encrypted ticket: ").strip()
                    password = input("Enter password: ").strip()
                    ticket = decrypt_ticket(encrypted_ticket, password)
                else:
                    print("Invalid option. Please try again.")
                    continue
                
                if ticket:
                    destination = input("Enter destination directory (or leave empty for current directory): ").strip()
                    destination = destination if destination else None
                    receive_file(ticket, destination)
                    
            elif choice == 3:  # Exit
                print("Goodbye!")
                break

if __name__ == "__main__":
    main()