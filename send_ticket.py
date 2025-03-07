import requests
import argparse
import time
import subprocess
import os
import platform
import sys
import hashlib
import random
import base64
from cryptography.fernet import Fernet
import getpass

# --- Configuration ---
# IMPORTANT: Replace with your VALID VirusTotal API key
VIRUSTOTAL_API_KEY = "a0b8a83824852f221c6a3ba0559316ba457b1c3a73b75bade4b4bb55470192f4"  
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files"
VIRUSTOTAL_SCAN_URL = "https://www.virustotal.com/api/v3/analyses/{}"
VIRUSTOTAL_RATE_LIMIT_DELAY = 15
VIRUSTOTAL_DETECTION_THRESHOLD = 1  # Number of malicious detections to consider a file risky

def validate_api_key(api_key):
    """Validate VirusTotal API key before use."""
    if api_key == "YOUR_VIRUSTOTAL_API_KEY" or not api_key:
        print("Error: Invalid VirusTotal API key. Please replace 'YOUR_VIRUSTOTAL_API_KEY' with a valid key.")
        return False
    return True

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    import hashlib
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_file_virustotal(file_path):
    """Uploads a file to VirusTotal or fetches existing report."""
    if not validate_api_key(VIRUSTOTAL_API_KEY):
        return None

    try:
        # First calculate the file hash
        file_hash = calculate_file_hash(file_path)
        
        # Try to get existing report by file hash
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            print(f"File already analyzed by VirusTotal. Using existing report.")
            # We need the analysis ID, not the file ID, to get the report
            last_analysis_id = response.json().get("data", {}).get("attributes", {}).get("last_analysis_id")
            if last_analysis_id:
                return last_analysis_id
        
        # If no existing report or can't get analysis ID, upload file
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(VIRUSTOTAL_API_URL, files=files, headers=headers)
            
            # Detailed error handling
            if response.status_code == 401:
                print("VirusTotal API Error: Unauthorized. Check your API key.")
                return None
            elif response.status_code == 429:
                print("VirusTotal API Error: Rate limit exceeded. Try again later.")
                return None
            elif response.status_code == 409:
                print("File already exists in VirusTotal. Fetching report...")
                # Use the previous method to get analysis ID
                return scan_file_virustotal(file_path)
            
            response.raise_for_status()
            return response.json()["data"]["id"]
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal Request Error: {e}")
        return None
    except (KeyError, requests.exceptions.JSONDecodeError) as e:
        print(f"VirusTotal Response Parsing Error: {e}")
        return None
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

def get_virustotal_report(scan_id):
    """Retrieves the VirusTotal scan report."""
    if not validate_api_key(VIRUSTOTAL_API_KEY):
        return -1

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = VIRUSTOTAL_SCAN_URL.format(scan_id)
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_response = response.json()

        status = json_response.get("data", {}).get("attributes", {}).get("status")
        if status != "completed":
            print(f"Analysis status: {status}. Waiting for completion...")
            return -1

        # Detailed statistics
        stats = json_response.get("data", {}).get("attributes", {}).get("stats", {})
        print("\n--- VirusTotal Scan Results ---")
        for key, value in stats.items():
            print(f"{key.capitalize()} detections: {value}")
        
        # Calculate total malicious detections
        malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
        print(f"Total potentially malicious detections: {malicious_count}")
        print("-----------------------------\n")

        return malicious_count
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal Report Retrieval Error: {e}")
        return -1
    except (KeyError, requests.exceptions.JSONDecodeError) as e:
        print(f"VirusTotal Report Parsing Error: {e}")
        return -1

def share_with_sendme(path):
    """
    Shares a file using sendme and captures the ticket.
    
    Args:
        path: The path to the file or directory to share.

    Returns:
        str: The sendme receive ticket, or None if sharing failed.
    """
    try:
        # Use full path to ensure correct file reference
        full_path = os.path.abspath(path)
        
        # Verify file/directory exists
        if not os.path.exists(full_path):
            print(f"Error: Path does not exist: {full_path}")
            return None

        # Capture the complete output of sendme send
        process = subprocess.Popen(
            ["sendme", "send", full_path], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True
        )

        # Variables to capture the ticket
        ticket = None
        file_details = None

        # Process output in real-time
        for line in process.stdout:
            # print(line.strip())  # Print the line
            
            # Look for the ticket line
            if line.strip().startswith("sendme receive"):
                # Extract only the blob part after "sendme receive "
                ticket_blob = line.strip().replace("sendme receive ", "")
                ticket = ticket_blob  # Store only the blob part
                # print(f"DEBUG: Extracted ticket blob: {ticket}")  # Debug confirmation
                
                # Process ticket right here for immediate debugging
                print("\n===== SECURE FILE SHARING =====")
                print("Processing ticket for secure sharing...")
                
                try:
                    # Generate a secure random password
                    password = base64.urlsafe_b64encode(os.urandom(8)).decode()[:8]
                    
                    # Generate encryption key from password
                    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
                    cipher_suite = Fernet(key)
                    
                    # Encrypt the ticket
                    encrypted_ticket = cipher_suite.encrypt(ticket.encode()).decode()
                    print(f"Encrypted ticket: {encrypted_ticket}")
                    print(f"Password: {password}")
                    print("\nTo share with recipient, send them both the encrypted ticket and password separately.")
                    print("They will need to use the decrypt_ticket.py script to access the file.")
                    print("================================")
                except Exception as e:
                    print(f"ERROR during inline encryption: {e}")
                    print("Will try regular encryption after processing completes.")
            
            # Look for file import details
            if "imported file" in line:
                file_details = line.strip()

        # Wait for the process to complete but with a timeout
        try:
            process.wait(timeout=10)  # Add 10-second timeout
        except subprocess.TimeoutExpired:
            print("Sendme process timed out, but ticket was captured successfully.")
            # Force terminate the process if it's still running
            process.terminate()

        # If no ticket found, return None
        if not ticket:
            print("No sendme ticket generated.")
            return None

        return ticket

    except Exception as e:
        print(f"Error during sendme sharing: {e}")
        return None

def secure_share_with_sendme(path):
    # Get the original ticket
    ticket = share_with_sendme(path)
    
    if not ticket:
        return None
    
    try:
        # Generate a secure random password
        password = base64.urlsafe_b64encode(os.urandom(8)).decode()[:8]
        
        # Generate encryption key from password
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
        cipher_suite = Fernet(key)
        
        # Encrypt the ticket
        encrypted_ticket = cipher_suite.encrypt(ticket.encode()).decode()
        
        # Return both the encrypted ticket and password
        return {
            "encrypted_ticket": encrypted_ticket,
            "password": password
        }
    except Exception as e:
        print(f"\nERROR in secure sharing: {e}")
        print(f"Encryption failed. Returning original unencrypted ticket.")
        return {"encrypted_ticket": ticket, "password": None}

def main():
    """Main function with improved error handling."""
    # Check for correct argument count
    if len(sys.argv) < 2:
        print("Usage: python script.py <file_or_directory_path>")
        sys.exit(1)

    path = sys.argv[1]
    
    # Normalize path and check existence
    path = os.path.normpath(path)
    if not os.path.exists(path):
        print(f"Error: Path not found: {path}")
        sys.exit(1)

    # VirusTotal scan is only for files, not directories
    if os.path.isfile(path):
        print(f"Scanning file: {path}")
        
        # Ask if user wants to skip VirusTotal scan
        skip_vt = input("VirusTotal scans often get stuck in queue. Skip scanning? (y/n, default=y): ").lower().strip()
        if skip_vt != 'n':
            print("Skipping VirusTotal scan.")
        else:
            try:
                scan_id = scan_file_virustotal(path)
                
                if scan_id:
                    print(f"VirusTotal scan initiated. Scan ID: {scan_id}")
                    print("Waiting for VirusTotal analysis...")
                    time.sleep(VIRUSTOTAL_RATE_LIMIT_DELAY)

                    vt_positives = -1
                    retries = 3  # Reduce retries to avoid long waits
                    retry_delay = 20
                    
                    for retry in range(retries):
                        try:
                            print(f"Checking analysis status (attempts remaining: {retries-retry})...")
                            vt_positives = get_virustotal_report(scan_id)
                            
                            if vt_positives != -1:
                                print("Analysis complete!")
                                break
                                
                            print(f"Analysis not ready yet. Waiting {retry_delay} seconds before retrying...")
                            time.sleep(retry_delay)
                        except Exception as e:
                            print(f"Error checking scan status: {e}")
                            time.sleep(retry_delay)
                    
                    if vt_positives == -1:
                        print("Failed to retrieve VirusTotal Report after multiple attempts.")
                        print(f"You can check manually later at: https://www.virustotal.com/gui/file/{calculate_file_hash(path)}")
                        
                        # Ask user if they want to continue anyway
                        proceed = input("Continue with file sharing anyway? (y/n): ").lower().strip()
                        if proceed != 'y':
                            print("Aborting operation.")
                            sys.exit(1)
            except Exception as e:
                print(f"Error during VirusTotal scanning: {e}")
                proceed = input("Continue with file sharing anyway? (y/n): ").lower().strip()
                if proceed != 'y':
                    print("Aborting operation.")
                    sys.exit(1)
    
    # Share the file with enhanced security
    result = secure_share_with_sendme(path)
    
    if not result:
        print("Failed to share the file.")
        sys.exit(1)
    
    print("\n===== SECURE FILE SHARING =====")
    if result["password"]:
        print("Your file has been securely shared!")
        print(f"\nEncrypted ticket: {result['encrypted_ticket']}")
        print(f"Password: {result['password']}")
        print("\nTo share with recipient, send them both the encrypted ticket and password separately.")
        print("They will need to use the decrypt_ticket.py script to access the file.")
    else:
        print("File shared with basic security (no encryption):")
        print(f"Ticket: {result['encrypted_ticket']}")
    print("================================")

if __name__ == "__main__":
    main()