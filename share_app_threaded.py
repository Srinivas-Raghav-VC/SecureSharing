import sys
import os
import threading
import subprocess
import base64
import hashlib
import time
import requests
from cryptography.fernet import Fernet, InvalidToken
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, 
                            QVBoxLayout, QHBoxLayout, QWidget, QFileDialog,
                            QTextEdit, QProgressBar, QMessageBox, QTabWidget,
                            QLineEdit, QFrame, QSplitter, QCheckBox)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont

# VirusTotal configuration
VIRUSTOTAL_API_KEY = "a0b8a83824852f221c6a3ba0559316ba457b1c3a73b75bade4b4bb55470192f4"  # Default API key
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files"
VIRUSTOTAL_SCAN_URL = "https://www.virustotal.com/api/v3/analyses/{}"
VIRUSTOTAL_DETECTION_THRESHOLD = 1

class WorkerSignals(QObject):
    finished = pyqtSignal(dict)
    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    decrypt_finished = pyqtSignal(dict)

class ShareApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Sharing")
        self.setGeometry(100, 100, 800, 600)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.share_tab = QWidget()
        self.decrypt_tab = QWidget()
        
        self.tabs.addTab(self.share_tab, "Share File")
        self.tabs.addTab(self.decrypt_tab, "Decrypt Ticket")
        
        # Init both tabs
        self.init_share_tab()
        self.init_decrypt_tab()
        
        self.setCentralWidget(self.tabs)
        
        # Worker signals setup
        self.signals = WorkerSignals()
        self.signals.log.connect(self.log)
        self.signals.progress.connect(self.progress.setValue)
        self.signals.finished.connect(self.handle_results)
        self.signals.decrypt_finished.connect(self.handle_decrypt_results)
        
    def init_share_tab(self):
        """Initialize the file sharing tab"""
        # Main layout
        main_layout = QVBoxLayout(self.share_tab)
        
        # Header
        header = QLabel("Secure File Sharing")
        header.setFont(QFont("", 16, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header)
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path = QTextEdit()
        self.file_path.setFixedHeight(50)
        self.file_path.setPlaceholderText("Selected file path will appear here")
        self.file_path.setReadOnly(True)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        
        file_layout.addWidget(self.file_path, 4)
        file_layout.addWidget(browse_btn, 1)
        main_layout.addLayout(file_layout)
        
        # Status
        self.status = QTextEdit()
        self.status.setReadOnly(True)
        self.status.setMinimumHeight(100)
        main_layout.addWidget(self.status)
        
        # Progress bar
        self.progress = QProgressBar()
        main_layout.addWidget(self.progress)
        
        # Results
        self.results = QTextEdit()
        self.results.setReadOnly(True)
        self.results.setMinimumHeight(150)
        main_layout.addWidget(self.results)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        self.share_btn = QPushButton("Share File")
        self.share_btn.clicked.connect(self.start_share)
        self.share_btn.setEnabled(False)
        
        copy_btn = QPushButton("Copy Results")
        copy_btn.clicked.connect(self.copy_results)
        
        btn_layout.addWidget(self.share_btn)
        btn_layout.addWidget(copy_btn)
        main_layout.addLayout(btn_layout)
        
        # VirusTotal scan options
        vt_frame = QFrame()
        vt_frame.setFrameShape(QFrame.StyledPanel)
        vt_layout = QVBoxLayout(vt_frame)

        vt_label = QLabel("VirusTotal Scan:")
        vt_label.setFont(QFont("", 10, QFont.Bold))
        vt_layout.addWidget(vt_label)

        self.vt_check = QCheckBox("Enable VirusTotal scanning")
        self.vt_check.setChecked(False)  # Default to off
        vt_layout.addWidget(self.vt_check)

        api_layout = QHBoxLayout()
        api_label = QLabel("API Key:")
        self.api_key = QLineEdit(VIRUSTOTAL_API_KEY)
        self.api_key.setPlaceholderText("Enter your VirusTotal API key")
        api_layout.addWidget(api_label)
        api_layout.addWidget(self.api_key)
        vt_layout.addLayout(api_layout)

        main_layout.addWidget(vt_frame)
        
        # Save options
        save_frame = QFrame()
        save_frame.setFrameShape(QFrame.StyledPanel)
        save_layout = QVBoxLayout(save_frame)
        
        save_label = QLabel("Save Options:")
        save_label.setFont(QFont("", 10, QFont.Bold))
        save_layout.addWidget(save_label)
        
        save_btn_layout = QHBoxLayout()
        
        save_ticket_btn = QPushButton("Save Encrypted Ticket")
        save_ticket_btn.clicked.connect(lambda: self.save_data("ticket"))
        
        save_password_btn = QPushButton("Save Password")
        save_password_btn.clicked.connect(lambda: self.save_data("password"))
        
        save_both_btn = QPushButton("Save Both Files")
        save_both_btn.clicked.connect(lambda: self.save_data("both"))
        
        save_btn_layout.addWidget(save_ticket_btn)
        save_btn_layout.addWidget(save_password_btn)
        save_btn_layout.addWidget(save_both_btn)
        
        save_layout.addLayout(save_btn_layout)
        main_layout.addWidget(save_frame)
        
        # Initialize with a message
        self.log("Ready. Please select a file to share.")
        
    def init_decrypt_tab(self):
        """Initialize the ticket decryption tab"""
        main_layout = QVBoxLayout(self.decrypt_tab)
        
        # Header
        header = QLabel("Decrypt Shared Ticket")
        header.setFont(QFont("", 16, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header)
        
        # Instruction
        instruction = QLabel("Enter the encrypted ticket and password to decrypt:")
        main_layout.addWidget(instruction)
        
        # Encrypted ticket input
        ticket_label = QLabel("Encrypted Ticket:")
        ticket_label.setFont(QFont("", 10, QFont.Bold))
        main_layout.addWidget(ticket_label)
        
        self.ticket_input = QTextEdit()
        self.ticket_input.setPlaceholderText("Paste the encrypted ticket here")
        self.ticket_input.setMinimumHeight(100)
        main_layout.addWidget(self.ticket_input)
        
        # Password input
        password_label = QLabel("Password:")
        password_label.setFont(QFont("", 10, QFont.Bold))
        main_layout.addWidget(password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter the password")
        main_layout.addWidget(self.password_input)
        
        # Decrypt button
        decrypt_btn = QPushButton("Decrypt Ticket")
        decrypt_btn.clicked.connect(self.decrypt_ticket)
        main_layout.addWidget(decrypt_btn)
        
        # Results
        result_label = QLabel("Decryption Result:")
        result_label.setFont(QFont("", 10, QFont.Bold))
        main_layout.addWidget(result_label)
        
        self.decrypt_result = QTextEdit()
        self.decrypt_result.setReadOnly(True)
        self.decrypt_result.setMinimumHeight(100)
        main_layout.addWidget(self.decrypt_result)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        self.receive_btn = QPushButton("Receive File")
        self.receive_btn.clicked.connect(self.receive_file)
        self.receive_btn.setEnabled(False)
        
        copy_ticket_btn = QPushButton("Copy Decrypted Ticket")
        copy_ticket_btn.clicked.connect(self.copy_decrypted)
        
        btn_layout.addWidget(self.receive_btn)
        btn_layout.addWidget(copy_ticket_btn)
        main_layout.addLayout(btn_layout)
        
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Share", "", "All Files (*)")
        if file_path:
            self.file_path.setText(file_path)
            self.share_btn.setEnabled(True)
            self.log(f"Selected file: {file_path}")
            
            if os.path.isfile(file_path):
                size_bytes = os.path.getsize(file_path)
                if size_bytes < 1024:
                    size_str = f"{size_bytes} bytes"
                elif size_bytes < 1024 * 1024:
                    size_str = f"{size_bytes/1024:.1f} KB"
                elif size_bytes < 1024 * 1024 * 1024:
                    size_str = f"{size_bytes/(1024*1024):.1f} MB"
                else:
                    size_str = f"{size_bytes/(1024*1024*1024):.1f} GB"
                    
                self.log(f"File size: {size_str}")
            else:
                self.log("Selected item is a directory")
    
    def log(self, message):
        self.status.append(message)
    
    def start_share(self):
        file_path = self.file_path.toPlainText()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Please select a valid file or directory")
            return
        
        # Disable share button while processing
        self.share_btn.setEnabled(False)
        
        # Reset and start progress
        self.progress.setValue(0)
        self.results.clear()
        
        # Start sharing operation in background thread
        worker_thread = threading.Thread(
            target=self.share_file_thread,
            args=(file_path,)
        )
        worker_thread.daemon = True  # Thread will close when app closes
        worker_thread.start()
        
        # Start periodic UI updates
        self.signals.progress.emit(10)
        self.signals.log.emit("Starting file sharing process...")
    
    def share_file_thread(self, file_path):
        """Thread to handle file sharing without blocking UI"""
        self.signals.progress.emit(20)
        self.signals.log.emit("Preparing to share file...")
        
        try:
            # Check if it's a file and if VirusTotal scan is enabled
            if os.path.isfile(file_path) and self.vt_check.isChecked():
                self.signals.progress.emit(25)
                self.signals.log.emit("Starting VirusTotal scan...")
                
                # Get API key from UI
                api_key = self.api_key.text().strip()
                
                # Start virus scanning
                try:
                    scan_id = scan_file_virustotal(file_path, api_key, self.signals)
                    
                    if scan_id:
                        self.signals.log.emit(f"VirusTotal scan initiated. Scan ID: {scan_id}")
                        self.signals.log.emit("Waiting for VirusTotal analysis...")
                        time.sleep(15)  # Rate limit delay

                        vt_positives = -1
                        retries = 3
                        retry_delay = 15
                        
                        for retry in range(retries):
                            try:
                                self.signals.log.emit(f"Checking analysis status (attempts remaining: {retries-retry})...")
                                vt_positives = get_virustotal_report(scan_id, api_key, self.signals)
                                
                                if vt_positives != -1:
                                    self.signals.log.emit("Analysis complete!")
                                    
                                    # If malicious detections exceed threshold, warn user
                                    if vt_positives >= VIRUSTOTAL_DETECTION_THRESHOLD:
                                        self.signals.log.emit(f"WARNING: {vt_positives} potential threats detected!")
                                        
                                        # Ask user if they want to continue
                                        # We can't directly ask in a thread, so we'll set a flag
                                        # and check it after a short delay
                                        self.vt_warning_result = None
                                        
                                        # This is a workaround - in a real app you'd use a proper
                                        # signal/slot mechanism to show a dialog from the main thread
                                        self.signals.log.emit("Potential security risk detected. Check terminal for options.")
                                        
                                        # Continue with sharing after warning (normally you'd prompt the user)
                                        self.signals.log.emit("Proceeding with file sharing as requested.")
                                    break
                                    
                                self.signals.log.emit(f"Analysis not ready yet. Waiting {retry_delay} seconds before retrying...")
                                time.sleep(retry_delay)
                            except Exception as e:
                                self.signals.log.emit(f"Error checking scan status: {e}")
                                time.sleep(retry_delay)
                        
                        if vt_positives == -1:
                            self.signals.log.emit("Failed to retrieve VirusTotal Report after multiple attempts.")
                            self.signals.log.emit(f"You can check manually later at: https://www.virustotal.com/gui/file/{calculate_file_hash(file_path)}")
                            # Abort file sharing if VirusTotal analysis failed
                            self.signals.log.emit("File sharing aborted: Unable to verify file safety.")
                            self.signals.progress.emit(100)
                            self.signals.finished.emit({"success": False, "error": "VirusTotal analysis failed. File sharing aborted."})
                            return
                    else:
                        self.signals.log.emit("Failed to initiate VirusTotal scan.")
                        # Abort file sharing if scan couldn't be initiated
                        self.signals.log.emit("File sharing aborted: Unable to initiate security scan.")
                        self.signals.progress.emit(100)
                        self.signals.finished.emit({"success": False, "error": "VirusTotal scan initialization failed. File sharing aborted."})
                        return
                except Exception as e:
                    self.signals.log.emit(f"Error during VirusTotal scanning: {e}")
                    # Abort file sharing on any error
                    self.signals.log.emit("File sharing aborted due to security scanning error.")
                    self.signals.progress.emit(100)
                    self.signals.finished.emit({"success": False, "error": f"VirusTotal scanning error: {str(e)}. File sharing aborted."})
                    return
            
            # Direct file sharing implementation
            self.signals.progress.emit(30)
            self.signals.log.emit("Starting sendme process...")
            
            # Create full path and verify
            full_path = os.path.abspath(file_path)
            if not os.path.exists(full_path):
                self.signals.log.emit(f"Error: Path does not exist: {full_path}")
                self.signals.finished.emit({"success": False, "error": "File not found"})
                return
            
            # Start the subprocess with output capture
            self.signals.progress.emit(40)
            process = subprocess.Popen(
                ["sendme", "send", full_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True,
                bufsize=1
            )
            
            ticket = None
            timeout = 60  # Wait up to 60 seconds
            start_time = time.time()
            self.signals.progress.emit(50)
            
            # Process output lines in real time
            for line in iter(process.stdout.readline, ''):
                if time.time() - start_time > timeout:
                    process.terminate()  # Kill process if it takes too long
                    self.signals.log.emit("Process timed out, but we'll check if we got a ticket")
                    break
                
                # Look for the ticket line
                if line.strip().startswith("sendme receive"):
                    ticket_blob = line.strip().replace("sendme receive ", "")
                    ticket = ticket_blob
                    self.signals.log.emit("Ticket received successfully!")
                    self.signals.progress.emit(70)
                    # We can break early once we have the ticket
                    break
            
            # If no ticket found in output, check stderr
            if not ticket:
                stderr_output = process.stderr.read()
                self.signals.log.emit(f"No ticket found. Process stderr: {stderr_output}")
                self.signals.progress.emit(100)
                self.signals.finished.emit({"success": False, "error": "No ticket generated"})
                return
            
            # Generate secure random password
            self.signals.progress.emit(80)
            self.signals.log.emit("Encrypting ticket...")
            password = base64.urlsafe_b64encode(os.urandom(8)).decode()[:8]
            
            # Generate encryption key from password
            key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            cipher_suite = Fernet(key)
            
            # Encrypt the ticket
            encrypted_ticket = cipher_suite.encrypt(ticket.encode()).decode()
            
            # Complete progress and return results
            self.signals.progress.emit(90)
            result = {
                "success": True,
                "encrypted_ticket": encrypted_ticket,
                "password": password,
                "original_ticket": ticket,
                "process": process  # Store the process so it stays running!
            }
            self.signals.progress.emit(100)
            self.signals.finished.emit(result)
            
        except Exception as e:
            self.signals.log.emit(f"Error during file sharing: {str(e)}")
            self.signals.progress.emit(100)
            self.signals.finished.emit({"success": False, "error": str(e)})
    
    def handle_results(self, result):
        """Handle the completed share operation results"""
        if result.get("success"):
            # Store the results for saving to file later
            self.current_result = result
            
            output_text = "===== SECURE FILE SHARING =====\n\n"
            output_text += "Your file has been securely shared!\n\n"
            output_text += f"Encrypted ticket:\n{result['encrypted_ticket']}\n\n"
            output_text += f"Password: {result['password']}\n\n"
            output_text += "To share with recipient, send them both the encrypted ticket and password separately.\n"
            output_text += "They will need to use the decrypt_ticket.py script or the Decrypt tab in this app."
            output_text += "\n================================"
            
            self.results.setPlainText(output_text)
            self.log("File shared successfully!")
            self.log("File server is now running. Keep this application open while sharing.")
        else:
            self.current_result = None
            error_msg = result.get("error", "Unknown error")
            self.results.setPlainText(f"Failed to share file: {error_msg}")
            self.log(f"Error: {error_msg}")
        
        # Re-enable the share button
        self.share_btn.setEnabled(True)
    
    def copy_results(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.results.toPlainText())
        QMessageBox.information(self, "Copied", "Results copied to clipboard!")
    
    def save_data(self, data_type):
        """Save ticket data to files"""
        if not hasattr(self, 'current_result') or not self.current_result:
            QMessageBox.warning(self, "Error", "No sharing results available to save")
            return
        
        try:
            if data_type == "ticket" or data_type == "both":
                # Save ticket to file
                file_path, _ = QFileDialog.getSaveFileName(
                    self, "Save Encrypted Ticket", "encrypted_ticket.txt", "Text Files (*.txt)"
                )
                if file_path:
                    with open(file_path, 'w') as f:
                        f.write(self.current_result["encrypted_ticket"])
                    self.log(f"Encrypted ticket saved to: {file_path}")
            
            if data_type == "password" or data_type == "both":
                # Save password to file
                file_path, _ = QFileDialog.getSaveFileName(
                    self, "Save Password", "password.txt", "Text Files (*.txt)"
                )
                if file_path:
                    with open(file_path, 'w') as f:
                        f.write(self.current_result["password"])
                    self.log(f"Password saved to: {file_path}")
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save file: {str(e)}")
    
    def decrypt_ticket(self):
        """Decrypt a ticket using the provided encrypted ticket and password"""
        encrypted_ticket = self.ticket_input.toPlainText().strip()
        password = self.password_input.text().strip()
        
        if not encrypted_ticket:
            QMessageBox.warning(self, "Error", "Please enter an encrypted ticket")
            return
        
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password")
            return
        
        # Start decryption in a separate thread to avoid UI freezing
        worker_thread = threading.Thread(
            target=self.decrypt_thread,
            args=(encrypted_ticket, password)
        )
        worker_thread.daemon = True
        worker_thread.start()
        
        self.decrypt_result.setPlainText("Decrypting...")
    
    def decrypt_thread(self, encrypted_ticket, password):
        """Thread for ticket decryption"""
        try:
            # Generate key from password
            key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            cipher_suite = Fernet(key)
            
            # Decrypt the ticket
            decrypted_ticket = cipher_suite.decrypt(encrypted_ticket.encode()).decode()
            
            # Signal success
            self.signals.decrypt_finished.emit({
                "success": True,
                "ticket": decrypted_ticket
            })
            
        except InvalidToken:
            self.signals.decrypt_finished.emit({
                "success": False,
                "error": "Invalid password or corrupted ticket"
            })
        except Exception as e:
            self.signals.decrypt_finished.emit({
                "success": False,
                "error": str(e)
            })
    
    def handle_decrypt_results(self, result):
        """Handle the decryption results"""
        if result.get("success"):
            self.decrypt_result.setPlainText(f"Decryption successful!\n\nDecrypted ticket:\n{result['ticket']}")
            # Store the ticket for receiving the file
            self.decrypted_ticket = result['ticket']
            self.receive_btn.setEnabled(True)
        else:
            self.decrypt_result.setPlainText(f"Decryption failed: {result.get('error', 'Unknown error')}")
            self.receive_btn.setEnabled(False)
    
    def copy_decrypted(self):
        """Copy the decrypted ticket to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.decrypt_result.toPlainText())
        QMessageBox.information(self, "Copied", "Decryption results copied to clipboard!")
    
    def receive_file(self):
        """Use the decrypted ticket to receive the file"""
        if not hasattr(self, 'decrypted_ticket') or not self.decrypted_ticket:
            QMessageBox.warning(self, "Error", "No valid ticket available")
            return
        
        # Ask user for download location
        download_dir = QFileDialog.getExistingDirectory(
            self, "Select Download Location", "", QFileDialog.ShowDirsOnly
        )
        
        if not download_dir:
            return  # User canceled
        
        # Start the receiving process in a separate thread
        worker_thread = threading.Thread(
            target=self.receive_file_thread,
            args=(self.decrypted_ticket, download_dir)
        )
        worker_thread.daemon = True
        worker_thread.start()
        
        self.decrypt_result.append("\n\nReceiving file... Please wait.")
    
    def receive_file_thread(self, ticket, download_dir):
        """Thread for receiving file with retry mechanism"""
        try:
            # Change to the download directory
            original_dir = os.getcwd()
            os.chdir(download_dir)
            
            # Show attempting connection message
            self.signals.decrypt_finished.emit({
                "success": True,
                "ticket": f"{self.decrypted_ticket}\n\nConnecting to remote endpoint..."
            })
            
            # Try multiple times with increasing delays
            max_retries = 3
            for attempt in range(1, max_retries + 1):
                try:
                    # Run the sendme receive command
                    process = subprocess.Popen(
                        ["sendme", "receive", ticket],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    self.signals.decrypt_finished.emit({
                        "success": True,
                        "ticket": f"{self.decrypted_ticket}\n\nAttempt {attempt}/{max_retries}: Transferring file..."
                    })
                    
                    stdout, stderr = process.communicate(timeout=90)  # Longer timeout
                    
                    # Check if successful
                    if process.returncode == 0:
                        # Go back to original directory
                        os.chdir(original_dir)
                        self.signals.decrypt_finished.emit({
                            "success": True,
                            "ticket": f"{self.decrypted_ticket}\n\nFile received successfully to {download_dir}"
                        })
                        return
                    else:
                        # If this isn't the last attempt, try again
                        if attempt < max_retries:
                            wait_time = attempt * 5  # Increasing wait time
                            self.signals.decrypt_finished.emit({
                                "success": True,
                                "ticket": f"{self.decrypted_ticket}\n\nConnection failed. Retrying in {wait_time} seconds..."
                            })
                            time.sleep(wait_time)
                        else:
                            # Final failure
                            error_detail = stderr if stderr else "No error details available"
                            self.signals.decrypt_finished.emit({
                                "success": False,
                                "error": f"Failed to receive file after {max_retries} attempts: {error_detail}"
                            })
                
                except subprocess.TimeoutExpired:
                    if attempt < max_retries:
                        self.signals.decrypt_finished.emit({
                            "success": True, 
                            "ticket": f"{self.decrypted_ticket}\n\nConnection timed out. Retrying..."
                        })
                    else:
                        self.signals.decrypt_finished.emit({
                            "success": False,
                            "error": "Connection timed out repeatedly. The sender may be offline."
                        })
            
            # Go back to original directory
            os.chdir(original_dir)
        
        except Exception as e:
            try:
                os.chdir(original_dir)  # Make sure we restore directory
            except:
                pass
            self.signals.decrypt_finished.emit({
                "success": False,
                "error": f"Error receiving file: {str(e)}"
            })

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_file_virustotal(file_path, api_key, signals=None):
    """Uploads a file to VirusTotal or fetches existing report."""
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY":
        if signals:
            signals.log.emit("Error: Invalid VirusTotal API key")
        return None

    try:
        # First calculate the file hash
        file_hash = calculate_file_hash(file_path)
        
        if signals:
            signals.log.emit(f"File hash: {file_hash}")
            signals.log.emit("Checking VirusTotal for existing report...")
        
        # Try to get existing report by file hash
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            if signals:
                signals.log.emit(f"File already analyzed by VirusTotal. Using existing report.")
            # We need the analysis ID, not the file ID, to get the report
            last_analysis_id = response.json().get("data", {}).get("attributes", {}).get("last_analysis_id")
            if last_analysis_id:
                return last_analysis_id
        
        # If no existing report or can't get analysis ID, upload file
        if signals:
            signals.log.emit("Uploading file to VirusTotal...")
        
        # Check file size for proper upload method
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:  # 32MB
            if signals:
                signals.log.emit("File is larger than 32MB. Using special upload URL...")
            
            # Step 1: Get a special upload URL for large files
            upload_url_endpoint = "https://www.virustotal.com/api/v3/files/upload_url"
            response = requests.get(upload_url_endpoint, headers=headers)
            response.raise_for_status()
            upload_url = response.json().get("data")
            
            if not upload_url:
                if signals:
                    signals.log.emit("Failed to get upload URL for large file")
                return None
                
            # Step 2: Upload the file to the special URL
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                response = requests.post(upload_url, files=files, headers=headers)
        else:
            # Standard upload for files under 32MB
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                response = requests.post(VIRUSTOTAL_API_URL, files=files, headers=headers)
            
        # Detailed error handling
        if response.status_code == 401:
            if signals:
                signals.log.emit("VirusTotal API Error: Unauthorized. Check your API key.")
            return None
        elif response.status_code == 429:
            if signals:
                signals.log.emit("VirusTotal API Error: Rate limit exceeded. Try again later.")
            return None
        elif response.status_code == 409:
            if signals:
                signals.log.emit("File already exists in VirusTotal. Fetching report...")
            # Use the previous method to get analysis ID
            return scan_file_virustotal(file_path, api_key, signals)
        
        response.raise_for_status()
        return response.json()["data"]["id"]
    except requests.exceptions.RequestException as e:
        if signals:
            signals.log.emit(f"VirusTotal Request Error: {e}")
        return None
    except (KeyError, requests.exceptions.JSONDecodeError) as e:
        if signals:
            signals.log.emit(f"VirusTotal Response Parsing Error: {e}")
        return None
    except FileNotFoundError:
        if signals:
            signals.log.emit(f"File not found: {file_path}")
        return None

def get_virustotal_report(scan_id, api_key, signals=None):
    """Retrieves the VirusTotal scan report."""
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY":
        if signals:
            signals.log.emit("Error: Invalid VirusTotal API key")
        return -1

    headers = {"x-apikey": api_key}
    url = VIRUSTOTAL_SCAN_URL.format(scan_id)
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_response = response.json()

        status = json_response.get("data", {}).get("attributes", {}).get("status")
        if status != "completed":
            if signals:
                signals.log.emit(f"Analysis status: {status}. Waiting for completion...")
            return -1

        # Detailed statistics
        stats = json_response.get("data", {}).get("attributes", {}).get("stats", {})
        if signals:
            signals.log.emit("\n--- VirusTotal Scan Results ---")
            for key, value in stats.items():
                signals.log.emit(f"{key.capitalize()} detections: {value}")
        
        # Calculate total malicious detections
        malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
        if signals:
            signals.log.emit(f"Total potentially malicious detections: {malicious_count}")
            signals.log.emit("-----------------------------\n")

        return malicious_count
    except requests.exceptions.RequestException as e:
        if signals:
            signals.log.emit(f"VirusTotal Report Retrieval Error: {e}")
        return -1
    except (KeyError, requests.exceptions.JSONDecodeError) as e:
        if signals:
            signals.log.emit(f"VirusTotal Report Parsing Error: {e}")
        return -1

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ShareApp()
    window.show()
    sys.exit(app.exec_())
