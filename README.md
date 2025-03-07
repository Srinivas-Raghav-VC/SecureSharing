# SecureSharing: Digital Privacy and Secure Communication
## HackoonaMatata 2025 Final Submission

### 🚀 Overview  
SecureSharing is a privacy-focused file-sharing application that ensures secure communication using encryption and optional malware scanning. It integrates **VirusTotal API** for threat detection and **SendMe (built on IROH)** for secure file transfer.

---

## 🔐 Features  
- **Secure File Sharing:** Encrypts and transfers files securely.  
- **Optional Malware Check:** Uses **VirusTotal API** to verify file safety.  
- **Encrypted Ticket & Password:** Ensures privacy and security.  
- **Personal Communication Channel:** Avoids Man-in-the-Middle Attacks.  
- **User-Friendly UI:** Simple and intuitive experience for both sender and receiver.  

---

## 📜 Workflow Diagram  
```mermaid
flowchart TD
    A["Sender - Initiates File Sharing"] --> B["Optional Malware Scan - VirusTotal API"]
    B --> C["SendMe (IROH) - Generates Encrypted Ticket & Password"]
    C --> D["Encrypted Ticket Sent to Receiver"]
    C --> E["Password Stored in Secure Personal Space"]
    D --> F["Receiver - Enters Encrypted Ticket"]
    E --> F["Receiver - Retrieves Password"]
    F --> G["File Browser - Securely Access & Save File"]
