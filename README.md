PII VAULT – SECURE ENCRYPTION/DECRYPTION API
(README DOCUMENTATION)
 OVERVIEW
PII Vault is a secure AES-256 encrypted API service built using Flask and MySQL. It
provides fast, safe encryption and decryption of sensitive data and includes a builtin load testing panel.
 FEATURES
AES-256 encryption/decryption
MySQL connection pooling
REST APIs
Load testing interface
CORS enabled
Robust error handling
Stateless architecture
 PROJECT STRUCTURE
/project-root
├── app.py
├── utils/
│ ├── crypto.py
│ ├── db.py
│ ├── helpers.py
├── loadtest/
│ ├── index.html
│ ├── load.js
├── requirements.txt
└── README.md
•
•
•
•
•
•
•
🛠 SETUP INSTRUCTIONS
CLONE REPO
git clone https://github.com/srj1304/encryption_api
INSTALL DEPENDENCIES
pip install -r requirements.txt
CONFIGURE .ENV
DB_HOST=localhost
DB_USER=root
DB_PASS=yourpassword
DB_NAME=pii_vault
AES_KEY=0123456789abcdef0123456789abcdef
RUN APP
python app.py
 API USAGE
ENCRYPT (POST)
/encrypt
DECRYPT (GET)
/decrypt?data=XYZ
 LOAD TESTING
Open:
loadtest/index.html
 ARCHITECTURE OVERVIEW
Client → Encrypt API → AES → Base64 → Response
Client → Decrypt API → Base64 → AES → JSON → Response
🛡 SECURITY MEASURES
AES-256-CBC
IV generation per request
Sanitized input
Error masking
No logger leakage
 TROUBLESHOOTING
Padding errors: check AES key
•
•
•
•
•
•
MySQL errors: verify connection
CORS issues: update CORS policy
 DEPLOYMENT
Docker & Gunicorn supported.
AUTHOR
Suraj Mishra
Full Stack Developer
•
• 
