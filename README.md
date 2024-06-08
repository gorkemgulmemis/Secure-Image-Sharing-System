# Secure Image Sharing System

Introduction
The Secure Image Sharing System is a web-based application designed to allow users to securely upload and download images. The system employs strong cryptographic measures to ensure that only intended users can access the images. Additionally, it includes user authentication, logging, and message integrity verification features. This document provides a detailed description of the design choices, implementation specifics, potential security holes, and countermeasures associated with the project.

Design Choices and Security Features
User Registration and Login
Flask-Login
Where and Why Used:

server.py
Flask-Login is used to manage user sessions, ensuring that only authenticated users can access the system. It provides decorators and utility functions to handle user authentication and session management.
User Credentials
Where and Why Used:

server.py
During registration, users provide a username and password. These credentials are stored securely. Users must log in to access the system, ensuring that only authenticated users can perform actions like uploading or downloading images.
Image Encryption and Decryption
AES Encryption
Where and Why Used:

utils.py
Images are encrypted using AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode. This provides confidentiality for the images, ensuring that they cannot be viewed by unauthorized users. AES is a widely-used symmetric encryption algorithm known for its security and efficiency.
RSA Encryption for AES Key
Where and Why Used:

utils.py
The AES key used to encrypt the image is further encrypted using RSA public keys of the intended users. This ensures that only the intended recipients can decrypt the AES key and, consequently, the image. RSA is an asymmetric encryption algorithm that provides strong security for key exchange processes.
Digital Signatures
RSA Digital Signatures
Where and Why Used:

utils.py
Each encrypted image is signed using the uploader's RSA private key. This allows recipients to verify the integrity and authenticity of the image, ensuring that it has not been tampered with and confirming the identity of the uploader.
Message Authentication Code (MAC)
HMAC with SHA-256
Where and Why Used:

utils.py
To ensure the integrity and authenticity of messages (such as image upload notifications), we used HMAC (Hash-based Message Authentication Code) with the SHA-256 hash function. This prevents tampering and ensures that the messages have not been altered.
Logging
Python Logging Module
Where and Why Used:

server.py
All significant events (e.g., user registration, login, image upload, and download) are logged using Python's logging module. This provides an audit trail for system activities, which is useful for monitoring and debugging. Logs include timestamps and detailed descriptions of the events.
Implementation Details
Libraries Used
Flask: A lightweight web framework for building the web application.
Flask-Login: Manages user sessions and authentication, providing decorators and utilities to handle login-required routes.
PyCryptodome: Provides cryptographic functions such as AES and RSA encryption, HMAC, and digital signatures.
Logging: Python's built-in logging module for recording system events.
System Overview
User Registration:

Users register with a username and password.
RSA key pairs and a MAC key are generated for each user.
User credentials and keys are stored securely.
User Login:

Users log in with their credentials.
Flask-Login manages the session and user authentication.
Image Upload:

Logged-in users can upload images.
Images are encrypted using an AES key.
The AES key is encrypted with the RSA public keys of the intended recipients.
The encrypted image and metadata (digital signature, IV, encrypted AES keys) are stored.
Image Download:

Intended recipients can download the encrypted image.
The recipient decrypts the AES key using their RSA private key.
The image is decrypted using the AES key and IV.
The digital signature is verified to ensure the integrity and authenticity of the image.
