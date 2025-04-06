import * as forge from 'node-forge';

// Initialize WebsimSocket connection
const room = new WebsimSocket();

// The authorized public key (constant)
const AUTHORIZED_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuUDnEhVJVuQ43Or+coEv
4hqEFdwkWZk9ps1CZ5aI11OR06hD1bB9ugQYVD07YaR6zvHuK5D/zPgLWIQVmR1R
HFAv1a8x5+G2UbkTWgt17gqALpki2Kif4/lNghW7sWhDb0dwu/lHJjCsSPNlcZrg
Cy7DQFvmTa+9hSYCjTMlSRznc3SAjm9A814B4oAyiKkEiYHINWXZcpxsVRQ9ONKa
xXUfe5gtz03rk+/eCoaKMC58OhmpdoCT8uBeuYKmPS5hOTyDI0g0yH6iAh83TN4s
DtacoojYBqbPZRdR7OEEvxHYAEOC7HCsm2ulR4YHRAPZ4ZjMUoc3AVfvrvioZjkn
IQIDAQAB
-----END PUBLIC KEY-----`;

// DOM elements
const messageInput = document.getElementById('messageInput');
const privateKeyInput = document.getElementById('privateKeyInput');
const keyFileInput = document.getElementById('keyFileInput');
const signAndPostBtn = document.getElementById('signAndPostBtn');
const messagesList = document.getElementById('messagesList');
const statusMessage = document.getElementById('statusMessage');

// Event listeners
signAndPostBtn.addEventListener('click', signAndPostMessage);
keyFileInput.addEventListener('change', handleKeyFileUpload);

// Subscribe to message updates
room.collection('signedMessage').subscribe(displayMessages);

// Function to sign and post a message
async function signAndPostMessage() {
    const messageText = messageInput.value.trim();
    const privateKeyPEM = privateKeyInput.value.trim();
    
    if (!messageText) {
        setStatus('Please enter a message', 'error');
        return;
    }

    if (!privateKeyPEM) {
        setStatus('Please enter a private key', 'error');
        return;
    }

    try {
        // Try to sign the message, but always allow submission
        let signature = '';
        try {
            signature = signMessage(messageText, privateKeyPEM);
        } catch (error) {
            console.warn('Signing warning:', error);
            // Continue with empty signature if signing fails
        }
        
        // Create a signed message record
        await room.collection('signedMessage').create({
            text: messageText,
            signature: signature
        });
        
        // Clear the message input and show success
        messageInput.value = '';
        setStatus('Message posted successfully', 'success');
        
    } catch (error) {
        console.error('Error posting message:', error);
        setStatus('Error: ' + error.message, 'error');
    }
}

// Function to sign a message using a private key
function signMessage(message, privateKeyPEM) {
    try {
        // Parse the private key
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPEM);
        
        // Create message digest
        const md = forge.md.sha256.create();
        md.update(message, 'utf8');
        
        // Sign the digest
        const signature = privateKey.sign(md);
        
        // Convert to base64 for storage
        return forge.util.encode64(signature);
    } catch (error) {
        console.error('Signing error:', error);
        throw error;
    }
}

// Function to verify a signature using the authorized public key
function verifySignature(message, signature) {
    try {
        // Parse the public key
        const publicKey = forge.pki.publicKeyFromPem(AUTHORIZED_PUBLIC_KEY);
        
        // Create message digest
        const md = forge.md.sha256.create();
        md.update(message, 'utf8');
        
        // Decode the signature from base64
        const decodedSignature = forge.util.decode64(signature);
        
        // Verify the signature
        return publicKey.verify(md.digest().bytes(), decodedSignature);
    } catch (error) {
        console.error('Verification error:', error);
        return false;
    }
}

// Function to display messages
function displayMessages(messages) {
    // Sort messages with newest first
    const sortedMessages = [...messages].reverse();
    
    // Clear existing messages
    messagesList.innerHTML = '';
    
    if (sortedMessages.length === 0) {
        messagesList.innerHTML = '<p class="text-center">No messages yet. Be the first to post!</p>';
        return;
    }
    
    // Display each message
    sortedMessages.forEach(message => {
        // Verify the signature
        const isValid = verifySignature(message.text, message.signature);
        
        // Create message element
        const messageElement = document.createElement('div');
        messageElement.className = `message ${isValid ? 'valid' : 'invalid'}`;
        
        const timestamp = new Date(message.created_at).toLocaleString();
        
        messageElement.innerHTML = `
            <div class="message-header">
                <span>From: ${message.username}</span>
                <span>${timestamp}</span>
            </div>
            <div class="message-content">${escapeHTML(message.text)}</div>
            <div class="validation-status ${isValid ? 'valid-signature' : 'invalid-signature'}">
                Signature: ${isValid ? 'VALID ✓' : 'INVALID ✗'}
            </div>
        `;
        
        messagesList.appendChild(messageElement);
    });
}

// Helper function to set status message
function setStatus(message, type) {
    statusMessage.textContent = message;
    statusMessage.style.color = type === 'error' ? '#e63946' : '#2a9d8f';
    
    // Clear status after 3 seconds
    setTimeout(() => {
        statusMessage.textContent = '';
    }, 3000);
}

// Helper function to escape HTML to prevent XSS
function escapeHTML(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Function to handle key file upload
function handleKeyFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = function(e) {
        privateKeyInput.value = e.target.result;
        setStatus('Key file loaded successfully', 'success');
    };
    reader.onerror = function() {
        setStatus('Error reading key file', 'error');
    };
    reader.readAsText(file);
}