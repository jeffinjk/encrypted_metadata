from flask import Flask, request, jsonify, send_file, make_response
from flask_cors import CORS
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from Crypto.Cipher import AES
import hashlib
import secrets
import os
import base64
from PIL import Image
import numpy as np
import io
import json
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB file size limit
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'tiff', 'webp'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --------------------------
# Improved BB84 simulation
# --------------------------
def bb84_key(n_bits=512):
    # Generate random bits and bases for Alice using cryptographically secure RNG
    alice_bits = [secrets.randbelow(2) for _ in range(n_bits)]
    alice_bases = [secrets.randbelow(2) for _ in range(n_bits)]
    
    # Bob chooses random bases
    bob_bases = [secrets.randbelow(2) for _ in range(n_bits)]
    bob_bits = []
    
    backend = AerSimulator()
    
    for i in range(n_bits):
        qc = QuantumCircuit(1, 1)
        
        # Alice prepares qubit
        if alice_bits[i] == 1:
            qc.x(0)
        if alice_bases[i] == 1:  # Hadamard basis
            qc.h(0)
        
        # Bob measures
        if bob_bases[i] == 1:  # Hadamard basis
            qc.h(0)
        qc.measure(0, 0)
        
        # Execute simulation
        job = backend.run(qc, shots=1, memory=True)
        result = job.result()
        memory = result.get_memory()
        bob_bit = int(memory[0])
        bob_bits.append(bob_bit)
    
    # Sift the key - keep only bits where bases match
    sifted_key = []
    for i in range(n_bits):
        if alice_bases[i] == bob_bases[i]:
            sifted_key.append(alice_bits[i])
    
    # Ensure we have enough bits for AES key
    if len(sifted_key) < 256:
        # Pad with zeros if needed (in practice, you'd want to handle this differently)
        sifted_key.extend([0] * (256 - len(sifted_key)))
    else:
        sifted_key = sifted_key[:256]
    
    # Convert to bytes and hash for stronger key
    bit_string = ''.join(map(str, sifted_key))
    key_bytes = bytes(int(bit_string[i:i+8], 2) for i in range(0, 256, 8))
    key = hashlib.sha256(key_bytes).digest()
    
    return key

# --------------------------
# Encrypt image to bytes
# --------------------------
def encrypt_image_to_bytes(image_data, key):
    try:
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(image_data)
        nonce = cipher.nonce
        
        # Combine all components
        encrypted_data = nonce + tag + ciphertext
        data_length = len(encrypted_data)
        
        # Prefix with length (4 bytes)
        length_bytes = data_length.to_bytes(4, 'big')
        full_data = length_bytes + encrypted_data
        full_length = len(full_data)
        
        # Calculate optimal image dimensions
        side_length = int(np.ceil(np.sqrt(full_length)))
        total_pixels = side_length * side_length
        
        # Pad data to fit the image
        padded_data = full_data + bytes(total_pixels - full_length)
        
        # Create image from bytes
        img = Image.frombytes("L", (side_length, side_length), padded_data)
        
        # Convert to bytes
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr.seek(0)
        
        return img_byte_arr.getvalue()
        
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")

# --------------------------
# Decrypt image from bytes
# --------------------------
def decrypt_image_from_bytes(encrypted_image_data, key):
    try:
        # Convert bytes to image and get data
        img = Image.open(io.BytesIO(encrypted_image_data))
        img_data = img.tobytes()
        
        if len(img_data) < 36:  # 4 (length) + 16 (nonce) + 16 (tag)
            raise ValueError("Invalid encrypted image: insufficient data")
        
        # Extract length
        data_length = int.from_bytes(img_data[:4], 'big')
        
        # Extract encrypted_data (without padding)
        encrypted_data = img_data[4:4 + data_length]
        
        if len(encrypted_data) != data_length:
            raise ValueError("Invalid encrypted image: data length mismatch")
        
        # Extract components
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext
        
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

# --------------------------
# Flask routes
# --------------------------
@app.route("/encrypt", methods=["POST"])
def encrypt_endpoint():
    if "image" not in request.files:
        return jsonify({"error": "No image file uploaded"}), 400

    file = request.files["image"]
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
        
    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    try:
        # Read image data
        image_data = file.read()
        
        # Generate quantum key
        key = bb84_key()
        
        # Encrypt image
        encrypted_image_data = encrypt_image_to_bytes(image_data, key)
        
        # Create response with image and key in headers
        response = make_response(encrypted_image_data)
        response.headers.set('Content-Type', 'image/png')
        response.headers.set('Content-Disposition', 'attachment', filename='encrypted_image.png')
        response.headers.set('X-Encryption-Key', key.hex())
        response.headers.set('Access-Control-Expose-Headers', 'X-Encryption-Key')
        
        return response
        
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500

@app.route("/decrypt", methods=["POST"])
def decrypt_endpoint():
    if "image" not in request.files:
        return jsonify({"error": "No encrypted image file uploaded"}), 400

    key_hex = request.form.get("key")
    if not key_hex:
        return jsonify({"error": "Missing decryption key"}), 400

    file = request.files["image"]
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    try:
        # Read encrypted image data
        encrypted_image_data = file.read()
        
        # Convert key from hex
        key = bytes.fromhex(key_hex)
        
        # Decrypt image
        decrypted_image_data = decrypt_image_from_bytes(encrypted_image_data, key)
        
        # Create response with decrypted image
        response = make_response(decrypted_image_data)
        response.headers.set('Content-Type', 'image/png')
        response.headers.set('Content-Disposition', 'attachment', filename='decrypted_image.png')
        
        return response
        
    except ValueError as e:
        if "MAC check failed" in str(e) or "Authentication failed" in str(e):
            return jsonify({"error": "Decryption failed: Invalid key or corrupted data"}), 400
        else:
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy"})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)