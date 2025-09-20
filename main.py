# save as medical_image_api.py
from fastapi import FastAPI, UploadFile, Form, File
from fastapi.responses import StreamingResponse, JSONResponse
from PIL import Image, PngImagePlugin
import os, io, uuid, hashlib, secrets, numpy as np
from Crypto.Cipher import AES
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
import json

app = FastAPI(title="Medical Image Encryption & Metadata API")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ------------------ Metadata Functions ------------------
def embed_metadata(img_path, metadata):
    img = Image.open(img_path).convert("RGB")
    png_info = PngImagePlugin.PngInfo()
    for key, value in metadata.items():
        png_info.add_text(key, str(value))
    buf = io.BytesIO()
    img.save(buf, "PNG", pnginfo=png_info)
    buf.seek(0)
    return buf

def extract_metadata(img_bytes):
    img = Image.open(io.BytesIO(img_bytes))
    metadata = img.info
    filtered_metadata = {k: v for k, v in metadata.items() if k not in ["dpi", "transparency"]}
    return filtered_metadata

# ------------------ Quantum AES Key ------------------
def bb84_key(n_bits=512):
    alice_bits = [secrets.randbelow(2) for _ in range(n_bits)]
    alice_bases = [secrets.randbelow(2) for _ in range(n_bits)]
    bob_bases = [secrets.randbelow(2) for _ in range(n_bits)]
    bob_bits = []
    backend = AerSimulator()
    for i in range(n_bits):
        qc = QuantumCircuit(1,1)
        if alice_bits[i]==1: qc.x(0)
        if alice_bases[i]==1: qc.h(0)
        if bob_bases[i]==1: qc.h(0)
        qc.measure(0,0)
        result = backend.run(qc, shots=1, memory=True).result()
        bob_bits.append(int(result.get_memory()[0]))
    sifted_key = [alice_bits[i] for i in range(n_bits) if alice_bases[i]==bob_bases[i]]
    if len(sifted_key)<256: sifted_key.extend([0]*(256-len(sifted_key)))
    else: sifted_key = sifted_key[:256]
    bit_string = ''.join(map(str,sifted_key))
    key_bytes = bytes(int(bit_string[i:i+8],2) for i in range(0,256,8))
    return hashlib.sha256(key_bytes).digest()

# ------------------ AES-GCM Encrypt / Decrypt ------------------
def encrypt_image(image_data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(image_data)
    nonce = cipher.nonce
    encrypted_data = nonce + tag + ciphertext
    data_length = len(encrypted_data)
    length_bytes = data_length.to_bytes(4,'big')
    full_data = length_bytes + encrypted_data
    side_length = int(np.ceil(np.sqrt(len(full_data))))
    padded_data = full_data + bytes(side_length*side_length - len(full_data))
    img = Image.frombytes("L",(side_length,side_length),padded_data)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf

def decrypt_image(encrypted_bytes, key):
    img = Image.open(io.BytesIO(encrypted_bytes))
    data = img.tobytes()
    data_length = int.from_bytes(data[:4],'big')
    encrypted_data = data[4:4+data_length]
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ------------------ API Routes ------------------
@app.get("/")
async def root():
    return {"message":"Server running. Visit /docs for API usage."}

# --- Upload, Embed Metadata, Encrypt ---
@app.post("/encrypt/")
async def encrypt_endpoint(
    file: UploadFile = File(...),
    CaseID: str = Form(...),
    Modality: str = Form(...),
    Organ: str = Form(...),
    Disease: str = Form(...),
    SeverityIndex: str = Form(...),
    UrgencyZone: str = Form(...),
    Description: str = Form(...),
):
    if not file.content_type.startswith("image/"):
        return JSONResponse({"error":"Invalid file type"}, status_code=400)
    
    # Save original upload temporarily
    ext = os.path.splitext(file.filename)[-1]
    temp_path = os.path.join(UPLOAD_DIR,f"{uuid.uuid4()}{ext}")
    with open(temp_path,"wb") as buf: buf.write(await file.read())
    
    # Embed metadata
    metadata = {
        "CaseID":CaseID,"Modality":Modality,"Organ":Organ,
        "Disease":Disease,"SeverityIndex":SeverityIndex,
        "UrgencyZone":UrgencyZone,"Description":Description
    }
    png_buf = embed_metadata(temp_path, metadata)
    
    # Encrypt PNG bytes
    key = bb84_key()
    encrypted_buf = encrypt_image(png_buf.read(), key)
    
    return StreamingResponse(
        encrypted_buf,
        media_type="image/png",
        headers={
            "Content-Disposition":"attachment; filename=encrypted_image.png",
            "X-Encryption-Key": key.hex(),
            "Access-Control-Expose-Headers":"X-Encryption-Key"
        }
    )

# --- Decrypt, Return Original Image + Metadata ---
@app.post("/decrypt/")
async def decrypt_endpoint(file: UploadFile = File(...), key_hex: str = Form(...)):
    encrypted_bytes = await file.read()
    key = bytes.fromhex(key_hex)
    try:
        decrypted_bytes = decrypt_image(encrypted_bytes, key)
        metadata = extract_metadata(decrypted_bytes)
        buf = io.BytesIO(decrypted_bytes)
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="image/png",
            headers={
                "Content-Disposition":"attachment; filename=original_image.png",
                "X-Metadata": json.dumps(metadata),
                "Access-Control-Expose-Headers":"X-Metadata"
            }
        )
    except ValueError:
        return JSONResponse({"error":"Invalid key or corrupted data"}, status_code=400)
