import hmac
import hashlib

def generate_hmac_signature(secret_key: bytes, file_path: str) -> str:
    """
    Generates an HMAC-SHA256 signature for a given file.
    This is used to seal the final evidence package to prevent tampering.
    """
    h = hmac.new(secret_key, digestmod=hashlib.sha256)
    
    with open(file_path, 'rb') as f:
        # Read in 4K chunks
        for byte_block in iter(lambda: f.read(4096), b""):
            h.update(byte_block)
            
    return h.hexdigest()

def verify_hmac_signature(secret_key: bytes, file_path: str, signature: str) -> bool:
    """
    Verifies the HMAC-SHA256 signature of a file.
    """
    expected_signature = generate_hmac_signature(secret_key, file_path)
    return hmac.compare_digest(expected_signature, signature)
