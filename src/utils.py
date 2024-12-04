from eth_utils import keccak, to_checksum_address
from cryptography.hazmat.primitives.asymmetric import ec

def clean_hex_input(hex_str: str) -> str:
    """Clean hex input by removing '0x' prefix and whitespace"""
    return hex_str.replace('0x', '').replace(' ', '').strip().lower()

def derive_public_key_from_private(private_key_hex: str) -> str:
    """Derive uncompressed public key from private key hex string
    
    Args:
        private_key_hex (str): Private key in hex format (with or without 0x prefix)
        
    Returns:
        str: Uncompressed public key in hex format (with 04 prefix)
    """
    # Clean input and convert to bytes
    private_key_clean = clean_hex_input(private_key_hex)
    private_bytes = bytearray(bytes.fromhex(private_key_clean))
    
    # Generate private key object and derive public key
    private_key = ec.derive_private_key(
        int.from_bytes(private_bytes, byteorder='big'), 
        ec.SECP256K1()
    )
    public_key = private_key.public_key()
    
    # Get public key coordinates
    public_numbers = public_key.public_numbers()
    x_hex = format(public_numbers.x, '064x')
    y_hex = format(public_numbers.y, '064x')
    
    # Return uncompressed public key format
    return f"04{x_hex}{y_hex}"

def format_key_details(keypair):
    """Format key details for display"""
    # Get Ethereum address from public key
    public_key_bytes = bytes.fromhex(keypair['public_key'][2:])  # Remove '04' prefix
    address = keccak(public_key_bytes)[-20:]  # Take last 20 bytes of hash
    eth_address = to_checksum_address('0x' + address.hex())
    
    details = {
        'private_key': {
            'with_prefix': f"0x{keypair['private_key']}",
            'without_prefix': keypair['private_key'],
            'length': f"{len(keypair['private_key'])} hex characters (32 bytes)"
        },
        'public_key': {
            'with_prefix': f"0x{keypair['public_key']}",
            'without_prefix': keypair['public_key'],
            'length': f"{len(keypair['public_key'])} hex characters (65 bytes - includes '04' prefix)"
        },
        'eth_address': eth_address
    }
    return details

def derive_eth_address(public_key: str) -> str:
    """Derive Ethereum address from public key"""
    # Remove '04' prefix if present and convert to bytes
    public_key_bytes = bytes.fromhex(public_key[2:] if public_key.startswith('04') else public_key)
    # Take last 20 bytes of the hash
    address = keccak(public_key_bytes)[-20:]
    # Convert to checksum address
    return to_checksum_address('0x' + address.hex())

def generate_ecdsa_keypair() -> dict:
    """Generate a new ECDSA key pair on the secp256k1 curve
    
    Returns:
        dict: Contains private and public keys in hex format
    """
    # Generate private key
    private_key = ec.generate_private_key(ec.SECP256K1())
    
    # Get private key as hex
    private_value = private_key.private_numbers().private_value
    private_key_hex = format(private_value, '064x')
    
    # Get public key
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    x_hex = format(public_numbers.x, '064x')
    y_hex = format(public_numbers.y, '064x')
    
    # Format public key in uncompressed format (04 + x + y)
    public_key_hex = f"04{x_hex}{y_hex}"
    
    return {
        'private_key': private_key_hex,
        'public_key': public_key_hex
    }