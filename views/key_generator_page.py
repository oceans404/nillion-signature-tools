import streamlit as st
from src.utils import generate_ecdsa_keypair, format_key_details

def show():
    st.header("Generate an ECDSA Key Pair")
    
    st.text("""
        - The ECDSA private key is a secret number that allows you to sign transactions.
        - The public key is derived from the private key and is used to verify signatures.
        - The Ethereum address is a hashed version of the public key, which is used to receive funds.
    """)
    
    # Security warning
    st.warning("""
        🔒 **Security Note:**
        - Keep your private key secret! Anyone with your private key can control your assets
        - This tool runs in your browser and keys are not stored or transmitted
        - For production use, generate your keys in a secure, offline environment
    """)
    keypair = None
    details = None
    
    if st.button("Generate New Key Pair"):
        keypair = generate_ecdsa_keypair()
        details = format_key_details(keypair)
        
        st.subheader("Private Key")
        st.text_input(
        "Private Key (hex)",
        help="64 characters hexadecimal, with or without '0x' prefix",
        type="password",
        value=details['private_key']['with_prefix']
    )

        st.subheader("Public Key")
        st.code(details['public_key']['with_prefix'])
        
        st.subheader("Ethereum Address")
        st.code(details['eth_address'])