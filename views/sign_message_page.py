import streamlit as st
import asyncio
from src.nillion_utils import sign_message

def show():
    st.text("""
        This tool uses Nillion's threshold ECDSA to securely sign messages without exposing the private key stored in Nillion.
    """)
    
    # Input fields
    store_id = st.text_input(
        "Store ID of the ECDSA Private Key",
        help="The UUID where your key is stored in Nillion"
    )
    
    user_key_seed = st.text_input(
        "User Key Seed",
        help="This user key needs to have Nillion compute permissions for the stored private key"
    )
    
    message = st.text_area(
        "Message to Sign",
        help="Enter any message you want to sign (e.g., 'Hello World' or a transaction payload)"
    )

    st.info("""
        The signature will be returned in a format compatible with Ethereum and other ECDSA verification systems. 
        You can use this signature to prove message authenticity on-chain or off-chain.
    """)
    
    if st.button("Sign Message"):
        if not all([store_id, user_key_seed, message]):
            st.error("All fields are required")
            return
            
        try:
            with st.spinner('Signing message with Nillion...'):
                # Sign the message
                signature_result = asyncio.run(sign_message(
                    message.encode('utf-8'),
                    store_id,
                    user_key_seed=user_key_seed
                ))
                
                # Show success message
                st.success("✅ Message signed successfully!")
                
                st.header("Signature Details")
                
                st.subheader("Message")
                st.code(signature_result['message'])
                
                st.subheader("Message Hash (SHA-256)")
                st.text("This is the cryptographic hash of your message that was actually signed. It's needed for signature verification.")
                st.code(signature_result['message_hash'])
                
                st.subheader("Signature Components")
                st.text("The signature consists of two components (r,s) that prove the message was signed by the owner of the private key, without revealing the key itself")
                st.subheader("Signature Component 'r'")
                st.text("r is derived from a random point on the elliptic curve during signing. It helps make each signature unique, even for the same message")
                st.code(signature_result['signature']['r'], language='plaintext')
                
                st.subheader("Signature Component 's'")
                st.text("s is calculated using the message hash, 'r', and your private key in a way that can be verified without exposing the private key")
                st.code(signature_result['signature']['s'], language='plaintext')
                
        except Exception as e:
            st.error(f"Error signing message: {str(e)}") 