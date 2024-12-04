import streamlit as st
from src.nillion_utils import verify_signature

def show():
    st.text("""
        Verify an ECDSA signature using the public key. This tool can verify signatures created by Nillion's threshold ECDSA or any other ECDSA implementation that uses the secp256k1 curve.
    """)
    
    # Input type selection
    input_type = st.radio(
        "Input Type",
        ["Original Message", "Message Hash"],
        help="Choose whether to provide the original message or its SHA-256 hash"
    )
    
    if input_type == "Original Message":
        message = st.text_area(
            "Original Message",
            help="The exact message that was signed"
        )
        is_hash = False
    else:
        message = st.text_input(
            "Message Hash (hex)",
            help="The SHA-256 hash of the message (with or without 0x prefix)"
        )
        is_hash = True
    
    st.subheader("Signature Components")
    r_component = st.text_input(
        "r component (hex)",
        help="The 'r' component of the signature (with or without 0x prefix)"
    )
    
    s_component = st.text_input(
        "s component (hex)",
        help="The 's' component of the signature (with or without 0x prefix)"
    )
    
    public_key = st.text_input(
        "Public Key (hex)",
        help="The uncompressed public key (130 characters starting with '04')"
    )
    
    if st.button("Verify Signature"):
        if not all([message, r_component, s_component, public_key]):
            st.error("All fields are required")
            return
            
        try:
            # Clean inputs
            r_component = r_component.replace('0x', '')
            s_component = s_component.replace('0x', '')
            
            # Verify the signature
            result = verify_signature(
                message_or_hash=message,
                signature={
                    'r': f"0x{r_component}",
                    's': f"0x{s_component}"
                },
                public_key=public_key,
                is_hash=is_hash
            )
            
            if result['verified']:
                st.success("✅ Signature verified successfully!")
                
                st.subheader("Verification Details")
                
                if 'original_message' in result:
                    st.text("Original Message")
                    st.code(result['original_message'])
                
                st.text("Message Hash (SHA-256)")
                st.code(result['message'])
                
                st.text("Signature Components")
                st.json(result['signature'])
                
                st.text("Public Key")
                st.code(result['public_key']['hex'])
                
                st.info("""
                    The signature is valid! This proves that
                    1. The message was signed by someone with compute permission to the private key stored in Nillion
                    2. The message hasn't been modified since it was signed
                    3. The signature was created using the corresponding private key
                """)
            else:
                st.error("❌ Invalid signature!")
                if 'error' in result:
                    st.error(f"Error details: {result['error']}")
                if 'debug' in result:
                    st.expander("Debug Information", expanded=False).json(result['debug'])
                
        except Exception as e:
            st.error(f"Error verifying signature: {str(e)}") 