import streamlit as st

st.set_page_config(page_title="Nillion Signature Tools", page_icon="🔏")

st.title("Nillion Signature Tools")
st.write("Welcome! Use the tools below to generate private keys, store keys in Nillion, sign messages with stored private keys, and verify signatures.")

st.markdown("""
### Available Tools:
- **[ECDSA Key Generator](/ECDSA_Key_Generator)**: Generate new ECDSA key pairs
- **[Store Key In Nillion](/Store_Key_In_Nillion)**: Store your ECDSA private key in Nillion
- **[Retrieve Key from Nillion](/Retrieve_Key_from_Nillion)**: Retrieve your stored ECDSA private key from Nillion
- **[Sign Message](/Sign_Message)**: Sign messages securely using Nillion's threshold ECDSA via your stored private key
- **[Verify Signature](/Verify_Signature)**: Verify the authenticity of signed messages
- **[Other Tools](/Other_Tools)**: Explore additional dev tools that help generate a Nillion user ID from a seed, derive Ethereum addresses, and derive public keys
""")