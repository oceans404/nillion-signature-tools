import streamlit as st
from views import verify_signature_page

st.set_page_config(
    page_title="Verify ECDSA Signature",
    page_icon="✅",
    initial_sidebar_state="expanded"
)

st.title("Verify ECDSA Signature")
verify_signature_page.show() 