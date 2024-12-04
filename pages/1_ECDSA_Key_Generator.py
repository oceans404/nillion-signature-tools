import streamlit as st
from views import key_generator_page

st.set_page_config(
    page_title="ECDSA Key Generator",
    page_icon="🔏",
    initial_sidebar_state="expanded"
)

st.title("ECDSA Key Generator")
key_generator_page.show() 