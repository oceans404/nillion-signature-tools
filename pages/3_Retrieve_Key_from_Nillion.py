import streamlit as st
from views import retrieve_key_page

st.set_page_config(
    page_title="Retrieve Key from Nillion",
    page_icon="🔐",
    initial_sidebar_state="expanded"
)

st.title("Retrieve Key from Nillion")
retrieve_key_page.show() 