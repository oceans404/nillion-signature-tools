import streamlit as st
from views import sign_message_page

st.set_page_config(
    page_title="Sign Message with Nillion",
    page_icon="✍️",
    initial_sidebar_state="expanded"
)

st.title("Sign Message with Nillion")
sign_message_page.show() 