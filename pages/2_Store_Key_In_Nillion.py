import streamlit as st
from views import store_key_page

st.set_page_config(
    page_title="Store Key in Nillion",
    page_icon="🔐",
    initial_sidebar_state="expanded"
)

st.title("Store Key in Nillion")
store_key_page.show() 