import streamlit as st
from views import other_helpers_page

st.set_page_config(
    page_title="Other Tools",
    page_icon="🛠️",
    initial_sidebar_state="expanded"
)

st.title("Other Tools")
other_helpers_page.show() 