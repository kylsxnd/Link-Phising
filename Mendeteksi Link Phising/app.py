import streamlit as st

# 1. KONFIGURASI CORE UTAMA
st.set_page_config(page_title="Anti-Phishing Dashboard", layout="wide")

# 2. DEFINISIKAN HALAMAN-HALAMAN
halaman_1 = st.Page("page_dataset.py", title="Dataset & Pengujian Lokal", default=True)
halaman_2 = st.Page("page_realtime.py", title="Pemindai Real-Time",)

# 3. SATUKAN DAN JALANKAN LOGIKA NAVIGASI SIDEBAR
navigasi_sistem = st.navigation({
    "Menu Utama Dashboard": [halaman_1, halaman_2]
})

navigasi_sistem.run()