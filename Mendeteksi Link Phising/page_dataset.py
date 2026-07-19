import streamlit as st
import pandas as pd
import numpy as np
import joblib
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

st.title("Dataset & Pengujian Lokal")
st.write("Halaman untuk mengeksplorasi data, melakukan *web scraping* real-time, dan menguji baris dataset menggunakan model Random Forest.")

# Load model dan dataset
@st.cache_resource
def load_model():
    return joblib.load('model_rf_new.pkl')

@st.cache_data
def load_dataset():
    return pd.read_csv('dataset_phishing.csv')

try:
    model = load_model()
    df_dataset = load_dataset()
except Exception as e:
    st.error(f"Error memuat file: {e}")
    st.stop()

# Tampilkan tabel dataset
st.dataframe(df_dataset, use_container_width=True, height=350)

st.subheader("Uji Baris Dataset dengan Web Scraping")
row_index = st.number_input("Masukkan indeks baris (0 - 11429):", min_value=0, max_value=len(df_dataset)-1, value=0)

# Fungsi Kustom Web Scraping untuk Ekstraksi 11 Fitur
def ekstrak_fitur_dengan_scraping(url, row_data):
    # A. Hitung 7 Fitur Leksikal dari String URL secara mandiri
    length_url = len(url)
    nb_dots = url.count('.')
    nb_hyphens = url.count('-')
    nb_slash = url.count('/')
    nb_qm = url.count('?')
    
    digits = sum(c.isdigit() for c in url)
    ratio_digits_url = digits / length_url if length_url > 0 else 0.0
    
    parsed = urlparse(url)
    http_in_path = 1 if 'http' in parsed.path else 0
    
    # B. Inisialisasi 4 Fitur Konten HTML (Default 0)
    login_form = 0
    iframe = 0
    submit_email = 0
    popup_window = 0
    status_scraping = "Sukses (Live Data)"
    
    # C. Proses Web Scraping menggunakan BeautifulSoup
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, timeout=4, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. Cek Login Form (ada input password atau form login)
        if soup.find('input', {'type': 'password'}) or 'login' in response.text.lower():
            login_form = 1
            
        # 2. Hitung jumlah Iframe
        iframe = len(soup.find_all('iframe'))
        
        # 3. Cek Submit Email (ada mailto:)
        if 'mailto:' in response.text.lower():
            submit_email = 1
            
        # 4. Cek Popup Window (ada window.open)
        if 'window.open(' in response.text.lower():
            popup_window = 1
            
    except Exception as e:
        # Jika website down/mati, aktifkan fitur fallback (ambil data asli dari CSV)
        status_scraping = "Gagal (Fallback ke Data CSV)"
        login_form = int(row_data['login_form'])
        iframe = int(row_data['iframe'])
        submit_email = int(row_data['submit_email'])
        popup_window = int(row_data['popup_window'])
        
    vector = [
        length_url, nb_dots, nb_hyphens, nb_slash, nb_qm,
        ratio_digits_url, http_in_path, login_form, iframe,
        submit_email, popup_window
    ]
    return vector, status_scraping

# Tombol Aksi Pengujian
if st.button("Uji Indeks", type="primary"):
    if row_index > len(df_dataset) - 1 or row_index < 0:
        st.error("Indeks di luar batas aman!")
    else:
        row_data = df_dataset.iloc[row_index]
        test_url = row_data['url']
        
        if 'status' in df_dataset.columns:
            actual_label = str(row_data['status']).strip().lower()
        else:
            actual_label = str(row_data.iloc[-1]).strip().lower()
            
        st.info(f"**URL Target:** {test_url}\n\n**Label Asli Dataset:** {actual_label.upper()}")
        
        # Jalankan proses Web Scraping dengan visual spinner loading
        with st.spinner("Sedang menjalankan modul Web Scraping pada URL target..."):
            features_list, status_scraping = ekstrak_fitur_dengan_scraping(test_url, row_data)
            features_vector = np.array(features_list).reshape(1, -1)
        
        # Tampilkan status keberhasilan scraping di layar
        if "Sukses" in status_scraping:
            st.caption(f"Status Ekstraksi: :green[{status_scraping}]")
        else:
            st.caption(f"Status Ekstraksi: :orange[{status_scraping}] (Website target tidak merespon)")
            
        # Prediksi menggunakan model 11 fitur Random Forest
        prediction = model.predict(features_vector)[0]
        
        status_tampil = "PHISHING" if prediction == 1 else "AMAN"
        kunci_tebakan_ai = "phishing" if prediction == 1 else "legitimate"
        
        if kunci_tebakan_ai == actual_label:
            st.success(f"Hasil AI: {status_tampil} (Tebakan AI Sesuai)")
        else:
            st.error(f"Hasil AI: {status_tampil} (Tebakan AI Tidak Sesuai)")
            
        # DETAIL ANALISIS FITUR + STANDARISASI LINK AMAN
        with st.expander("🔍 Detail Fitur Hasil Web Scraping & Standarisasi Keamanan"):
            st.markdown("### 📊 Tabel Analisis Parameter: Aktual vs Standarisasi Link Aman")
            st.write("Berikut adalah rincian nilai parameter hasil ekstraksi sistem dibandingkan dengan acuan teoritis website aman (*legitimate*):")
            
            # Pengkondisian Status Indikator Visual untuk Mempermudah Bacaan
            status_panjang = "Normal" if features_list[0] < 54 else "Terlalu Panjang"
            status_titik = "Normal" if features_list[1] <= 3 else "Subdomain Mencurigakan"
            status_strip = "Normal" if features_list[2] <= 1 else "Manipulasi Brand"
            status_slash = "Normal" if features_list[3] <= 5 else "Folder Terlalu Dalam"
            status_login = "Aman" if features_list[7] == 0 else "Resiko Pencurian Data"
            status_iframe = "Aman" if features_list[8] == 0 else "Indikasi Frame Palsu"
            status_email = "Aman" if features_list[9] == 0 else "Redirect Email Bahaya"
            status_popup = "Aman" if features_list[10] == 0 else "Popup Mencurigakan"

            # Render Tabel Menggunakan Markdown untuk Kejelasan Maksimal
            st.markdown(f"""
            | Parameter Fitur | Nilai Aktual Projek | Standarisasi Tautan Aman (Teori) | Status Indikasi |
            | :--- | :---: | :--- | :---: |
            | **Panjang URL** | {int(features_list[0])} hrf | **Pendek/Wajar (< 54 Karakter)**. Tautan phishing sengaja dibuat sangat panjang untuk menyembunyikan token palsu. | {status_panjang} |
            | **Tanda Titik** | {int(features_list[1])} buah | **Sedikit (1 - 3 Titik)**. Tautan phishing sering menggunakan banyak titik untuk menyusun rantai sub-domain palsu. | {status_titik} |
            | **Tanda Hubung (-)** | {int(features_list[2])} buah | **Minimal (0 - 1 Buah)**. Penggunaan '-' berlebih biasanya dipakai penipu untuk mengelabui nama brand asli. | {status_strip} |
            | **Garis Miring (/)** | {int(features_list[3])} buah | **Wajar (3 - 5 Buah)**. Jumlah berlebih mengindikasikan struktur direktori dalam tempat menyembunyikan skrip fraud. | {status_slash} |
            | **Form Login** | {"Ada" if features_list[7] == 1 else "Tidak Ada"} | **Tidak Ada** (Kecuali domain utama resmi). Munculnya form login di link antah berantah sangat diwaspadai. | {status_login} |
            | **Tag Iframe** | {int(features_list[8])} buah | **0 buah (Tidak Ada)**. Website phishing menggunakan `iframe` untuk menempelkan/menduplikasi halaman login asli di web mereka. | {status_iframe} |
            | **Submit Email** | {"Ada" if features_list[9] == 1 else "Tidak Ada"} | **Tidak Ada (Bukan mailto)**. Tautan aman mengirim data ke database server, bukan dialihkan langsung ke email penipu via *mailto:*. | {status_email} |
            | **Popup Window** | {"Ada" if features_list[10] == 1 else "Tidak Ada"} | **Tidak Ada**. Sering dipakai tautan palsu untuk memicu pop-up otomatis yang menyembunyikan kolom *address bar* asli browser. | {status_popup} |
            """)
            
            st.divider()
            st.caption("Catatan: Evaluasi parameter di atas berjalan secara dinamis dan membandingkan langsung hasil scraping dengan basis teori standar industri keamanan siber.")