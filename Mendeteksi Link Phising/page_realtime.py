import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
from datetime import datetime
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup

st.title("Pemindai URL Real-Time")
st.write("Analisis keamanan link menggunakan ekstrasi fitur konten dan klasifikasi Random Forest.")

@st.cache_resource
def load_model():
    return joblib.load('model_rf_new.pkl')

try:
    model = load_model()
except:
    st.error("File model_rf_new.pkl tidak ditemukan.")
    st.stop()

# Basis data domain populer untuk Whitelist & Jarak Levenshtein
POPULAR_DOMAINS = [
    'google.com', 'accounts.google.com', 'mail.google.com', 'youtube.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'studentsite.gunadarma.ac.id', 'gunadarma.ac.id', 'baak.gunadarma.ac.id',
    'github.com', 'microsoft.com', 'linkedin.com', 'yahoo.com', 'shopee.co.id'
]

# Algoritma Jarak Levenshtein Komputasi Mandiri
def hitung_levenshtein(s1, s2):
    if len(s1) < len(s2):
        return hitung_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            ins = prev_row[j + 1] + 1
            del_ = curr_row[j] + 1
            sub = prev_row[j] + (c1 != c2)
            curr_row.append(min(ins, del_, sub))
        prev_row = curr_row
    return prev_row[-1]

def scraping_web(url):
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    options.add_argument("--disable-blink-features=AutomationControlled")

    try:
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(10)
        driver.get(url)
        import time
        time.sleep(3)  # Jeda render konten agar iframe ke-load sempurna
        html = driver.page_source
        driver.quit()
        return html
    except:
        return None

def ambil_fitur(url):
    features = []
    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('/'))
    features.append(url.count('?'))
    features.append(sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0)
    
    try:
        path = urlparse(url).path
        has_http = 1 if 'http' in path.lower() else 0
    except:
        has_http = 0
    features.append(has_http)
    
    with st.spinner("Mengekstraksi komponen halaman website..."):
        html = scraping_web(url)
        
    if html:
        soup = BeautifulSoup(html, 'html.parser')
        login_form = 1 if len(soup.find_all('form')) > 0 or "password" in html.lower() else 0
        iframe = len(soup.find_all('iframe'))
        submit_email = 1 if "mailto:" in html.lower() else 0
        popup = 1 if "window.open(" in html.lower() else 0
    else:
        login_form, iframe, submit_email, popup = 0, 0, 0, 0
        
    features.extend([login_form, iframe, submit_email, popup])
    return np.array(features).reshape(1, -1)

# Layout Grid Dashboard
col1, col2 = st.columns([2, 1])

with col1:
    input_url = st.text_input("Input Tautan URL:", placeholder="https://example.com")
    
    if st.button("Mulai Pemindaian", type="primary", use_container_width=True):
        if input_url:
            url_clean = input_url.strip()
            if not url_clean.startswith(('http://', 'https://')):
                url_scan = 'https://' + url_clean
            else:
                url_scan = url_clean
            
            try:
                domain = urlparse(url_scan).netloc.replace('www.', '')
                if not domain:
                    domain = url_scan.split('/')[0].replace('www.', '')
            except:
                domain = url_scan
            
            st.divider()
            
            # --- EVALUASI TYPOSQUATTING (ALGORITMA LEVENSHTEIN) ---
            is_typosquatting = False
            target_mirip = ""
            jarak_terdekat = 999
            
            for pop_domain in POPULAR_DOMAINS:
                jarak = hitung_levenshtein(domain, pop_domain)
                if jarak == 0:
                    jarak_terdekat = 0
                    break
                if jarak < jarak_terdekat:
                    jarak_terdekat = jarak
                    target_mirip = pop_domain
            
            if 0 < jarak_terdekat <= 2:
                is_typosquatting = True
            
            # --- OUTPUT CONTAINER RESULTS ---
            with st.container():
                # 1. Kondisi jika masuk Whitelist Mutlak
                if jarak_terdekat == 0:
                    st.success(f"Situs Aman: Domain Terdaftar di Whitelist")
                    
                    m_col1, m_col2 = st.columns(2)
                    m_col1.metric("Keputusan Sistem", "AMAN")
                    m_col2.metric("Akurasi Mutlak", "100%")
                    
                    with st.expander("Hasil Bedah Atribut Fitur"):
                        st.markdown("**Penjelasan:**")
                        st.info(f"Domain '{domain}' dilewati dari kalkulasi AI karena masuk kategori entitas terpercaya.")
                
                # 2. Kondisi Evaluasi Menggunakan Model ML + Levenshtein
                else:
                    fitur = ambil_fitur(url_scan)
                    prediksi = model.predict(fitur)[0]
                    prob = model.predict_proba(fitur)[0]
                    skor = prob[prediksi] * 100
                    
                    m_col1, m_col2 = st.columns(2)
                    
                    if is_typosquatting or prediksi == 1:
                        st.error("Peringatan: Tautan Terindikasi Bahaya / Phishing")
                        m_col1.metric("Keputusan AI", "PHISHING")
                    else:
                        st.success("Sistem: Tautan Dinilai Aman")
                        m_col1.metric("Keputusan AI", "AMAN")
                        
                    m_col2.metric("Tingkat Keyakinan", f"{skor:.2f}%")
                    
                    with st.expander("Hasil Bedah Atribut Fitur"):
                        st.markdown("**Penjelasan:**")
                        
                        if is_typosquatting:
                            st.warning(f"⚠️ **Indikator Typosquatting:** Domain terdeteksi meniru '{target_mirip}' dengan Jarak Levenshtein: {jarak_terdekat} edit.")
                        else:
                            st.success(f"✅ **Indikator Typosquatting:** Tidak ada indikasi penyamaran domain populer (Jarak Levenshtein aman).")
                        
                        st.divider()
                        
                        st.markdown("**Nilai Ekstraksi Fitur Tautan:**")
                        f_col1, f_col2 = st.columns(2)
                        with f_col1:
                            st.text(f"Panjang URL: {int(fitur[0][0])} hrf")
                            st.text(f"Tanda Titik: {int(fitur[0][1])} buah")
                        with f_col2:
                            st.text(f"Form Login: {'Ada' if fitur[0][7] == 1 else 'Tidak Ada'}")
                            st.text(f"Tag Iframe: {int(fitur[0][8])} buah")
                            
                        st.divider()
                        
                        st.markdown("**Standar Acuan Parameter Aman:**")
                        s_col1, s_col2 = st.columns(2)
                        with s_col1:
                            st.text("Panjang URL: < 54 karakter")
                            st.text("Tanda Titik: Maksimal 2-3 buah")
                        with s_col2:
                            st.text("Form Login: Harus 'Tidak Ada'")
                            st.text("Tag Iframe: Harus '0 buah'")
                            
                        st.divider()
                        st.caption("Bobot keputusan dihitung secara multivariat menggunakan kombinasi Jarak Levenshtein dan Random Forest.")
            
            # --- PERBAIKAN LOGIKA SIMPAN RIWAYAT (LOGGING) ---
            log_file = 'history_log.csv'
            if jarak_terdekat == 0:
                hasil_log = "AMAN (WHITELIST)"
            else:
                hasil_log = "PHISHING" if (is_typosquatting or prediksi == 1) else "AMAN"
                
            log_baru = pd.DataFrame([{
                'Tanggal': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'URL': url_clean,
                'Hasil': hasil_log
            }])
            
            if not os.path.isfile(log_file):
                log_baru.to_csv(log_file, index=False)
            else:
                log_baru.to_csv(log_file, mode='a', header=False, index=False)
        else:
            st.warning("Kolom URL tidak boleh kosong.")

with col2:
    st.subheader("Riwayat Aktivitas")
    if os.path.isfile('history_log.csv'):
        df_log = pd.read_csv('history_log.csv')
        st.dataframe(df_log.tail(8), use_container_width=True)
        if st.button("Clear Log", use_container_width=True):
            os.remove('history_log.csv')
            st.rerun()
    else:
        st.info("Riwayat kosong.")