import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# =========================================================================
# 1. TAHAP LOAD DATASET
# =========================================================================
print("Memuat dataset (dataset_phishing.csv)...")
df = pd.read_csv('dataset_phishing.csv')
df = df.dropna(subset=['url']).reset_index(drop=True)

# Menentukan kolom kunci jawaban secara dinamis
if 'status' in df.columns:
    kolom_target = 'status'
else:
    kolom_target = df.columns[-1]

print(f"Menggunakan kolom '{kolom_target}' sebagai kunci jawaban asli.")
df['target'] = df[kolom_target].str.lower().map({'legitimate': 0, 'phishing': 1})
y = df['target'].values

# =========================================================================
# 2. TAHAP PENYIAPAN 11 FITUR MURNI
# =========================================================================
fitur_wajib = [
    'length_url', 'nb_dots', 'nb_hyphens', 'nb_slash', 'nb_qm',
    'ratio_digits_url', 'http_in_path', 'login_form', 'iframe', 'submit_email', 'popup_window'
]
X = df[fitur_wajib].values

# Membagi data (80% Latih, 20% Uji) secara berimbang
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# =========================================================================
# 3. TAHAP PELATIHAN MODEL RANDOM FOREST
# =========================================================================
print("Melatih Model Random Forest Classifier...")
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf_classifier.fit(X_train, y_train)

# Pengujian Model
y_pred = rf_classifier.predict(X_test)
akurasi = accuracy_score(y_test, y_pred)

# =========================================================================
# 4. OUTPUT DAN PENYIMPANAN MODEL
# =========================================================================
print("\n" + "="*60)
print("=== HASIL PELATIHAN MODEL RANDOM FOREST ===")
print("="*60)
print(f"Akurasi Akhir Model Murni (11 Fitur): {akurasi * 100:.2f}%")
print("="*60)

# Memunculkan report presisi detail untuk bahan laporan PI lu
print("\nLaporan Klasifikasi Detail:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

# Simpan objek kepintaran AI
joblib.dump(rf_classifier, 'model_rf_new.pkl')
print("\n[SUKSES] Berkas 'model_rf_new.pkl' versi 11 Fitur sukses disimpan!")