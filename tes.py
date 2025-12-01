# app.py
import streamlit as st
import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

st.set_page_config(page_title="Encryption & Decryption Tool", page_icon="🔐", layout="wide")

st.title("🔐 Encryption & Decryption Tool — AES-GCM & Fernet (Demo)")
st.markdown(
    "Alat demo enkripsi simetris. Pilih algoritme, buat atau tempel key, lalu enkripsi / dekripsi "
    "teks atau file. **Hanya untuk tujuan edukasi.**"
)

# --- Utility helpers ----------------------------------------------------
def b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()

def b64_decode(data_b64: str) -> bytes:
    return base64.urlsafe_b64decode(data_b64.encode())

# --- Fernet helpers ----------------------------------------------------
def generate_fernet_key() -> str:
    return Fernet.generate_key().decode()

def fernet_encrypt(key_b64: str, plaintext: bytes) -> bytes:
    f = Fernet(key_b64.encode())
    return f.encrypt(plaintext)

def fernet_decrypt(key_b64: str, token: bytes) -> bytes:
    f = Fernet(key_b64.encode())
    return f.decrypt(token)

# --- AES-GCM helpers ---------------------------------------------------
def generate_aes256_key_b64() -> str:
    key = os.urandom(32)  # 256-bit
    return b64_encode(key)

def aesgcm_encrypt(key_b64: str, plaintext: bytes, aad: bytes = None) -> bytes:
    key = b64_decode(key_b64)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # recommended 96-bit nonce for AESGCM
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    # store nonce + ciphertext (ciphertext already contains tag)
    return nonce + ct

def aesgcm_decrypt(key_b64: str, nonce_plus_ct: bytes, aad: bytes = None) -> bytes:
    key = b64_decode(key_b64)
    aesgcm = AESGCM(key)
    nonce = nonce_plus_ct[:12]
    ct = nonce_plus_ct[12:]
    return aesgcm.decrypt(nonce, ct, aad)

# --- UI layout ----------------------------------------------------------
col1, col2 = st.columns([1, 2])

with col1:
    st.header("Settings")
    mode = st.radio("Mode", ("Encrypt", "Decrypt"))
    algo = st.selectbox("Algorithm", ("Fernet (cryptography.Fernet)", "AES-GCM (AES-256-GCM)"))
    st.markdown("**Key management**")
    key_input = st.text_area("Key (base64 for AES-GCM / raw urlsafe base64 for Fernet)", height=80,
                             placeholder="Kosongkan lalu klik 'Generate Key' untuk membuat baru")
    key_generated = None

    if st.button("Generate Key"):
        if algo.startswith("Fernet"):
            key_generated = generate_fernet_key()
        else:
            key_generated = generate_aes256_key_b64()
        st.success("Key generated. Copy/Use it below.")
        # update key_input visually
        key_input = key_generated
        st.code(key_generated)

    st.markdown("---")
    st.markdown("**Input options**")
    input_type = st.radio("Input type", ("Text", "File (binary)"))
    if input_type == "Text":
        text_input = st.text_area("Plaintext (for encrypt) / Ciphertext (base64) (for decrypt)", height=200)
    else:
        uploaded_file = st.file_uploader("Upload file", accept_multiple_files=False)

    # optional AAD for AES-GCM
    if algo.startswith("AES"):
        aad_text = st.text_input("Associated Data (AAD) — optional (text)", value="")
    else:
        aad_text = ""

    st.markdown("---")
    if st.button("Run"):
        # run actions in main column via session state pass-through
        st.session_state.run_trigger = True
        st.session_state._ui = {
            "mode": mode,
            "algo": algo,
            "key_input": key_input,
            "input_type": input_type,
            "text_input": text_input if input_type == "Text" else None,
            "uploaded_file": uploaded_file if input_type == "File" else None,
            "aad": aad_text.encode() if aad_text else None,
        }

with col2:
    st.header("Output")
    if "run_trigger" not in st.session_state:
        st.info("Klik **Run** untuk mengeksekusi operasi enkripsi / dekripsi.")
    else:
        ui = st.session_state._ui
        mode = ui["mode"]
        algo = ui["algo"]
        key_input = ui["key_input"]
        aad = ui["aad"]

        if not key_input:
            st.error("Key kosong — silakan generate atau paste key yang valid.")
        else:
            try:
                if mode == "Encrypt":
                    # --- prepare plaintext bytes ---
                    if ui["input_type"] == "Text":
                        if not ui["text_input"]:
                            st.error("Tidak ada plaintext yang dimasukkan.")
                            raise ValueError("Plaintext kosong")
                        plaintext = ui["text_input"].encode()
                        filename = None
                    else:
                        if not ui["uploaded_file"]:
                            st.error("Tidak ada file yang diupload.")
                            raise ValueError("No file")
                        uploaded = ui["uploaded_file"]
                        plaintext = uploaded.read()
                        filename = uploaded.name

                    # --- encryption ---
                    if algo.startswith("Fernet"):
                        st.subheader("Fernet encrypt")
                        try:
                            ciphertext = fernet_encrypt(key_input, plaintext)
                            out_b64 = b64_encode(ciphertext)
                            st.success("Berhasil mengenkripsi (Fernet).")
                            st.markdown("**Ciphertext (base64, urlsafe):**")
                            st.code(out_b64)
                            # download
                            st.download_button(
                                label="Download ciphertext (.bin)",
                                data=ciphertext,
                                file_name=(filename + ".fernet" if filename else "ciphertext.fernet"),
                                mime="application/octet-stream"
                            )
                        except Exception as e:
                            st.error(f"Gagal enkripsi Fernet: {e}")

                    else:
                        st.subheader("AES-GCM encrypt (nonce + ciphertext, base64)")
                        try:
                            ciphertext_blob = aesgcm_encrypt(key_input, plaintext, aad)
                            out_b64 = b64_encode(ciphertext_blob)
                            st.success("Berhasil mengenkripsi (AES-GCM).")
                            st.markdown("**Output (base64):** nonce||ciphertext_tag (concat).")
                            st.code(out_b64)
                            st.download_button(
                                label="Download ciphertext (.bin)",
                                data=ciphertext_blob,
                                file_name=(filename + ".aesgcm" if filename else "ciphertext.aesgcm"),
                                mime="application/octet-stream"
                            )
                        except Exception as e:
                            st.error(f"Gagal enkripsi AES-GCM: {e}")

                else:  # Decrypt
                    if ui["input_type"] == "Text":
                        if not ui["text_input"]:
                            st.error("Tidak ada ciphertext yang dimasukkan.")
                            raise ValueError("Ciphertext kosong")
                        try:
                            blob = b64_decode(ui["text_input"].strip())
                        except Exception as e:
                            st.error("Gagal decode base64 dari input teks. Pastikan input adalah base64.")
                            raise

                    else:
                        if not ui["uploaded_file"]:
                            st.error("Tidak ada file yang diupload.")
                            raise ValueError("No file")
                        uploaded = ui["uploaded_file"]
                        blob = uploaded.read()

                    if algo.startswith("Fernet"):
                        st.subheader("Fernet decrypt")
                        try:
                            plaintext = fernet_decrypt(key_input, blob)
                            st.success("Berhasil dekripsi (Fernet).")
                            # show text if printable
                            try:
                                txt = plaintext.decode()
                                st.markdown("**Plaintext (decoded UTF-8):**")
                                st.code(txt)
                            except Exception:
                                st.markdown("**Plaintext (binary):**")
                                st.write(plaintext)
                            st.download_button(
                                label="Download plaintext",
                                data=plaintext,
                                file_name="decrypted.bin",
                                mime="application/octet-stream"
                            )
                        except InvalidToken:
                            st.error("Invalid token / key — dekripsi Fernet gagal (InvalidToken).")
                        except Exception as e:
                            st.error(f"Gagal dekripsi Fernet: {e}")

                    else:
                        st.subheader("AES-GCM decrypt")
                        try:
                            plaintext = aesgcm_decrypt(key_input, blob, aad)
                            st.success("Berhasil dekripsi (AES-GCM).")
                            try:
                                txt = plaintext.decode()
                                st.markdown("**Plaintext (decoded UTF-8):**")
                                st.code(txt)
                            except Exception:
                                st.markdown("**Plaintext (binary):**")
                                st.write(plaintext)
                            st.download_button(
                                label="Download plaintext",
                                data=plaintext,
                                file_name="decrypted.bin",
                                mime="application/octet-stream"
                            )
                        except Exception as e:
                            st.error(f"Gagal dekripsi AES-GCM: {e}")

            except Exception:
                # error details already shown above
                pass

# --- Footer / Notes -----------------------------------------------------
st.markdown("---")
st.markdown(
    "**Notes:**\n"
    "- Fernet: key adalah urlsafe base64 32-byte key yang di-generate oleh `Fernet.generate_key()`.\n"
    "- AES-GCM: key disajikan dalam base64 (256-bit raw key). Output enkripsi adalah `nonce (12 bytes)` + `ciphertext|tag` yang kemudian disajikan sebagai base64.\n"
    "- AAD (Associated Authenticated Data) di-support untuk AES-GCM (opsional).\n"
    "- Jangan gunakan alat ini untuk data sensitif di lingkungan produksi tanpa audit keamanan.\n"
)
