import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize session state for navigation and failed attempts
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "choice" not in st.session_state:
    st.session_state.choice = "Home"

# Generate a key (this should be stored securely in production)
if "cipher" not in st.session_state:
    KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(KEY)

# In-memory data storage
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {"encrypted_text": {"encrypted_text": "xyz", "passkey": "hashed"}}

# Function to hash passkey
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text: str, passkey: str) -> str:
    return st.session_state.cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text: str, passkey: str) -> str | None:
    hashed_passkey = hash_passkey(passkey)
    stored_data = st.session_state.stored_data

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            try:
                return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
            except Exception:
                return None
    
    st.session_state.failed_attempts += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.choice))

# Update session state choice
st.session_state.choice = choice

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:", key="store_data")
    passkey = st.text_input("Enter Passkey:", type="password", key="store_passkey")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:", key="retrieve_data")
    passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_passkey")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            try:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                        st.session_state.choice = "Login"
                        st.rerun()
            except Exception as e:
                st.error(f"❌ Decryption failed: {str(e)}")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password", key="login_pass")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.session_state.choice = "Retrieve Data"
            st.rerun()
        else:
            st.error("❌ Incorrect password!")