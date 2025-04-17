import streamlit as st
import os
import base64
import json
import time
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Session State Initialization ---
if "is_authenticated" not in st.session_state:
    st.session_state.is_authenticated = False
    st.session_state.username = ""
    st.session_state.user_files = {"messages": []}
    st.session_state.failed_attempts = 0
    st.session_state.lock_time = 10  # in seconds
    st.session_state.lock_start = None

USER_DB = "users.json"

def load_users():
    if os.path.exists(USER_DB):
        with open(USER_DB, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f)

def hash_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def aes_encrypt(data: str, password: str) -> bytes:
    salt = os.urandom(16)
    key = hash_password(password, salt)[:16]
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + salt + encrypted_data)

def aes_decrypt(encrypted_data: bytes, password: str) -> bytes:
    data = base64.b64decode(encrypted_data)
    iv, salt, ciphertext = data[:16], data[16:32], data[32:]
    key = hash_password(password, salt)[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()

# --- Styled Containers ---
def styled_container(title: str):
    st.markdown(f"""
        <style>
        .auth-box {{
            max-width: 400px;
            margin: 0 auto;
            padding: 2rem;
            background-color: #5C5C99;
            border-radius: 10px;
            border: 1px solid #292966;
            box-shadow: 0 10px 10px rgba(0,0,0,0.1);
        }}
        .auth-title {{
            text-align: center;
            font-size: 24px;
            font-weight: bold;
            color: #fff;
        }}
        input[type="text"], input[type="password"], textarea {{
            background-color: #F5F5FF;
            border: 2px solid #A3A3CC;
            border-radius: 8px;
            padding: 0.5rem;
            font-size: 16px;
            color: #292966;
        }}
        input[type="text"]:focus, input[type="password"]:focus, textarea:focus {{
            border-color: #A3A3CC;
            outline: none;
            box-shadow: 0 0 5px #A3A3CC;
        }}
        select {{
            background-color: #F5F5FF;
            color: #292966;
            border: 2px solid #5C5C99;
            border-radius: 8px;
            padding: 0.5rem;
            font-size: 16px;
        }}
        select:focus {{
            border-color: #292966;
            box-shadow: 0 0 5px #A3A3CC;
        }}
        </style>
        <div class="auth-box">
            <div class="auth-title">{title}</div>
    """, unsafe_allow_html=True)

def close_container():
    st.markdown("</div>", unsafe_allow_html=True)

# --- Register Page ---
def register_user():
    styled_container("Create an Account")
    st.write("")
    st.write("")
    username = st.text_input("Username", key="reg_username")
    password = st.text_input("Password", type="password", key="reg_password")

    if st.button("Register"):
        users = load_users()
        if username in users:
            st.warning("❌ Username already exists.")
        else:
            salt = os.urandom(16)
            hashed_password = hash_password(password, salt)
            users[username] = {
                "salt": base64.b64encode(salt).decode(),
                "password": base64.b64encode(hashed_password).decode()
            }
            save_users(users)
            st.success("✅ Registered successfully! You can now log in.")
    close_container()

# --- Login Page with Lock Timer ---
# ...existing code...

def countdown_timer(duration=10):
    countdown_placeholder = st.empty()  # Create a placeholder for the countdown
    for i in range(duration, 0, -1):
        countdown_placeholder.warning(f"⏳ Time remaining: {i} seconds")
        time.sleep(1)  # Wait for 1 second
    countdown_placeholder.empty()  # Clear the placeholder after the countdown ends

# ...existing code...

# ...existing code...

def authenticate_user():
    if st.session_state.failed_attempts >= 3:
        if st.session_state.lock_start is None:
            st.session_state.lock_start = time.time()

        elapsed = time.time() - st.session_state.lock_start
        remaining = st.session_state.lock_time - int(elapsed)

        if remaining > 0:
            countdown_timer(remaining)  # Use the countdown timer for dynamic updates
            return
        else:
            st.session_state.failed_attempts = 0
            st.session_state.lock_start = None

    # ...existing code...

    styled_container("Login to Your Account")
    st.write("")
    st.write("")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")

    # Validate username and password fields
    if st.button("Login"):
        if not username or not password:
            st.error("❌ Both username and password are required.")
            return

        users = load_users()
        if username in users:
            salt = base64.b64decode(users[username]["salt"])
            stored_hash = base64.b64decode(users[username]["password"])
            input_hash = hash_password(password, salt)
            if input_hash == stored_hash:
                st.session_state.is_authenticated = True
                st.session_state.username = username
                st.session_state.failed_attempts = 0
                st.session_state.lock_start = None
                st.success("✅ Logged in successfully!")
            else:
                st.session_state.failed_attempts += 1
                st.error("❌ Invalid password.")
        else:
            st.session_state.failed_attempts += 1
            st.error("❌ User does not exist.")
    close_container()

# --- Messaging ---
def send_message():
    st.subheader("✉️ Send Encrypted Message")
    message = st.text_area("Write your message here:")
    password = st.text_input("Enter password to encrypt", type="password")
    if st.button("Encrypt & Send"):
        encrypted = aes_encrypt(message, password)
        st.session_state.user_files["messages"].append(encrypted)
        st.success("✅ Message encrypted and saved!")

def view_messages():
    st.subheader("🔓 View Encrypted Messages")
    password = st.text_input("Enter password to decrypt messages", type="password")
    if st.button("Decrypt Messages"):
        for idx, msg in enumerate(st.session_state.user_files["messages"], start=1):
            try:
                decrypted = aes_decrypt(msg, password).decode()
                st.info(f"Message {idx}: {decrypted}")
            except Exception:
                st.error(f"Message {idx}: ❌ Incorrect password or corrupted message.")

# --- File Encryption ---
def file_encryption():
    st.subheader("📁 File Encryption")
    uploaded_file = st.file_uploader("Choose a file to encrypt")
    password = st.text_input("Password for encryption", type="password")
    if uploaded_file and password:
        if st.button("Encrypt File"):
            file_data = uploaded_file.read().decode(errors="ignore")
            encrypted_data = aes_encrypt(file_data, password)
            st.session_state.user_files[uploaded_file.name] = encrypted_data
            st.success("✅ File encrypted!")
            st.download_button("Download Encrypted File", encrypted_data, file_name=f"{uploaded_file.name}.enc")

# --- File Decryption ---
def file_decryption():
    st.subheader("🔓 File Decryption")
    encrypted_files = [k for k in st.session_state.user_files if k != "messages"]
    if not encrypted_files:
        st.info("No encrypted files available.")
        return

    file_name = st.selectbox("Select an encrypted file", options=encrypted_files)
    password = st.text_input("Password to decrypt", type="password")
    if st.button("Decrypt File"):
        encrypted = st.session_state.user_files.get(file_name)
        try:
            decrypted = aes_decrypt(encrypted, password)
            st.success("✅ File decrypted!")
            st.download_button("Download Decrypted File", decrypted, file_name=f"decrypted_{file_name}")
        except Exception:
            st.error("❌ Incorrect password or file is corrupted.")

# --- Main App Logic ---
def main():
    

    st.markdown("""
        <style>
        [data-testid="stSidebar"] {
            background-color: #CCCCFF;
        }
        .stButton > button {
            background-color: #292966;
            color: #CCCFFF;
            font-weight: bold;
            border: none;
            border-radius: 8px;
            padding: 0.5rem 1rem;
            transition: 0.3s;
        }
        .stButton > button:hover {
            background-color: #A3A3CC;
            color: #292966;
        }
        </style>
    """, unsafe_allow_html=True)
# Sidebar Customization
st.sidebar.markdown(
    "<h1 style='text-align: center; font-size: 24px;'>🔐 Secure Encryption App</h1>",
    unsafe_allow_html=True
)
st.sidebar.write("")

# Description text
st.sidebar.markdown(
    "<p style='text-align: center; font-size: 14px; color: #292966;'>"
    "🔐 Welcome to <b>SecureVault</b> — Your trusted vault for secure data storage and encryption. 🔑"
    "</p>",
    unsafe_allow_html=True
)

# Spacer
st.sidebar.write("")

# Option for authentication or user interaction
if not st.session_state.is_authenticated:
    auth_option = st.sidebar.selectbox("🔐 Secure Access - Choose Your Path", ["Login", "Register"])
    if auth_option == "Register":
        register_user()
    elif auth_option == "Login":
        authenticate_user()
else:
    # Personalized greeting for authenticated users
    st.sidebar.markdown(
        f"<p style='color:#808034; font-weight:bold;'>👋 Welcome, {st.session_state.username}</p>",
        unsafe_allow_html=True
    )

    # Action menu for authenticated users
    menu = st.sidebar.selectbox("Choose Action", [
        "Send Message", "View Messages", "Encrypt File", "Decrypt File", "Logout"
    ])

    if menu == "Send Message":
        send_message()
    elif menu == "View Messages":
        view_messages()
    elif menu == "Encrypt File":
        file_encryption()
    elif menu == "Decrypt File":
        file_decryption()
    elif menu == "Logout":
        st.session_state.is_authenticated = False
        st.session_state.username = ""
        st.session_state.user_files = {"messages": []}
        st.rerun()


# --- Run App ---
if __name__ == "__main__":
    main()
