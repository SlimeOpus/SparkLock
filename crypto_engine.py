import os
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import base64

METADATA_FILE = ".usb_crypt_meta.json"

def derive_key(password: str, salt: bytes, key_size: int = 32) -> bytes:
    """Генерирует ключ нужной длины из пароля и соли"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, algorithm: str, key: bytes):
    """Шифрует файл в зависимости от выбранного алгоритма"""
    data = Path(file_path).read_bytes()
    
    if algorithm == "AES-256-GCM":
        nonce = os.urandom(12)
        cipher = AESGCM(key)
        encrypted_data = cipher.encrypt(nonce, data, None)
    elif algorithm == "ChaCha20":
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(key)
        encrypted_data = cipher.encrypt(nonce, data, None)
    else:
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")

    encrypted_path = file_path + ".encrypted"
    Path(encrypted_path).write_bytes(encrypted_data)
    os.remove(file_path)
    return nonce

def decrypt_file(file_path: str, algorithm: str, key: bytes, nonce: bytes):
    """Расшифровывает файл в зависимости от алгоритма"""
    encrypted_data = Path(file_path).read_bytes()

    if algorithm == "AES-256-GCM":
        cipher = AESGCM(key)
    elif algorithm == "ChaCha20":
        cipher = ChaCha20Poly1305(key)
    else:
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")

    try:
        decrypted_data = cipher.decrypt(nonce, encrypted_data, None)
    except Exception as e:
        raise ValueError("Неверный пароль или повреждённые данные") from e

    original_path = file_path.replace(".encrypted", "")
    Path(original_path).write_bytes(decrypted_data)
    os.remove(file_path)

def save_metadata(drive_path: str, salt: bytes, file_nonces: dict, algorithm: str):
    """Сохраняет метаданные на флешку"""
    meta = {
        "algorithm": algorithm,
        "salt": base64.b64encode(salt).decode(),
        "files": {
            rel_path: {
                "nonce": base64.b64encode(nonce).decode(),
                "nonce_size": len(nonce)
            }
            for rel_path, nonce in file_nonces.items()
        }
    }
    meta_path = os.path.join(drive_path, METADATA_FILE)
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)

def load_metadata(drive_path: str):
    """Загружает метаданные с флешки"""
    meta_path = os.path.join(drive_path, METADATA_FILE)
    if not os.path.exists(meta_path):
        raise FileNotFoundError("Метаданные не найдены. Устройство не зашифровано.")
    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    salt = base64.b64decode(meta["salt"])
    files = {}
    for rel_path, info in meta["files"].items():
        nonce = base64.b64decode(info["nonce"])
        files[rel_path] = nonce
    return salt, files, meta["algorithm"]

def is_encrypted(drive_path: str) -> bool:
    return os.path.exists(os.path.join(drive_path, METADATA_FILE))

def encrypt_drive(drive_path: str, password: str, algorithm: str = "AES-256-GCM", progress_callback=None):
    if is_encrypted(drive_path):
        raise ValueError("Накопитель уже зашифрован!")

    # Определяем длину ключа
    key_size = 32  # все три алгоритма используют 256-битный ключ
    salt = os.urandom(16)
    key = derive_key(password, salt, key_size)

    all_files = []
    for root, dirs, files in os.walk(drive_path):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('System Volume Information', '$RECYCLE.BIN')]
        for f in files:
            if f == METADATA_FILE or f.startswith('.'):
                continue
            all_files.append(os.path.join(root, f))

    total = len(all_files)
    file_nonces = {}

    for i, file_path in enumerate(all_files):
        try:
            rel_path = os.path.relpath(file_path, drive_path)
            nonce = encrypt_file(file_path, algorithm, key)
            file_nonces[rel_path] = nonce
        except Exception as e:
            print(f"⚠️ Пропущен файл {file_path}: {e}")
        if progress_callback:
            progress_callback(i + 1, total)

    save_metadata(drive_path, salt, file_nonces, algorithm)
    return total

def decrypt_drive(drive_path: str, password: str, progress_callback=None):
    if not is_encrypted(drive_path):
        raise ValueError("Накопитель не зашифрован!")

    salt, file_nonces, algorithm = load_metadata(drive_path)
    key = derive_key(password, salt, 32)

    total = len(file_nonces)
    for i, (rel_path, nonce) in enumerate(file_nonces.items()):
        encrypted_path = os.path.join(drive_path, rel_path + ".encrypted")
        if not os.path.exists(encrypted_path):
            print(f"⚠️ Файл не найден: {encrypted_path}")
            continue
        try:
            decrypt_file(encrypted_path, algorithm, key, nonce)
        except Exception as e:
            raise ValueError(f"Ошибка расшифровки файла {rel_path}: {e}")
        if progress_callback:
            progress_callback(i + 1, total)

    os.remove(os.path.join(drive_path, METADATA_FILE))
    return total