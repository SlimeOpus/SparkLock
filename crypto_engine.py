import os
import json
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

METADATA_FILE = ".usb_crypt_meta.json"

def derive_key(password: str, salt: bytes) -> bytes:
    """Генерирует 32-байтный ключ из пароля и соли (PBKDF2 + SHA256)"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, key: bytes):
    """Шифрует файл с помощью AES-GCM и добавляет .encrypted"""
    data = Path(file_path).read_bytes()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce, data, None)

    # Сохраняем как <имя>.encrypted
    encrypted_path = file_path + ".encrypted"
    Path(encrypted_path).write_bytes(encrypted_data)

    # Удаляем оригинал
    os.remove(file_path)

    return nonce

def decrypt_file(file_path: str, key: bytes, nonce: bytes):
    """Расшифровывает .encrypted файл"""
    encrypted_data = Path(file_path).read_bytes()
    aesgcm = AESGCM(key)

    try:
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
    except Exception as e:
        raise ValueError("Неверный пароль или повреждённые данные") from e

    original_path = file_path.replace(".encrypted", "")
    Path(original_path).write_bytes(decrypted_data)
    os.remove(file_path)

def save_metadata(drive_path: str, salt: bytes, file_nonces: dict, algorithm: str = "AES-256-GCM"):
    """Сохраняет метаданные на флешку"""
    meta = {
        "algorithm": algorithm,
        "salt": base64.b64encode(salt).decode(),
        "files": {
            rel_path: base64.b64encode(nonce).decode()
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
    files = {
        rel_path: base64.b64decode(nonce_b64)
        for rel_path, nonce_b64 in meta["files"].items()
    }
    return salt, files, meta["algorithm"]

def is_encrypted(drive_path: str) -> bool:
    """Проверяет, зашифрован ли накопитель"""
    return os.path.exists(os.path.join(drive_path, METADATA_FILE))

def encrypt_drive(drive_path: str, password: str, progress_callback=None):
    """Шифрует весь накопитель"""
    if is_encrypted(drive_path):
        raise ValueError("Накопитель уже зашифрован!")

    salt = os.urandom(16)
    key = derive_key(password, salt)
    file_nonces = {}

    # Собираем все файлы (рекурсивно, кроме скрытых и системных)
    all_files = []
    for root, dirs, files in os.walk(drive_path):
        # Пропускаем скрытые папки (например, .Trash-1000)
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('System Volume Information', '$RECYCLE.BIN')]
        for f in files:
            if f == METADATA_FILE or f.startswith('.'):
                continue
            file_path = os.path.join(root, f)
            all_files.append(file_path)

    total = len(all_files)
    for i, file_path in enumerate(all_files):
        try:
            rel_path = os.path.relpath(file_path, drive_path)
            nonce = encrypt_file(file_path, key)
            file_nonces[rel_path] = nonce
        except Exception as e:
            print(f"⚠️ Пропущен файл {file_path}: {e}")

        if progress_callback:
            progress_callback(i + 1, total)

    # Сохраняем метаданные
    save_metadata(drive_path, salt, file_nonces)
    return total

def decrypt_drive(drive_path: str, password: str, progress_callback=None):
    """Расшифровывает весь накопитель"""
    if not is_encrypted(drive_path):
        raise ValueError("Накопитель не зашифрован!")

    salt, file_nonces, _ = load_metadata(drive_path)
    key = derive_key(password, salt)

    total = len(file_nonces)
    for i, (rel_path, nonce) in enumerate(file_nonces.items()):
        encrypted_path = os.path.join(drive_path, rel_path + ".encrypted")
        if not os.path.exists(encrypted_path):
            print(f"⚠️ Файл не найден: {encrypted_path}")
            continue

        try:
            decrypt_file(encrypted_path, key, nonce)
        except Exception as e:
            raise ValueError(f"Ошибка расшифровки файла {rel_path}: {e}")

        if progress_callback:
            progress_callback(i + 1, total)

    # Удаляем метаданные
    os.remove(os.path.join(drive_path, METADATA_FILE))
    return total