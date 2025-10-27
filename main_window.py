import json
import tkinter as tk
from tkinter import ttk, messagebox, Menu
import os
import platform
import subprocess
import threading
from encryption_window import EncryptionWindow

class MainWindow:
    def __init__(self, root):
        self.active_encryption_window = None
        self.root = root
        self.root.title("Шифровальщик USB-накопителей")
        self.root.geometry("1000x600")
        self.root.minsize(800, 500)
        self.root.configure(bg="#f0f0f0")

        # Верхнее меню
        top_button_frame = tk.Frame(root, bg="#e0e0e0", height=40)
        top_button_frame.pack(side="top", fill="x", padx=5, pady=5)
        top_button_frame.pack_propagate(False)

        btn_encrypt = ttk.Button(top_button_frame, text="Шифровать", command=self.encrypt_selected, width=12)
        btn_encrypt.pack(side="left", padx=5, pady=5)

        btn_decrypt = ttk.Button(top_button_frame, text="Расшифровать", command=self.decrypt_selected, width=14)
        btn_decrypt.pack(side="left", padx=5, pady=5)

        btn_settings = ttk.Button(top_button_frame, text="Настройки", command=self.open_settings, width=12)
        btn_settings.pack(side="left", padx=5, pady=5)

        btn_help = ttk.Button(top_button_frame, text="Помощь", command=self.open_help, width=12)
        btn_help.pack(side="left", padx=5, pady=5)

        btn_about = ttk.Button(top_button_frame, text="О программе", command=self.show_about, width=13)
        btn_about.pack(side="left", padx=5, pady=5)

        # --- Левая боковая панель (USB-устройства) ---
        left_frame = tk.Frame(root, bg="#e0e0e0", width=300)
        left_frame.pack(side="left", fill="y", padx=5, pady=5)
        left_frame.pack_propagate(False)

        tk.Label(left_frame, text="Подключённые USB-накопители", font=("Arial", 12, "bold"), bg="#e0e0e0").pack(pady=(10, 5))

        # Список устройств
        self.usb_listbox = tk.Listbox(left_frame, selectmode="single", height=20, bg="white", relief="flat")
        self.usb_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self.usb_listbox.bind("<<ListboxSelect>>", self.on_usb_select)

        # --- Центральная область (информация) ---
        center_frame = tk.Frame(root, bg="white", padx=10, pady=10)
        center_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        tk.Label(center_frame, text="Детальная информация", font=("Arial", 14, "bold"), bg="white").pack(anchor="w", pady=(0, 10))

        self.info_text = tk.Text(center_frame, wrap="word", state="disabled", bg="white", relief="flat", height=20)
        self.info_text.pack(fill="both", expand=True)

        # --- Нижняя панель (статус и прогресс) ---
        bottom_frame = tk.Frame(root, bg="#d0d0d0", height=40)
        bottom_frame.pack(side="bottom", fill="x", padx=5, pady=5)
        bottom_frame.pack_propagate(False)

        self.status_label = tk.Label(bottom_frame, text="Готов к работе...", anchor="w", bg="#d0d0d0")
        self.status_label.pack(side="left", padx=10)

        self.progress = ttk.Progressbar(bottom_frame, mode="indeterminate")
        self.progress.pack(side="right", padx=10, fill="x", expand=True)

        # Загрузка устройств при запуске
        self.scan_usb_drives()

    def scan_usb_drives(self):
        """Сканирует и заполняет список USB-устройств"""
        drives = self.get_usb_drives()  # ← Этот метод должен быть отдельно!
        self.usb_listbox.delete(0, tk.END)
        for drive in drives:
            info = self.get_drive_info(drive)
            status = "Зашифровано" if info.get("encrypted", False) else "Не зашифровано"
            display = f"{info['name']} ({info['size']}) — {status}"
            self.usb_listbox.insert(tk.END, display)
            self.usb_listbox.itemconfig(tk.END, {'fg': 'red' if info.get("encrypted") else 'black'})

    def get_usb_drives(self):
        """Возвращает список USB-дисков (Windows/Linux/Mac)"""
        drives = []
        system = platform.system()
        if system == "Windows":
            import string
            from ctypes import windll
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    try:
                        if windll.kernel32.GetDriveTypeW(drive) == 2:  # DRIVE_REMOVABLE
                            drives.append(drive)
                    except Exception:
                        continue
        elif system == "Linux":
            base = "/media/"
            if os.path.exists(base):
                for user in os.listdir(base):
                    user_path = os.path.join(base, user)
                    if os.path.isdir(user_path):
                        for device in os.listdir(user_path):
                            drives.append(os.path.join(user_path, device))
        elif system == "Darwin":  # macOS
            base = "/Volumes/"
            if os.path.exists(base):
                for volume in os.listdir(base):
                    if not volume.startswith('.'):
                        drives.append(os.path.join(base, volume))
        return drives

    def get_drive_name(self, path):
        """Возвращает понятное имя устройства (метку тома или букву диска)"""
        system = platform.system()
        try:
            if system == "Windows":
                import subprocess
                # Получаем метку тома через vol
                result = subprocess.run(
                    ["vol", path[0] + ":"],
                    capture_output=True, text=True, shell=True
                )
                for line in result.stdout.splitlines():
                    if "тома" in line or "Volume" in line:
                        parts = line.split(" ")
                        # Пример: "Том в устройстве E имеет метку USB_DRIVE"
                        if "метку" in line:
                            return line.split("метку")[-1].strip()
                        elif "is" in line:
                            # Английский: "Volume in drive E is USB_DRIVE"
                            return line.split("is")[-1].strip()
                # Если метки нет — возвращаем букву диска
                return f"{path[0]}:"
            elif system == "Linux":
                return os.path.basename(path)
            elif system == "Darwin":
                return os.path.basename(path)
        except Exception as e:
            print(f"Не удалось получить имя устройства: {e}")
            return os.path.basename(path) or path

    def get_drive_info(self, path):
        name = self.get_drive_name(path)  # ← Используем новую функцию
        total, used, free = shutil.disk_usage(path) if os.path.exists(path) else (0, 0, 0)
        size_gb = total // (1024**3)
        free_gb = free // (1024**3)
        fs_type = self.get_filesystem_type(path)
        meta_path = os.path.join(path, ".usb_crypt_meta.json")
        encrypted = os.path.exists(meta_path)
        
        if encrypted:
            try:
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                algorithm = meta.get("algorithm", "AES-256-GCM")
            except:
                algorithm = "Неизвестен"
        else:
            algorithm = "—"

        return {
            "name": name,
            "size": f"{size_gb} ГБ",
            "free": f"{free_gb} ГБ свободно",
            "fs": fs_type,
            "encrypted": encrypted,
            "algorithm": algorithm
        }

    def get_filesystem_type(self, path):
        """Определяет тип файловой системы"""
        system = platform.system()
        try:
            if system == "Windows":
                import subprocess

                # Попробуем через wmic (более надёжно)
                try:
                    result = subprocess.run(
                        ["wmic", "volume", "where", f"DriveLetter='{path[0]}:'", "get", "FileSystem"],
                        capture_output=True, text=True, check=True
                    )
                    for line in result.stdout.splitlines():
                        if line.strip() and not line.startswith("FileSystem"):
                            return line.strip()
                except Exception:
                    pass

                # Если wmic не сработал — пробуем fsutil
                try:
                    output = subprocess.check_output(f'fsutil fsinfo volumeinfo {path}', shell=True, text=True)
                    for line in output.splitlines():
                        if "File System Name" in line:
                            return line.split(":")[1].strip()
                except Exception:
                    pass

                return "FAT32/NTFS/exFAT"

            elif system == "Linux":
                result = subprocess.run(
                    ["df", "-T", path],
                    capture_output=True, text=True, check=True
                )
                lines = result.stdout.strip().splitlines()
                if len(lines) >= 2:
                    return lines[1].split()[1]
                return "ext4/FAT32/exFAT"

            elif system == "Darwin":  # macOS
                result = subprocess.run(
                    ["diskutil", "info", path],
                    capture_output=True, text=True, check=True
                )
                for line in result.stdout.splitlines():
                    if "File System Personality" in line:
                        return line.split(":")[1].strip()
                return "APFS/HFS+"

        except Exception as e:
            print(f"Ошибка определения ФС: {e}")
            return "Неизвестная ФС"

    def on_usb_select(self, event):
        """Обновляет информацию при выборе устройства"""
        selection = self.usb_listbox.curselection()
        if not selection:
            return

        index = selection[0]
        drive = self.get_usb_drives()[index]
        info = self.get_drive_info(drive)

        text = f"Имя устройства: {info['name']}\n"
        text += f"Объём: {info['size']}\n"
        text += f"Свободное место: {info['free']}\n"
        text += f"Файловая система: {info['fs']}\n"
        text += f"Алгоритм шифрования: {info['algorithm']}\n"
        text += f"Статус: {'✅ Зашифровано' if info['encrypted'] else '❌ Не зашифровано'}"

        self.info_text.config(state="normal")
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(tk.END, text)
        self.info_text.config(state="disabled")

    def encrypt_selected(self):
        """Открывает окно шифрования"""
        selection = self.usb_listbox.curselection()
        if not selection:
            messagebox.showwarning("Ошибка", "Выберите USB-накопитель.")
            return

        drive = self.get_usb_drives()[selection[0]]
        if self.active_encryption_window is None or not self.active_encryption_window.winfo_exists():
            from encryption_window import EncryptionWindow
            self.active_encryption_window = EncryptionWindow(self, drive, mode="encrypt").win
        else:
            messagebox.showinfo("Информация", "Окно шифрования уже открыто.")

    def decrypt_selected(self):
        """Открывает окно расшифровки"""
        selection = self.usb_listbox.curselection()
        if not selection:
            messagebox.showwarning("Ошибка", "Выберите USB-накопитель.")
            return

        drive = self.get_usb_drives()[selection[0]]
        if self.active_encryption_window is None or not self.active_encryption_window.winfo_exists():
            from encryption_window import EncryptionWindow
            self.active_encryption_window = EncryptionWindow(self, drive, mode="decrypt").win
        else:
            messagebox.showinfo("Информация", "Окно шифрования уже открыто.")

    def start_operation(self, message, success_msg):
        """Запускает операцию в отдельном потоке с анимацией прогресса"""
        self.status_label.config(text=message)
        self.progress.start()

        def simulate_work():
            import time
            time.sleep(3)  # Имитация работы
            self.root.after(0, lambda: self.finish_operation(success_msg))

        thread = threading.Thread(target=simulate_work)
        thread.daemon = True
        thread.start()

    def finish_operation(self, msg):
        """Завершение операции"""
        self.progress.stop()
        self.status_label.config(text=msg)
        messagebox.showinfo("Готово", msg)
        self.scan_usb_drives()  # Обновляем список

    def open_settings(self):
        """Открывает окно настроек"""
        from settings_window import SettingsWindow
        SettingsWindow(self)

    def show_about(self):
        """Открывает окно помощи"""
        from help_window import HelpWindow
        HelpWindow(self)

    def open_help(self):
        """Открывает окно помощи"""
        from help_window import HelpWindow
        HelpWindow(self)

# Добавим импорт для disk_usage
try:
    import shutil
except ImportError:
    shutil = None

if __name__ == "__main__":
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()