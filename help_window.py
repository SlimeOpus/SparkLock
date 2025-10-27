import tkinter as tk
from tkinter import ttk, messagebox

class HelpWindow:
    def __init__(self, parent):
        self.parent = parent

        # Создаём модальное окно
        self.win = tk.Toplevel(parent.root)
        self.win.title("Помощь")
        self.win.geometry("700x500")
        self.win.resizable(True, True)
        self.win.transient(parent.root)
        self.win.grab_set()

        # --- Заголовок ---
        tk.Label(self.win, text="Помощь", font=("Arial", 16, "bold")).pack(pady=(10, 5))

        # --- Вкладки ---
        notebook = ttk.Notebook(self.win)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Вкладка: Инструкции
        instructions_frame = tk.Frame(notebook)
        notebook.add(instructions_frame, text="📌 Инструкции")

        instructions_text = tk.Text(instructions_frame, wrap="word", bg="white", relief="flat", font=("Arial", 11))
        instructions_text.pack(fill="both", expand=True, padx=10, pady=10)

        instructions_content = """
=== Как использовать программу ===

1. Подключите USB-накопитель к компьютеру.
2. В главном окне выберите устройство из списка слева.
3. Нажмите «Шифровать» или «Расшифровать» в верхнем меню.
4. В открывшемся окне:
   - Введите пароль и подтвердите его.
   - Выберите алгоритм шифрования (по умолчанию AES-256).
   - Нажмите «Начать».
5. Дождитесь завершения операции — отобразится прогресс и оставшееся время.
6. После завершения вы можете безопасно извлечь флешку.

⚠️ Важно:
- Не прерывайте процесс шифрования — это может повредить данные.
- Пароль не восстанавливается! Сохраните его в надёжном месте.
- Рекомендуется делать резервную копию важных данных перед шифрованием.
"""

        instructions_text.insert(tk.END, instructions_content)
        instructions_text.config(state="disabled")  # только для чтения

        # Вкладка: FAQ
        faq_frame = tk.Frame(notebook)
        notebook.add(faq_frame, text="❓ FAQ")

        faq_text = tk.Text(faq_frame, wrap="word", bg="white", relief="flat", font=("Arial", 11))
        faq_text.pack(fill="both", expand=True, padx=10, pady=10)

        faq_content = """
=== Часто задаваемые вопросы ===

Q: Что делать, если я забыл пароль?
A: К сожалению, без пароля расшифровать данные невозможно. Программа не хранит пароли.

Q: Можно ли шифровать системный диск?
A: Нет. Программа работает только с съёмными носителями (USB, SD-карты).

Q: Почему после шифрования флешка не видна в других ОС?
A: Убедитесь, что вы используете совместимую файловую систему (NTFS/FAT32/exFAT). Linux/macOS могут требовать установки дополнительных драйверов.

Q: Как проверить, зашифрован ли накопитель?
A: В главном окне рядом с устройством отображается статус: «Зашифровано» или «Не зашифровано».

Q: Где хранятся настройки программы?
A: В файле config.json в папке с программой.

Q: Можно ли шифровать отдельные файлы, а не весь диск?
A: Сейчас программа шифрует весь накопитель целиком. Для шифрования отдельных файлов используйте другие инструменты.
"""

        faq_text.insert(tk.END, faq_content)
        faq_text.config(state="disabled")

        # Вкладка: Поддержка
        support_frame = tk.Frame(notebook)
        notebook.add(support_frame, text="📧 Поддержка")

        support_text = tk.Text(support_frame, wrap="word", bg="white", relief="flat", font=("Arial", 11))
        support_text.pack(fill="both", expand=True, padx=10, pady=10)

        support_content = """
=== Контактная информация ===

Если у вас возникли проблемы или есть предложения:

📧 Электронная почта: support@usb-crypt.com
🌐 Официальный сайт: https://usb-crypt.com
📖 Документация: https://usb-crypt.com/docs
💬 Форум: https://usb-crypt.com/forum

💡 Отправьте нам:
- Версию программы
- Описание проблемы
- Скриншот ошибки (если есть)
- Лог-файл (если включено в настройках)

Мы ответим в течение 24 часов.
"""

        support_text.insert(tk.END, support_content)
        support_text.config(state="disabled")

        # Кнопка закрытия
        tk.Button(self.win, text="Закрыть", command=self.win.destroy, width=15).pack(pady=10)

# Пример использования (для тестирования)
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # скрываем главное окно
    win = HelpWindow(root)
    root.mainloop()