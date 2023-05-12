import tkinter as tk
import hashlib
from tkinter import filedialog

class App(tk.Tk):
    def _init_(self):
        super()._init_()
        self.title("Dosya Hash Hesaplama")
        self.geometry("400x300")

        self.filename = ""

        self.selected_file_label = tk.Label(self, text="Dosya Seçilmedi", font=("Arial", 12))
        self.selected_file_label.pack(pady=10)

        self.hash_type_label = tk.Label(self, text="Hash Türü:", font=("Arial", 12))
        self.hash_type_label.pack(pady=5)

        self.hash_type_var = tk.StringVar()
        self.hash_type_var.set("md5")

        self.hash_type_menu = tk.OptionMenu(self, self.hash_type_var, "md5", "sha1", "sha256", "sha512")
        self.hash_type_menu.pack(pady=5)

        self.calculate_button = tk.Button(self, text="Hash Hesapla", command=self.calculate_hash)
        self.calculate_button.pack(pady=10)

        self.hash_entry = tk.Entry(self, font=("Arial", 12), width=40)
        self.hash_entry.pack(pady=10)

        self.check_button = tk.Button(self, text="Dosya Doğrula", command=self.check_hash)
        self.check_button.pack(pady=10)

        self.result_label = tk.Label(self, text="", font=("Arial", 12))
        self.result_label.pack(pady=10)

    def select_file(self):
        self.filename = filedialog.askopenfilename(initialdir="/", title="Dosya Seç", filetypes=[("All Files", ".")])
        self.selected_file_label.config(text=self.filename)

    def calculate_hash(self):
        hash_type = self.hash_type_var.get()
        if self.filename == "":
            self.result_label.config(text="Lütfen bir dosya seçin.")
        else:
            with open(self.filename, "rb") as f:
                if hash_type == "md5":
                    h = hashlib.md5()
                elif hash_type == "sha1":
                    h = hashlib.sha1()
                elif hash_type == "sha256":
                    h = hashlib.sha256()
                elif hash_type == "sha512":
                    h = hashlib.sha512()
                else:
                    self.result_label.config(text="Geçersiz hash türü.")
                    return
                chunk = f.read(4096)
                while chunk:
                    h.update(chunk)
                    chunk = f.read(4096)
                self.hash_entry.delete(0, tk.END)
                self.hash_entry.insert(0, h.hexdigest())
                self.result_label.config(text="Hash başarıyla hesaplandı.")

    def check_hash(self):
        hash_type = self.hash_type_var.get()
        hash_value = self.hash_entry.get()
        if self.filename == "":
            self.result_label.config(text="Lütfen bir dosya seçin.")
        elif hash_value == "":
            self.result_label.config(text="Lütfen bir hash değeri yapıştırın.")
        else:
            with open(self.filename, "rb") as f:
                if hash_type == "md5":
                    h = hashlib.md5()
                elif hash_type == "sha1":
                    h = hashlib.sha1()
                elif hash_type == "sha256":
                    h = hashlib.sha256()
                elif hash