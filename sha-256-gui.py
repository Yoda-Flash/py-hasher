import tkinter as tk
from tkinter import Entry, Label
from tkinter import ttk

tk = tk.Tk()

tk.title('SHA-256 Hasher')
combobox = ttk.Combobox(tk, values=['SHA-256', 'AES-GCM'])
combobox.pack(pady=20)
combobox.set('SHA-256')
mode = combobox.get()
# if mode == 'SHA-256':
Label(tk, text='Message to hash:')
message = Entry(tk)

tk.mainloop()