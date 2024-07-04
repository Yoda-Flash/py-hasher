import tkinter as tk
from tkinter import Entry, Label
from tkinter import ttk

root = tk.Tk()

def on_select(event):
    mode = combobox.get()
    print(mode)
    if mode == 'SHA-256':
        Label(root, text='Message to hash:').pack()
        message = Entry(root)
        message.pack()
    elif mode == 'AES-GCM':
        Label(root, text='Message to transfer:').pack()
        message = Entry(root)
        message.pack()
        Label(root, text='Secret key:').pack()
        secret = Entry(root)
        secret.pack()

root.title('SHA-256 Hasher')
combobox = ttk.Combobox(root, values=['SHA-256', 'AES-GCM'])
combobox.pack(pady=20)
combobox.set('SHA-256')
combobox.bind('<<ComboboxSelected>>', on_select)

root.mainloop()