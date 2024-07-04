import tkinter as tk
from tkinter import Entry, Label
from tkinter import ttk
# from sha-256-scratch import Sha256Hasher

root = tk.Tk()

root.title('SHA-256 Hasher')
combobox = ttk.Combobox(root, values=['SHA-256', 'AES-GCM'])
hash_label = Label(root, text='Message to hash:')
hash_message = message = Entry(root)
transfer_label = Label(root, text='Message to transfer:')
transfer_message = Entry(root)
secret_label = Label(root, text='Secret:')
secret_message = Entry(root)
combobox.pack(pady=20)
combobox.set('SHA-256')
mode = combobox.get()
hash_label.pack()
hash_message.pack()


def on_select(event):
    mode = combobox.get()
    if mode == 'SHA-256':
        transfer_label.pack_forget()
        transfer_message.pack_forget()
        secret_label.pack_forget()
        secret_message.pack_forget()
        hash_label.pack()
        hash_message.pack()
    elif mode == 'AES-GCM':
        hash_label.pack_forget()
        hash_message.pack_forget()
        transfer_label.pack()
        transfer_message.pack()
        secret_label.pack()
        secret_message.pack()

combobox.bind('<<ComboboxSelected>>', on_select)

root.mainloop()