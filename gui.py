import tkinter as tk
from tkinter import Entry, Label, Button
from tkinter import ttk

from aes_gcm import AES_GCM
from sha_256_scratch import SHA_256_Hasher

root = tk.Tk()
aes = AES_GCM()
sha = SHA_256_Hasher()

root.title('SHA-256 Hasher')
combobox = ttk.Combobox(root, values=['SHA-256', 'AES-GCM'])
hash_label = Label(root, text='Message to hash:')
hash_message = Entry(root)
transfer_label = Label(root, text='Message to transfer:')
transfer_message = Entry(root)
secret_label = Label(root, text='Secret:')
secret_key = Entry(root)
combobox.pack(pady=20)
combobox.set('SHA-256')

hashed_label = Label(root, text='Your hashed message is:')
encrypted_label = Label(root, text='Your encrypted message is:')
decrypted_label = Label(root, text=f'Your decrypted message is:')

mode = combobox.get()
hash_label.pack()
hash_message.pack()

def on_enter():
    mode = combobox.get()
    if mode == 'SHA-256':
        transfer_label.pack_forget()
        decrypted_label.pack_forget()
        hashed_message = sha.sha256(str(hash_message.get()))
        hashed_label.config(text=f'Your hashed message is: {hashed_message}')
        hashed_label.pack()
    elif mode == 'AES-GCM':
        hashed_label.pack_forget()
        encrypted_message = aes.encrypt(str(secret_key.get()), str(transfer_message.get()))
        encrypted_label.config(text=f'Your encrypted message is: {encrypted_message}')
        encrypted_label.pack()
        decrypted_message = aes.decrypt(str(secret_key.get()), encrypted_message)
        decrypted_label.config(text=f'Your decrypted message is: {decrypted_message}')
        decrypted_label.pack()

enter_button = Button(root, text='Enter!', command=on_enter)
enter_button.pack(pady=10)

def on_select(event):
    mode = combobox.get()
    if mode == 'SHA-256':
        transfer_label.pack_forget()
        transfer_message.pack_forget()
        secret_label.pack_forget()
        secret_key.pack_forget()
        decrypted_label.pack_forget()
        hash_label.pack()
        hash_message.pack()

    elif mode == 'AES-GCM':
        enter_button.pack_forget()
        hash_label.pack_forget()
        hash_message.pack_forget()
        hashed_label.pack_forget()
        transfer_label.pack()
        transfer_message.pack()
        secret_label.pack()
        secret_key.pack()
        enter_button.pack(pady=20)
combobox.bind('<<ComboboxSelected>>', on_select)

root.mainloop()
