import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import os
import datetime

def run_footprinting():
    target = entry.get().strip()
    if not target:
        messagebox.showerror("Fout", "Voer een domein of IP-adres in.")
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = f"recon-{target}-{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    output_text.insert(tk.END, f"[+] Start scanning {target}\nOutput folder: {output_dir}\n\n")
    output_text.see(tk.END)
    root.update()

    commands = {
        "WHOIS": f"whois {target}",
        "DNS Lookup": f"nslookup {target}",
        "Ping": f"ping -c 4 {target}" if os.name != 'nt' else f"ping {target}",
    }

    for name, cmd in commands.items():
        output_text.insert(tk.END, f"[+] Running {name}...\n")
        try:
            result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
            with open(f"{output_dir}/{name.replace(' ', '_').lower()}.txt", "w") as f:
                f.write(result)
            output_text.insert(tk.END, f"[✔] {name} voltooid\n\n")
        except subprocess.CalledProcessError as e:
            output_text.insert(tk.END, f"[!] {name} mislukt: {e.output}\n\n")
        output_text.see(tk.END)
        root.update()

    output_text.insert(tk.END, f"🎉 Footprinting voltooid! Bekijk de map: {output_dir}\n")

# GUI Setup
root = tk.Tk()
root.title("Footprinting GUI Tool")
root.geometry("600x400")

tk.Label(root, text="Voer een domein of IP-adres in:").pack(pady=5)
entry = tk.Entry(root, width=50)
entry.pack(pady=5)

tk.Button(root, text="Start Footprinting", command=run_footprinting).pack(pady=10)

output_text = scrolledtext.ScrolledText(root, width=70, height=15)
output_text.pack(padx=10, pady=10)

root.mainloop()