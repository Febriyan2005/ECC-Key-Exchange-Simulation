import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, time, binascii, threading

# ---------------------------
# Requirements:
# pip install cryptography
# ---------------------------

# ======================================
# KONFIGURASI & SETUP
# ======================================
CURVE_MAP = {
    "SECP256R1 (prime256v1)": ec.SECP256R1(),
    "SECP384R1": ec.SECP384R1(),
    "SECP521R1": ec.SECP521R1(),
}

RECEIVED_DIR = "received_files"
os.makedirs(RECEIVED_DIR, exist_ok=True)

# ======================================
# CUSTOM WIDGETS
# ======================================
class CyberButton(tk.Button):
    def __init__(self, master, **kwargs):
        bg_color = kwargs.pop('bg', "#073f5f")
        hover_color = "#0a8fb0"
        super().__init__(master, **kwargs)
        self.configure(bg=bg_color, fg="white", activebackground=hover_color, 
                       activeforeground="white", bd=0, relief="flat", cursor="hand2",
                       font=("Segoe UI", 10, "bold"), padx=12, pady=5)
        self.bind("<Enter>", lambda e: self.config(bg=hover_color))
        self.bind("<Leave>", lambda e: self.config(bg=bg_color))

# ======================================
# APLIKASI UTAMA
# ======================================
class ECDHChatApp:
    def __init__(self, root):
        self.root = root
        root.title("ECDH Secure Chat — Cyber Enterprise")
        
        # --- Full Screen Setup ---
        try:
            root.state('zoomed') 
        except:
            root.attributes('-fullscreen', True) 

        # --- Theme Colors ---
        self.bg_top = "#051626"
        self.bg_bottom = "#020b12"
        self.card_bg = "#0e1720"
        self.card_border = "#1c3a4f"
        self.accent = "#00E0FF"
        self.text_primary = "#d7eef6"
        self.mono_font = ("Consolas", 10)

        # --- Main Layout ---
        root.configure(bg=self.bg_bottom)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=0) # Header
        root.rowconfigure(1, weight=2) # Chat Area
        root.rowconfigure(2, weight=1) # Bottom Info Area

        # --- Variables ---
        self.alice_priv = None
        self.bob_priv = None
        self.alice_pub = None
        self.bob_pub = None
        self.shared_key = None

        # --- Build UI ---
        self._build_header()
        self._build_chat_area()
        self._build_bottom_area()
        self._setup_styles()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Cyber.Horizontal.TProgressbar", 
                        troughcolor='#08131b', 
                        background=self.accent, 
                        bordercolor=self.card_border, 
                        lightcolor=self.accent, 
                        darkcolor=self.accent)

    # ----------------------------
    # UI: HEADER
    # ----------------------------
    def _build_header(self):
        header_frame = tk.Frame(self.root, bg=self.card_bg, pady=10, padx=20)
        header_frame.grid(row=0, column=0, sticky="ew")
        
        # Garis aksen bawah header
        tk.Frame(header_frame, bg=self.accent, height=2).pack(side="bottom", fill="x")

        # Container Tombol
        ctrl_frame = tk.Frame(header_frame, bg=self.card_bg)
        ctrl_frame.pack(side="top", fill="x", pady=5)

        # Dropdown Curve
        tk.Label(ctrl_frame, text="ECC Curve:", bg=self.card_bg, fg="white", font=("Segoe UI", 11)).pack(side="left", padx=5)
        self.curve_cb = ttk.Combobox(ctrl_frame, values=list(CURVE_MAP.keys()), state="readonly", width=25)
        self.curve_cb.current(0)
        self.curve_cb.pack(side="left", padx=5)

        # Tombol Aksi Utama
        CyberButton(ctrl_frame, text="1. Generate Keys", command=self.generate_keys).pack(side="left", padx=10)
        CyberButton(ctrl_frame, text="2. Hitung Shared Key", command=self.compute_shared).pack(side="left", padx=10)
        CyberButton(ctrl_frame, text="Reset / Clear", command=self.reset_app, bg="#5f0707").pack(side="right", padx=10)

    # ----------------------------
    # UI: CHAT AREA (TENGAH)
    # ----------------------------
    def _build_chat_area(self):
        chat_container = tk.Frame(self.root, bg=self.bg_bottom, padx=20, pady=10)
        chat_container.grid(row=1, column=0, sticky="nsew")
        
        chat_container.columnconfigure(0, weight=1) # Alice Column
        chat_container.columnconfigure(1, weight=1) # Bob Column
        chat_container.rowconfigure(0, weight=1)

        # --- ALICE PANEL ---
        self.alice_frame = self._create_user_panel(chat_container, "ALICE", 0, self.alice_send_msg, self.alice_send_file)
        self.alice_chat_log = self.alice_frame['log']
        self.alice_input = self.alice_frame['input']

        # --- BOB PANEL ---
        self.bob_frame = self._create_user_panel(chat_container, "BOB", 1, self.bob_send_msg, self.bob_send_file)
        self.bob_chat_log = self.bob_frame['log']
        self.bob_input = self.bob_frame['input']

    def _create_user_panel(self, parent, name, col, send_cmd, file_cmd):
        # Frame Kartu
        frame = tk.Frame(parent, bg=self.card_bg, bd=1, relief="solid")
        frame.grid(row=0, column=col, sticky="nsew", padx=10)
        
        # Judul User
        tk.Label(frame, text=name, bg=self.card_bg, fg=self.accent, font=("Segoe UI", 14, "bold")).pack(pady=5)
        
        # Area Chat Log (Output)
        log = scrolledtext.ScrolledText(frame, bg="#050b10", fg=self.text_primary, 
                                        insertbackground="white", font=self.mono_font, relief="flat")
        log.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Area Input Pesan
        input_frame = tk.Frame(frame, bg=self.card_bg)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        entry = tk.Entry(input_frame, bg="#1a2633", fg="white", font=("Segoe UI", 11), relief="flat", insertbackground="white")
        entry.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=5)
        
        # Tombol Kirim
        CyberButton(input_frame, text="Kirim Pesan", command=send_cmd).pack(side="right")
        CyberButton(input_frame, text="Kirim File", command=file_cmd, bg="#075f48").pack(side="right", padx=5)

        return {'log': log, 'input': entry}

    # ----------------------------
    # UI: BOTTOM INFO (BAWAH)
    # ----------------------------
    def _build_bottom_area(self):
        bottom_frame = tk.Frame(self.root, bg=self.bg_bottom, padx=20, pady=10)
        bottom_frame.grid(row=2, column=0, sticky="nsew")
        
        bottom_frame.columnconfigure(0, weight=1)
        bottom_frame.columnconfigure(1, weight=1)
        bottom_frame.columnconfigure(2, weight=1)
        bottom_frame.rowconfigure(0, weight=1)

        # Kolom 1: Key Info
        self.panel_keys = self._create_info_panel(bottom_frame, "Key Information (Alice & Bob)", 0)
        
        # Kolom 2: Shared Key 
        self.panel_shared = self._create_info_panel(bottom_frame, "Shared Key Calculation", 1)

        # Kolom 3: Simulasi Log
        self.panel_sim = self._create_info_panel(bottom_frame, "Simulation Logs & Steps", 2)
        
        # Tombol Auto Simulation di panel kanan
        btn_frame = tk.Frame(self.panel_sim['frame'], bg=self.card_bg)
        btn_frame.place(relx=1.0, rely=0.0, anchor="ne", x=-5, y=5)
        CyberButton(btn_frame, text="Run Full Simulation", command=self.run_full_simulation, bg="#5f0753").pack()

    def _create_info_panel(self, parent, title, col):
        container = tk.Frame(parent, bg=self.card_bg, bd=1, relief="solid")
        container.grid(row=0, column=col, sticky="nsew", padx=5)
        
        tk.Label(container, text=title, bg=self.card_bg, fg=self.accent, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=5)
        
        text_area = scrolledtext.ScrolledText(container, bg="#02080c", fg="#00ff9d", 
                                              font=("Consolas", 9), relief="flat", height=10)
        text_area.pack(fill="both", expand=True, padx=5, pady=5)
        return {'text': text_area, 'frame': container}

    # ======================================
    # LOGIC: CRYPTOGRAPHY
    # ======================================
    def log_to_panel(self, panel, message):
        panel['text'].insert(tk.END, message + "\n")
        panel['text'].see(tk.END)

    def generate_keys(self):
        curve = CURVE_MAP[self.curve_cb.get()]
        self.alice_priv = ec.generate_private_key(curve)
        self.bob_priv = ec.generate_private_key(curve)
        self.alice_pub = self.alice_priv.public_key()
        self.bob_pub = self.bob_priv.public_key()
        
        # Display to Left Panel
        self.panel_keys['text'].delete("1.0", tk.END)
        apriv_hex = hex(self.alice_priv.private_numbers().private_value)
        apub_bytes = self.alice_pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        bpriv_hex = hex(self.bob_priv.private_numbers().private_value)
        bpub_bytes = self.bob_pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

        self.log_to_panel(self.panel_keys, f"[ALICE]\nPrivate: {apriv_hex[:30]}...\nPublic : {binascii.hexlify(apub_bytes).decode()[:30]}...\n")
        self.log_to_panel(self.panel_keys, f"[BOB]\nPrivate: {bpriv_hex[:30]}...\nPublic : {binascii.hexlify(bpub_bytes).decode()[:30]}...")
        self.log_to_panel(self.panel_sim, ">> Step 1: Alice & Bob Generating ECC Keys...")
        self.shared_key = None
        self.panel_shared['text'].delete("1.0", tk.END) # Reset shared panel

    def compute_shared(self):
        if not self.alice_priv or not self.bob_priv:
            messagebox.showerror("Error", "Generate Keys dulu! (Step 1)")
            return

        # Clear panel
        self.panel_shared['text'].delete("1.0", tk.END)
        self.log_to_panel(self.panel_sim, ">> Step 2: Starting Shared Key Calculation (ECDH Exchange)")
        
        # ----------------------------------------------
        # STEP 2a: ALICE CALCULATES SHARED SECRET
        # Alice menggunakan Private Key-nya dan Public Key Bob
        # ----------------------------------------------
        self.log_to_panel(self.panel_shared, "--- [STEP 2a] ALICE: Computing Raw Shared Secret ---")
        self.log_to_panel(self.panel_shared, "Menggunakan: Alice_Private_Key * Bob_Public_Key")
        shared_a_bytes = self.alice_priv.exchange(ec.ECDH(), self.bob_pub)
        hex_a = binascii.hexlify(shared_a_bytes).decode()
        self.log_to_panel(self.panel_shared, f"Hasil (Raw Shared A): {hex_a[:60]}...")
        self.log_to_panel(self.panel_sim, "    -> Alice selesai menghitung Raw Shared Secret.")

        # ----------------------------------------------
        # STEP 2b: BOB CALCULATES SHARED SECRET
        # Bob menggunakan Private Key-nya dan Public Key Alice
        # ----------------------------------------------
        self.log_to_panel(self.panel_shared, "\n--- [STEP 2b] BOB: Computing Raw Shared Secret ---")
        self.log_to_panel(self.panel_shared, "Menggunakan: Bob_Private_Key * Alice_Public_Key")
        shared_b_bytes = self.bob_priv.exchange(ec.ECDH(), self.alice_pub)
        hex_b = binascii.hexlify(shared_b_bytes).decode()
        self.log_to_panel(self.panel_shared, f"Hasil (Raw Shared B): {hex_b[:60]}...")
        self.log_to_panel(self.panel_sim, "    -> Bob selesai menghitung Raw Shared Secret.")

        # ----------------------------------------------
        # STEP 3: VERIFIKASI RAW SECRET
        # ----------------------------------------------
        self.log_to_panel(self.panel_shared, "\n--- [STEP 3] VERIFIKASI & HKDF ---")
        if shared_a_bytes == shared_b_bytes:
            self.log_to_panel(self.panel_shared, "✅ Raw Shared Secret: MATCH!")
            self.log_to_panel(self.panel_sim, "    -> Verifikasi berhasil, Raw Secret A == Raw Secret B.")
            
            # ----------------------------------------------
            # STEP 4: DERIVASI KEY (HKDF)
            # Mengubah Raw Shared Secret menjadi Key AES-256 (32 bytes)
            # ----------------------------------------------
            self.log_to_panel(self.panel_shared, "Melakukan Derivasi Kunci (HKDF-SHA256, Length 32)...")
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ECDH Chat")
            derived_key = hkdf.derive(shared_a_bytes)
            self.shared_key = derived_key
            
            self.log_to_panel(self.panel_shared, f"🔑 Shared AES Key (32 bytes): {binascii.hexlify(self.shared_key).decode()}")
            self.log_to_panel(self.panel_sim, ">> Step 4: Shared AES Key siap digunakan untuk enkripsi.")
        else:
            self.log_to_panel(self.panel_shared, "❌ Raw Shared Secret: MISMATCH!")
            self.log_to_panel(self.panel_sim, ">> ERROR: Shared Key gagal terbentuk.")
            self.shared_key = None

    def run_full_simulation(self):
        self.generate_keys()
        # Menggunakan threading untuk memastikan UI tidak hang saat menunggu.
        threading.Thread(target=self._full_simulation_worker, daemon=True).start()

    def _full_simulation_worker(self):
        # Tunggu sebentar setelah Generate Keys (500ms)
        time.sleep(0.5) 
        self.root.after(0, self.compute_shared)
        
        # Beri waktu untuk proses compute_shared selesai
        time.sleep(2) 
        self.root.after(0, lambda: self.log_to_panel(self.panel_sim, ">> READY: Secure Channel Established. Ready to chat."))

    def reset_app(self):
        self.alice_priv = None
        self.bob_priv = None
        self.shared_key = None
        self.panel_keys['text'].delete("1.0", tk.END)
        self.panel_shared['text'].delete("1.0", tk.END)
        self.panel_sim['text'].delete("1.0", tk.END)
        self.alice_chat_log.delete("1.0", tk.END)
        self.bob_chat_log.delete("1.0", tk.END)

    # ======================================
    # LOGIC: ENCRYPTION & SENDING (MODIFIED)
    # ======================================
    def aes_encrypt(self, data):
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.shared_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return iv, ct, encryptor.tag

    def aes_decrypt(self, iv, ct, tag):
        cipher = Cipher(algorithms.AES(self.shared_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    # --- POPUP LOADING ANIMATION ---
    def _animate_process(self, task_name, callback_fn):
        top = tk.Toplevel(self.root)
        top.title("Processing...")
        top.geometry("400x160")
        top.configure(bg=self.card_bg)
        top.overrideredirect(True) 
        
        # Center popup
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 200
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 80
        top.geometry(f"+{x}+{y}")
        
        # Border aksen
        tk.Frame(top, bg=self.accent, height=2).pack(side="top", fill="x")

        tk.Label(top, text=task_name, bg=self.card_bg, fg=self.accent, font=("Segoe UI", 12, "bold")).pack(pady=15)
        lbl_status = tk.Label(top, text="Initializing...", bg=self.card_bg, fg="white", font=("Segoe UI", 10))
        lbl_status.pack(pady=5)
        pb = ttk.Progressbar(top, style="Cyber.Horizontal.TProgressbar", orient="horizontal", length=300, mode="determinate")
        pb.pack(pady=10)

        def worker():
            steps = [("Generating Salt & IV...", 30, 0.4), ("Encrypting (AES-GCM)...", 60, 0.5), 
                     ("Transmitting...", 80, 0.5), ("Decrypting & Verifying...", 100, 0.4)]
            for text, val, sleep_time in steps:
                time.sleep(sleep_time)
                self.root.after(0, lambda t=text, v=val: update_ui(t, v))
            time.sleep(0.3)
            self.root.after(0, finish)

        def update_ui(text, val):
            lbl_status.config(text=text)
            pb['value'] = val

        def finish():
            top.destroy()
            callback_fn()

        threading.Thread(target=worker, daemon=True).start()

    # ----------------------------
    # SEND FUNCTIONS (UPDATED OUTPUT FORMAT)
    # ----------------------------
    def alice_send_msg(self):
        msg = self.alice_input.get()
        if not msg: return
        if not self.shared_key:
            messagebox.showerror("Error", "Hitung Shared Key dulu! (Langkah 2)")
            return
        
        def process():
            t0 = time.perf_counter()
            iv, ct, tag = self.aes_encrypt(msg.encode())
            try:
                dec = self.aes_decrypt(iv, ct, tag).decode()
            except Exception as e:
                dec = "ERROR"
            t1 = time.perf_counter()
            duration_ms = (t1 - t0) * 1000

            hex_ct = binascii.hexlify(ct).decode()
            if len(hex_ct) > 30: hex_ct = hex_ct[:30] + "..." 

            output_text = (
                f"[Pesan dari Alice]\n"
                f"Ciphertext: {hex_ct}\n"
                f"Ukuran: {len(ct)} bytes\n"
                f"Waktu: {duration_ms:.3f} ms\n"
                f"Hasil dekripsi: {dec}\n\n"
            )

            self.bob_chat_log.insert(tk.END, output_text)
            self.alice_input.delete(0, tk.END)
            self.log_to_panel(self.panel_sim, f"Alice sent message ({len(ct)} bytes).")

        self._animate_process("Secure Message Transfer", process)

    def bob_send_msg(self):
        msg = self.bob_input.get()
        if not msg: return
        if not self.shared_key:
            messagebox.showerror("Error", "Hitung Shared Key dulu! (Langkah 2)")
            return
        
        def process():
            t0 = time.perf_counter()
            iv, ct, tag = self.aes_encrypt(msg.encode())
            try:
                dec = self.aes_decrypt(iv, ct, tag).decode()
            except:
                dec = "ERROR"
            t1 = time.perf_counter()
            duration_ms = (t1 - t0) * 1000

            hex_ct = binascii.hexlify(ct).decode()
            if len(hex_ct) > 30: hex_ct = hex_ct[:30] + "..."

            output_text = (
                f"[Pesan dari Bob]\n"
                f"Ciphertext: {hex_ct}\n"
                f"Ukuran: {len(ct)} bytes\n"
                f"Waktu: {duration_ms:.3f} ms\n"
                f"Hasil dekripsi: {dec}\n\n"
            )

            self.alice_chat_log.insert(tk.END, output_text)
            self.bob_input.delete(0, tk.END)
            self.log_to_panel(self.panel_sim, f"Bob sent message ({len(ct)} bytes).")

        self._animate_process("Secure Message Transfer", process)

    def alice_send_file(self):
        if not self.shared_key:
            messagebox.showerror("Error", "Hitung Shared Key dulu! (Langkah 2)")
            return
        path = filedialog.askopenfilename()
        if not path: return
        filename = os.path.basename(path)
        
        def process():
            t0 = time.perf_counter()
            with open(path, "rb") as f: data = f.read()
            iv, ct, tag = self.aes_encrypt(data)
            dec_data = self.aes_decrypt(iv, ct, tag)
            t1 = time.perf_counter()
            duration_ms = (t1 - t0) * 1000

            save_path = os.path.join(RECEIVED_DIR, f"bob_received_{filename}")
            with open(save_path, "wb") as f: f.write(dec_data)

            output_text = (
                f"[FILE dari Alice]\n"
                f"Nama File: {filename}\n"
                f"Ukuran Terenkripsi: {len(ct)} bytes\n"
                f"Waktu Proses: {duration_ms:.3f} ms\n"
                f"Lokasi Simpan: {save_path}\n\n"
            )
            self.bob_chat_log.insert(tk.END, output_text)
            self.log_to_panel(self.panel_sim, f"Alice sent file: {filename}")

        self._animate_process(f"Encrypting File: {filename}", process)

    def bob_send_file(self):
        if not self.shared_key:
            messagebox.showerror("Error", "Hitung Shared Key dulu! (Langkah 2)")
            return
        path = filedialog.askopenfilename()
        if not path: return
        filename = os.path.basename(path)
        
        def process():
            t0 = time.perf_counter()
            with open(path, "rb") as f: data = f.read()
            iv, ct, tag = self.aes_encrypt(data)
            dec_data = self.aes_decrypt(iv, ct, tag)
            t1 = time.perf_counter()
            duration_ms = (t1 - t0) * 1000

            save_path = os.path.join(RECEIVED_DIR, f"alice_received_{filename}")
            with open(save_path, "wb") as f: f.write(dec_data)

            output_text = (
                f"[FILE dari Bob]\n"
                f"Nama File: {filename}\n"
                f"Ukuran Terenkripsi: {len(ct)} bytes\n"
                f"Waktu Proses: {duration_ms:.3f} ms\n"
                f"Lokasi Simpan: {save_path}\n\n"
            )
            self.alice_chat_log.insert(tk.END, output_text)
            self.log_to_panel(self.panel_sim, f"Bob sent file: {filename}")

        self._animate_process(f"Encrypting File: {filename}", process)

# ======================================
# START
# ======================================
if __name__ == "__main__":
    root = tk.Tk()
    app = ECDHChatApp(root)
    root.mainloop()