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
class ProfessionalButton(tk.Button):
    def __init__(self, master, **kwargs):
        # Default colors
        default_bg = kwargs.pop('bg', "#1f2a40") 
        default_fg = kwargs.pop('fg', "white")
        hover_color = "#3a4a68" 
        active_color = "#2c3b53" 
        
        super().__init__(master, **kwargs)
        self.default_bg = default_bg
        
        self.configure(bg=default_bg, fg=default_fg, activebackground=active_color, 
                       activeforeground="white", bd=0, relief="flat", cursor="hand2",
                       font=("Segoe UI", 10, "bold"), padx=12, pady=5)
        
        # Binding hover effect
        self.bind("<Enter>", lambda e: self.config(bg=hover_color))
        self.bind("<Leave>", lambda e: self.config(bg=self.default_bg))

class ChatSendButton(ProfessionalButton):
    # Button with a subtle "send" animation effect (background pulse)
    def __init__(self, master, **kwargs):
        self.base_color = kwargs.pop('bg', "#0d6efd") # Warna dasar biru profesional
        super().__init__(master, bg=self.base_color, **kwargs)
        self.default_bg = self.base_color # Override default_bg for better control

    def on_click_animation(self):
        # Animasi pulsa singkat saat tombol ditekan
        original_bg = self.base_color
        pulse_color = "#3399ff"
        
        # Step 1: Pulse (brighten)
        self.config(bg=pulse_color)
        
        # Step 2: Return to normal after a short delay
        self.after(100, lambda: self.config(bg=original_bg))
        self.after(100, lambda: self.config(bg=self.base_color)) # Ensure it returns to base

# ======================================
# APLIKASI UTAMA
# ======================================
class ECDHChatApp:
    def __init__(self, root):
        self.root = root
        root.title("ECDH Secure Chat — Professional Enterprise")
        
        # --- Full Screen Setup ---
        try:
            root.state('zoomed') 
        except:
            root.attributes('-fullscreen', True) 

        # --- Theme Colors (Professional Dark/Blue) ---
        self.bg_top = "#141e30" # Header/Top Background (Dark Blue)
        self.bg_bottom = "#0c121e" # Main Background (Slightly Darker)
        self.card_bg = "#1f2a40" # Panel/Card Background (Blue Grey)
        self.card_border = "#4e6a8c" # Border
        self.accent = "#ffc107" # Professional Gold/Amber Accent
        self.text_primary = "#e0e7ee" # Light Text
        self.text_secondary = "#a0b2c8" # Secondary Text
        self.mono_font = ("Consolas", 10)
        self.text_chat = "#ffffff" # White for chat logs
        self.log_success = "#4CAF50" # Green for success logs

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
        self._setup_styles()
        self._build_header()
        self._build_chat_area()
        self._build_bottom_area()

    def _setup_styles(self):
        # Konfigurasi Ttk Styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Combobox style
        style.configure("TCombobox", 
                        fieldbackground=self.card_bg, 
                        background=self.card_bg, 
                        foreground=self.text_primary, 
                        selectbackground=self.accent, 
                        selectforeground=self.card_bg,
                        bordercolor=self.card_border,
                        arrowcolor=self.accent)
        style.map("TCombobox",
                  fieldbackground=[('readonly', self.card_bg)])

        # Progressbar style (Accent Gold)
        style.configure("Professional.Horizontal.TProgressbar", 
                        troughcolor='#333a4c', 
                        background=self.accent, 
                        bordercolor=self.card_border, 
                        lightcolor=self.accent, 
                        darkcolor=self.accent,
                        thickness=10)

    # ----------------------------
    # UI: HEADER
    # ----------------------------
    def _build_header(self):
        header_frame = tk.Frame(self.root, bg=self.bg_top, pady=10, padx=20)
        header_frame.grid(row=0, column=0, sticky="ew")
        
        # Garis aksen bawah header
        tk.Frame(header_frame, bg=self.accent, height=2).pack(side="bottom", fill="x")

        # Container Tombol
        ctrl_frame = tk.Frame(header_frame, bg=self.bg_top)
        ctrl_frame.pack(side="top", fill="x", pady=5)

        # Dropdown Curve
        tk.Label(ctrl_frame, text="ECC Curve:", bg=self.bg_top, fg=self.text_primary, font=("Segoe UI", 11)).pack(side="left", padx=5)
        self.curve_cb = ttk.Combobox(ctrl_frame, values=list(CURVE_MAP.keys()), state="readonly", width=25, style="TCombobox")
        self.curve_cb.current(0)
        self.curve_cb.pack(side="left", padx=10)

        # Tombol Aksi Utama
        ProfessionalButton(ctrl_frame, text="1. Generate Keys", command=self.generate_keys, bg="#0d6efd").pack(side="left", padx=10)
        ProfessionalButton(ctrl_frame, text="2. Hitung Shared Key", command=self.compute_shared, bg="#198754").pack(side="left", padx=10)
        ProfessionalButton(ctrl_frame, text="Reset / Clear", command=self.reset_app, bg="#dc3545").pack(side="right", padx=10)

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
        frame = tk.Frame(parent, bg=self.card_bg, bd=1, relief="solid", highlightbackground=self.card_border, highlightthickness=1)
        frame.grid(row=0, column=col, sticky="nsew", padx=10)
        
        # Judul User
        tk.Label(frame, text=name, bg=self.card_bg, fg=self.accent, font=("Segoe UI", 14, "bold")).pack(pady=8)
        
        # Area Chat Log (Output)
        log = scrolledtext.ScrolledText(frame, bg="#0c121e", fg=self.text_chat, 
                                        insertbackground=self.accent, font=self.mono_font, relief="flat", bd=0, padx=10, pady=10)
        log.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Area Input Pesan
        input_frame = tk.Frame(frame, bg=self.card_bg)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        entry = tk.Entry(input_frame, bg="#2c3b53", fg="white", font=("Segoe UI", 11), relief="flat", insertbackground="white", bd=0)
        entry.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=5)
#                                                            ^^^^^^^ Ditambahkan
        
        # Tombol Kirim Pesan dengan animasi
        send_btn = ChatSendButton(input_frame, text="Kirim Pesan", command=lambda: self.execute_and_animate(send_cmd, send_btn))
        send_btn.pack(side="right")
        
        # Tombol Kirim File
        ProfessionalButton(input_frame, text="Kirim File", command=file_cmd, bg="#198754").pack(side="right", padx=5)

        return {'log': log, 'input': entry}

    def execute_and_animate(self, command_fn, button_widget):
        # Run animation first
        if isinstance(button_widget, ChatSendButton):
            button_widget.on_click_animation()
        # Then execute the command after a slight delay (or immediately if blocking is handled by process thread)
        command_fn()
        
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

        # Kolom 1: Key Info (Warna Sekunder/Detail)
        self.panel_keys = self._create_info_panel(bottom_frame, "Key Information (Alice & Bob)", 0, self.text_secondary)
        
        # Kolom 2: Shared Key (Menggunakan Warna Sekunder untuk Detail Log, menghilangkan definisi yang duplikat)
        self.panel_shared = self._create_info_panel(bottom_frame, "Shared Key Calculation", 1, self.text_secondary)

        # Kolom 3: Simulasi Log (Warna Primer/Utama)
        self.panel_sim = self._create_info_panel(bottom_frame, "Simulation Logs & Steps", 2, self.text_primary)
        
        # Tombol Auto Simulation di panel kanan
        btn_frame = tk.Frame(self.panel_sim['frame'], bg=self.card_bg)
        btn_frame.place(relx=1.0, rely=0.0, anchor="ne", x=-5, y=5)
        ProfessionalButton(btn_frame, text="Run Full Simulation", command=self.run_full_simulation, bg="#6f42c1").pack()

    def _create_info_panel(self, parent, title, col, text_color):
        container = tk.Frame(parent, bg=self.card_bg, bd=1, relief="solid", highlightbackground=self.card_border, highlightthickness=1)
        container.grid(row=0, column=col, sticky="nsew", padx=5)
        
        tk.Label(container, text=title, bg=self.card_bg, fg=self.accent, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=5)
        
        text_area = scrolledtext.ScrolledText(container, bg="#0c121e", fg=text_color, 
                                              font=("Consolas", 9), relief="flat", height=10, bd=0, padx=5, pady=5)
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
        # ----------------------------------------------
        self.log_to_panel(self.panel_shared, "--- [STEP 2a] ALICE: Computing Raw Shared Secret ---")
        self.log_to_panel(self.panel_shared, "Menggunakan: Alice_Private_Key * Bob_Public_Key")
        shared_a_bytes = self.alice_priv.exchange(ec.ECDH(), self.bob_pub)
        hex_a = binascii.hexlify(shared_a_bytes).decode()
        self.log_to_panel(self.panel_shared, f"Hasil (Raw Shared A): {hex_a[:60]}...")
        self.log_to_panel(self.panel_sim, "    -> Alice selesai menghitung Raw Shared Secret.")

        # ----------------------------------------------
        # STEP 2b: BOB CALCULATES SHARED SECRET
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
        # Use the new style for progress bar
        pb = ttk.Progressbar(top, style="Professional.Horizontal.TProgressbar", orient="horizontal", length=300, mode="determinate")
        pb.pack(pady=10)

        def worker():
            steps = [("Generating Salt & IV...", 30, 0.4), ("Encrypting (AES-GCM)...", 60, 0.5), 
                     ("Transmitting...", 80, 0.5), ("Decrypting & Verifying...", 100, 0.4)]
            for text, val, sleep_time in steps:
                time.sleep(sleep_time)
                # Update UI in the main thread
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
                dec = "ERROR (Authentikasi Gagal)"
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
                dec = "ERROR (Authentikasi Gagal)"
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
            try:
                with open(path, "rb") as f: data = f.read()
                iv, ct, tag = self.aes_encrypt(data)
                dec_data = self.aes_decrypt(iv, ct, tag)
                t1 = time.perf_counter()
                duration_ms = (t1 - t0) * 1000

                save_path = os.path.join(RECEIVED_DIR, f"bob_received_{filename}")
                with open(save_path, "wb") as f: f.write(dec_data)
                status_msg = f"Lokasi Simpan: {save_path}"
                dec_size = len(dec_data)
            except Exception as e:
                t1 = time.perf_counter()
                duration_ms = (t1 - t0) * 1000
                ct = b""
                dec_size = 0
                status_msg = f"DEKRIPSI GAGAL: {e}"

            output_text = (
                f"[FILE dari Alice]\n"
                f"Nama File: {filename}\n"
                f"Ukuran Terenkripsi: {len(ct)} bytes\n"
                f"Ukuran Terdekripsi: {dec_size} bytes\n"
                f"Waktu Proses: {duration_ms:.3f} ms\n"
                f"{status_msg}\n\n"
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
            try:
                with open(path, "rb") as f: data = f.read()
                iv, ct, tag = self.aes_encrypt(data)
                dec_data = self.aes_decrypt(iv, ct, tag)
                t1 = time.perf_counter()
                duration_ms = (t1 - t0) * 1000

                save_path = os.path.join(RECEIVED_DIR, f"alice_received_{filename}")
                with open(save_path, "wb") as f: f.write(dec_data)
                status_msg = f"Lokasi Simpan: {save_path}"
                dec_size = len(dec_data)
            except Exception as e:
                t1 = time.perf_counter()
                duration_ms = (t1 - t0) * 1000
                ct = b""
                dec_size = 0
                status_msg = f"DEKRIPSI GAGAL: {e}"

            output_text = (
                f"[FILE dari Bob]\n"
                f"Nama File: {filename}\n"
                f"Ukuran Terenkripsi: {len(ct)} bytes\n"
                f"Ukuran Terdekripsi: {dec_size} bytes\n"
                f"Waktu Proses: {duration_ms:.3f} ms\n"
                f"{status_msg}\n\n"
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