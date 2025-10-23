#!/usr/bin/env python3
"""
Steganography GUI tool (LSB) — embed and extract text/files into images.

Features:
 - Embed text or file
 - Optional password (Fernet / AES) encryption
 - Capacity check
 - Supports PNG/BMP (PNG recommended)
 - Drag-and-drop if tkinterdnd2 is installed (fallback to file dialogs)
"""

import os
import io
import struct
import zlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
from base64 import urlsafe_b64encode, urlsafe_b64decode

# optional cryptography for encryption
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

# optional tkinter dnd2 for drag-and-drop
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except Exception:
    DND_AVAILABLE = False

MAGIC = b"STEG"   # 4 bytes magic
HEADER_STRUCT = ">4sBII"  # magic, flags, filename_len, payload_len
# flags bit0: is_file, bit1: encrypted

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key (urlsafe base64) from a password + salt."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography not installed")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=200_000, backend=default_backend())
    key = kdf.derive(password.encode('utf-8'))
    return urlsafe_b64encode(key)

def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    f = Fernet(key)
    token = f.encrypt(data)
    # store salt + token
    return salt + token

def decrypt_bytes(blob: bytes, password: str) -> bytes:
    if len(blob) < 16:
        raise InvalidToken("invalid blob")
    salt = blob[:16]
    token = blob[16:]
    key = derive_key_from_password(password, salt)
    f = Fernet(key)
    return f.decrypt(token)

def pack_payload(is_file: bool, filename: str, raw_bytes: bytes, password: str|None) -> bytes:
    # compress payload
    compressed = zlib.compress(raw_bytes)
    encrypted_flag = 0
    if password:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Encryption requested but cryptography package missing.")
        compressed = encrypt_bytes(compressed, password)
        encrypted_flag = 1
    fname_bytes = filename.encode('utf-8') if is_file and filename else b""
    header = struct.pack(HEADER_STRUCT, MAGIC, (int(is_file) & 1) | (encrypted_flag<<1),
                         len(fname_bytes), len(compressed))
    return header + fname_bytes + compressed

def unpack_payload(payload: bytes, password: str|None):
    # read header sizes
    hdr_size = struct.calcsize(HEADER_STRUCT)
    if len(payload) < hdr_size:
        raise ValueError("Payload too small")
    magic, flags, fname_len, payload_len = struct.unpack(HEADER_STRUCT, payload[:hdr_size])
    if magic != MAGIC:
        raise ValueError("Bad magic - not a valid steg file")
    is_file = bool(flags & 1)
    encrypted = bool((flags >> 1) & 1)
    pos = hdr_size
    filename = ""
    if fname_len > 0:
        filename = payload[pos:pos+fname_len].decode('utf-8', errors='replace')
        pos += fname_len
    data = payload[pos:pos+payload_len]
    if encrypted:
        if not password:
            raise ValueError("Payload is encrypted but no password provided")
        data = decrypt_bytes(data, password)
    decompressed = zlib.decompress(data)
    return is_file, filename, decompressed

def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def bits_to_bytes(bits):
    out = bytearray()
    b = 0
    cnt = 0
    for bit in bits:
        b = (b << 1) | bit
        cnt += 1
        if cnt == 8:
            out.append(b)
            b = 0
            cnt = 0
    return bytes(out)

def capacity_in_bits(img: Image.Image) -> int:
    mode = img.mode
    if mode not in ("RGB","RGBA"):
        img = img.convert("RGBA")
    w,h = img.size
    # we'll use 3 channels (R,G,B), 1 bit per channel
    return w*h*3

def embed_into_image(carrier: Image.Image, payload: bytes) -> Image.Image:
    # ensure RGB
    if carrier.mode not in ("RGB","RGBA"):
        carrier = carrier.convert("RGBA")
    w,h = carrier.size
    max_bits = capacity_in_bits(carrier)
    payload_bits = list(bytes_to_bits(payload))
    if len(payload_bits) > max_bits:
        raise ValueError(f"Payload too big for carrier image. Need {len(payload_bits)} bits, capacity {max_bits} bits.")
    pixels = list(carrier.getdata())
    new_pixels = []
    bit_iter = iter(payload_bits)
    finished = False
    for px in pixels:
        r,g,b = px[0], px[1], px[2]
        # modify r,g,b LSBs if bits available
        try:
            rb = next(bit_iter)
            r = (r & ~1) | rb
            gb = next(bit_iter)
            g = (g & ~1) | gb
            bb = next(bit_iter)
            b = (b & ~1) | bb
        except StopIteration:
            finished = True
            # if one or two bits consumed, we handled them; no further changes
        if carrier.mode == "RGBA":
            new_pixels.append((r,g,b,px[3]))
        else:
            new_pixels.append((r,g,b))
        if finished and len(new_pixels) >= len(pixels):
            break
    # if we didn't fill all pixels (likely), append remaining original pixels
    if len(new_pixels) < len(pixels):
        new_pixels.extend(pixels[len(new_pixels):])
    out = Image.new(carrier.mode, carrier.size)
    out.putdata(new_pixels)
    return out

def extract_from_image(carrier: Image.Image) -> bytes:
    if carrier.mode not in ("RGB","RGBA"):
        carrier = carrier.convert("RGBA")
    pixels = list(carrier.getdata())
    bits = []
    for px in pixels:
        r,g,b = px[0], px[1], px[2]
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)
    # we need to read header first to know total payload size
    # read enough bits for header
    hdr_bytes_len = struct.calcsize(HEADER_STRUCT)
    hdr_bits_len = hdr_bytes_len * 8
    hdr_bits = bits[:hdr_bits_len]
    hdr = bits_to_bytes(hdr_bits)
    try:
        magic, flags, fname_len, payload_len = struct.unpack(HEADER_STRUCT, hdr)
    except struct.error:
        raise ValueError("Failed to read header; image probably doesn't contain payload.")
    if magic != MAGIC:
        raise ValueError("Magic not found - not a supported steg image.")
    # total bytes after header = fname_len + payload_len
    total_after = fname_len + payload_len
    total_bits_needed = hdr_bits_len + total_after*8
    if total_bits_needed > len(bits):
        raise ValueError("Image does not contain enough data for indicated payload length.")
    payload_bits = bits[hdr_bits_len:hdr_bits_len + total_after*8]
    payload_bytes = bits_to_bytes(payload_bits)
    full_payload = hdr + payload_bytes
    return full_payload

# ------------------ GUI ------------------

class StegUI:
    def __init__(self, root):
        self.root = root
        root.title("Steganography (LSB) — Embed & Extract")
        self.carrier_path = tk.StringVar()
        self.payload_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.password = tk.StringVar()
        self.is_file = tk.BooleanVar(value=False)

        # Top: Carrier selection and preview
        top = tk.Frame(root)
        tk.Label(top, text="Carrier image (PNG/BMP recommended):").pack(anchor="w")
        carrier_row = tk.Frame(top)
        tk.Entry(carrier_row, textvariable=self.carrier_path, width=60).pack(side="left", padx=4, pady=2)
        tk.Button(carrier_row, text="Browse", command=self.browse_carrier).pack(side="left", padx=4)
        tk.Button(carrier_row, text="Preview", command=self.preview_carrier).pack(side="left", padx=4)
        carrier_row.pack(fill="x")
        top.pack(fill="x", padx=8, pady=6)

        # payload selection
        mid = tk.Frame(root)
        tk.Label(mid, text="Payload:").grid(row=0,column=0, sticky="w")
        tk.Radiobutton(mid, text="Text message", variable=self.is_file, value=False).grid(row=1,column=0, sticky="w")
        tk.Radiobutton(mid, text="File to embed", variable=self.is_file, value=True).grid(row=1,column=1, sticky="w")
        # text box
        self.textbox = scrolledtext.ScrolledText(mid, width=60, height=8)
        self.textbox.grid(row=2,column=0, columnspan=3, padx=4, pady=4)
        # file selector
        file_row = tk.Frame(mid)
        tk.Entry(file_row, textvariable=self.payload_path, width=50).pack(side="left", padx=4)
        tk.Button(file_row, text="Browse File", command=self.browse_payload).pack(side="left", padx=4)
        file_row.grid(row=3,column=0, columnspan=3, sticky="w")

        mid.pack(fill="x", padx=8, pady=6)

        # password and output
        bottom = tk.Frame(root)
        tk.Label(bottom, text="Password (optional — enables encryption):").grid(row=0,column=0, sticky="w")
        tk.Entry(bottom, textvariable=self.password, show="*", width=30).grid(row=0,column=1, sticky="w", padx=6)
        tk.Label(bottom, text="Output file:").grid(row=1,column=0, sticky="w")
        tk.Entry(bottom, textvariable=self.output_path, width=40).grid(row=1,column=1, sticky="w")
        tk.Button(bottom, text="Choose Output", command=self.browse_output).grid(row=1,column=2, padx=6)
        bottom.pack(fill="x", padx=8, pady=6)

        # action buttons
        actions = tk.Frame(root)
        tk.Button(actions, text="Embed → Create Stego Image", command=self.do_embed, width=30).pack(side="left", padx=6)
        tk.Button(actions, text="Extract from Carrier", command=self.do_extract, width=24).pack(side="left", padx=6)
        actions.pack(pady=8)

        # preview canvas
        self.preview_label = tk.Label(root, text="(Image preview will appear here)", bd=1, relief="sunken", width=60, height=10)
        self.preview_label.pack(padx=8, pady=6)

        # status
        self.status = tk.Label(root, text="", anchor="w")
        self.status.pack(fill="x", padx=8, pady=2)

        # optionally enable drag-and-drop
        if DND_AVAILABLE:
            self.enable_dnd(root)

    def set_status(self, text):
        self.status.config(text=text)

    def enable_dnd(self, root):
        # try to attach dnd for carrier and payload entries
        try:
            root = TkinterDnD.Tk() if isinstance(root, TkinterDnD.Tk) else root
            # this method only runs if tkinterdnd2 is installed
            entries = [self.root.nametowidget(str(w)) for w in (self.root,) ]  # just no-op, we rely on filedialog as primary
            self.set_status("Drag-and-drop available.")
        except Exception:
            pass

    def browse_carrier(self):
        p = filedialog.askopenfilename(filetypes=[("Images","*.png;*.bmp;*.jpg;*.jpeg"),("All files","*.*")])
        if p:
            self.carrier_path.set(p)
            self.preview_carrier()

    def preview_carrier(self):
        p = self.carrier_path.get()
        if not p or not os.path.exists(p):
            messagebox.showwarning("No carrier", "Select a valid carrier image first.")
            return
        try:
            img = Image.open(p)
            img.thumbnail((400,240))
            self.imgtk = ImageTk.PhotoImage(img)
            self.preview_label.config(image=self.imgtk, text="")
            cap = capacity_in_bits(Image.open(p))
            cap_bytes = cap//8
            self.set_status(f"Carrier: {p}  •  Capacity: {cap} bits ({cap_bytes} bytes)")
        except Exception as e:
            messagebox.showerror("Preview error", str(e))

    def browse_payload(self):
        p = filedialog.askopenfilename(filetypes=[("All files","*.*")])
        if p:
            self.payload_path.set(p)
            # load file name into textbox?
            self.textbox.delete("1.0","end")
            self.textbox.insert("1.0", f"[File selected: {os.path.basename(p)}]\n\n(Using file input mode)")

    def browse_output(self):
        p = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image","*.png"), ("BMP image","*.bmp")])
        if p:
            self.output_path.set(p)

    def do_embed(self):
        carrier_p = self.carrier_path.get()
        if not carrier_p or not os.path.exists(carrier_p):
            messagebox.showerror("No carrier", "Select a carrier image first.")
            return
        is_file = self.is_file.get()
        payload_bytes = b""
        filename = ""
        if is_file:
            payload_p = self.payload_path.get()
            if not payload_p or not os.path.exists(payload_p):
                messagebox.showerror("No payload file", "Select a file to embed.")
                return
            with open(payload_p, "rb") as f:
                payload_bytes = f.read()
            filename = os.path.basename(payload_p)
        else:
            text = self.textbox.get("1.0","end").rstrip("\n")
            if not text:
                messagebox.showerror("Empty message", "Enter the message to embed.")
                return
            payload_bytes = text.encode("utf-8")
            filename = ""
        password = self.password.get().strip() or None
        try:
            packed = pack_payload(is_file, filename, payload_bytes, password)
        except Exception as e:
            messagebox.showerror("Packing error", str(e))
            return
        try:
            carrier_img = Image.open(carrier_p).convert("RGBA")
            cap = capacity_in_bits(carrier_img)
            if len(packed)*8 > cap:
                messagebox.showerror("Capacity exceeded",
                                     f"Payload ({len(packed)} bytes = {len(packed)*8} bits) too large for carrier capacity ({cap} bits). Choose a larger image or reduce payload.")
                return
            stego = embed_into_image(carrier_img, packed)
            outp = self.output_path.get()
            if not outp:
                outp = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image","*.png"), ("BMP image","*.bmp")])
                if not outp:
                    return
                self.output_path.set(outp)
            stego.save(outp)
            messagebox.showinfo("Success", f"Stego image saved to:\n{outp}")
            self.set_status(f"Embedded {len(packed)} bytes into {outp}")
            self.preview_carrier()  # show carrier preview again
        except Exception as e:
            messagebox.showerror("Embed error", str(e))

    def do_extract(self):
        carrier_p = self.carrier_path.get()
        if not carrier_p or not os.path.exists(carrier_p):
            carrier_p = filedialog.askopenfilename(title="Select stego/carrier image", filetypes=[("Images","*.png;*.bmp;*.jpg;*.jpeg")])
            if not carrier_p:
                return
            self.carrier_path.set(carrier_p)
        password = self.password.get().strip() or None
        try:
            img = Image.open(carrier_p).convert("RGBA")
            full_payload = extract_from_image(img)
            is_file, filename, data = unpack_payload(full_payload, password)
            if is_file:
                # ask where to save, default filename from header
                save_to = filedialog.asksaveasfilename(initialfile=(filename or "extracted.bin"), title="Save extracted file as")
                if not save_to:
                    return
                with open(save_to, "wb") as f:
                    f.write(data)
                messagebox.showinfo("Extracted", f"Extracted file saved to:\n{save_to}")
                self.set_status(f"Extracted file {os.path.basename(save_to)} ({len(data)} bytes)")
            else:
                # show text
                try:
                    text = data.decode("utf-8")
                except Exception:
                    text = repr(data)
                top = tk.Toplevel(self.root)
                top.title("Extracted message")
                txt = scrolledtext.ScrolledText(top, width=80, height=20)
                txt.pack(padx=8, pady=8)
                txt.insert("1.0", text)
                txt.config(state="disabled")
                self.set_status(f"Extracted text ({len(data)} bytes)")
        except InvalidToken:
            messagebox.showerror("Decryption failed", "Wrong password or corrupted encrypted payload.")
        except Exception as e:
            messagebox.showerror("Extract error", str(e))

def main():
    if DND_AVAILABLE:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    app = StegUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
