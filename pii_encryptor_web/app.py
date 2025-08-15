import io
import os
import tempfile
from pathlib import Path
from typing import Optional

from flask import Flask, render_template, request, redirect, url_for, send_file, flash

from pii_encryptor.keystore import list_keys, create_key, set_default_key_id, get_default_key_id
from pii_encryptor.processor import encrypt_text, decrypt_text, inspect_text
from pii_encryptor.file_io import read_text_auto, write_text_auto


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("PII_ENC_WEB_SECRET", os.urandom(16))
    app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/keys")
    def keys_page():
        keys = list_keys()
        default = get_default_key_id()
        return render_template("keys.html", keys=keys, default_key_id=default)

    @app.post("/keys/create")
    def keys_create():
        label = request.form.get("label", "")
        set_default = request.form.get("set_default") == "on"
        rec = create_key(label=label, set_default=set_default)
        flash(f"נוצר מפתח: {rec.key_id}")
        return redirect(url_for("keys_page"))

    @app.post("/keys/set_default")
    def keys_set_default():
        key_id = request.form.get("key_id")
        if key_id:
            set_default_key_id(key_id)
            flash(f"מפתח ברירת מחדל עודכן: {key_id}")
        return redirect(url_for("keys_page"))

    @app.get("/encrypt")
    def encrypt_page():
        keys = list_keys()
        default = get_default_key_id()
        return render_template("encrypt.html", keys=keys, default_key_id=default)

    def _save_upload_to_tmp(file_storage) -> Path:
        filename = file_storage.filename or "upload.txt"
        suffix = Path(filename).suffix or ".txt"
        tmp_dir = Path(tempfile.mkdtemp(prefix="pii_gui_"))
        tmp_path = tmp_dir / f"in{suffix}"
        file_storage.save(str(tmp_path))
        return tmp_path

    def _send_output_bytes(bytes_data: bytes, download_name: str):
        return send_file(io.BytesIO(bytes_data), as_attachment=True, download_name=download_name)

    @app.post("/encrypt")
    def encrypt_action():
        if 'file' not in request.files:
            flash("לא נבחר קובץ")
            return redirect(url_for("encrypt_page"))
        f = request.files['file']
        if not f.filename:
            flash("לא נבחר קובץ")
            return redirect(url_for("encrypt_page"))
        key_id = request.form.get("key_id") or None
        in_path = _save_upload_to_tmp(f)
        text = read_text_auto(in_path)
        out_text, meta = encrypt_text(text, key_id=key_id)
        # prepare output
        in_name = f.filename
        base = Path(in_name).stem
        ext = Path(in_name).suffix or ".txt"
        out_name = f"{base}_encrypted{ext}"
        tmp_out = in_path.parent / f"out{ext}"
        write_text_auto(tmp_out, out_text)
        data = tmp_out.read_bytes()
        try:
            os.remove(tmp_out)
            os.remove(in_path)
        except Exception:
            pass
        flash(f"הצפנה הושלמה. key_id={meta['key_id']} file_id={meta['file_id']}")
        return _send_output_bytes(data, out_name)

    @app.get("/decrypt")
    def decrypt_page():
        return render_template("decrypt.html")

    @app.post("/decrypt")
    def decrypt_action():
        if 'file' not in request.files:
            flash("לא נבחר קובץ")
            return redirect(url_for("decrypt_page"))
        f = request.files['file']
        if not f.filename:
            flash("לא נבחר קובץ")
            return redirect(url_for("decrypt_page"))
        in_path = _save_upload_to_tmp(f)
        text = read_text_auto(in_path)
        out_text, meta = decrypt_text(text)
        in_name = f.filename
        base = Path(in_name).stem
        ext = Path(in_name).suffix or ".txt"
        out_name = f"{base}_decrypted{ext}"
        tmp_out = in_path.parent / f"out{ext}"
        write_text_auto(tmp_out, out_text)
        data = tmp_out.read_bytes()
        try:
            os.remove(tmp_out)
            os.remove(in_path)
        except Exception:
            pass
        flash(f"פענוח הושלם. החלפות={meta.get('replaced')}")
        return _send_output_bytes(data, out_name)

    @app.get("/inspect")
    def inspect_page():
        return render_template("inspect.html", info=None)

    @app.post("/inspect")
    def inspect_action():
        if 'file' not in request.files:
            flash("לא נבחר קובץ")
            return redirect(url_for("inspect_page"))
        f = request.files['file']
        if not f.filename:
            flash("לא נבחר קובץ")
            return redirect(url_for("inspect_page"))
        in_path = _save_upload_to_tmp(f)
        text = read_text_auto(in_path)
        info = inspect_text(text)
        try:
            os.remove(in_path)
        except Exception:
            pass
        return render_template("inspect.html", info=info)

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "7860"))
    app.run(host="127.0.0.1", port=port, debug=False)