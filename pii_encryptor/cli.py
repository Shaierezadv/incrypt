import argparse
import sys
from pathlib import Path

from .keystore import create_key, list_keys, get_default_key_id, set_default_key_id
from .processor import encrypt_text, decrypt_text, inspect_text


def cmd_keygen(args: argparse.Namespace) -> int:
    rec = create_key(label=args.label, set_default=not args.no_default)
    print(f"Created key: {rec.key_id} (label='{rec.label}')")
    if not args.no_default:
        print(f"Set as default key")
    return 0


def cmd_keys(args: argparse.Namespace) -> int:
    keys = list_keys()
    default = get_default_key_id()
    for kid, rec in sorted(keys.items()):
        star = "*" if kid == default else " "
        print(f"{star} {kid} label='{rec.label}' created={rec.created_at_epoch}")
    return 0


def cmd_set_default(args: argparse.Namespace) -> int:
    set_default_key_id(args.key_id)
    print(f"Default key set to: {args.key_id}")
    return 0


def _read_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_file(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def cmd_encrypt(args: argparse.Namespace) -> int:
    text = _read_file(Path(args.input))
    out, meta = encrypt_text(text, key_id=args.key_id)
    _write_file(Path(args.output), out)
    print(f"Encrypted. key_id={meta['key_id']} file_id={meta['file_id']} pii_found={meta['num_pii']}")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    text = _read_file(Path(args.input))
    out, meta = decrypt_text(text)
    _write_file(Path(args.output), out)
    print(f"Decrypted. key_id={meta.get('key_id')} file_id={meta.get('file_id')} replaced={meta.get('replaced')}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    text = _read_file(Path(args.input))
    info = inspect_text(text)
    print(info)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pii-enc", description="Local PII encrypt/decrypt tool with robust watermarking.")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_keygen = sub.add_parser("keygen", help="Create a new symmetric key")
    p_keygen.add_argument("--label", default="", help="Optional label for the key")
    p_keygen.add_argument("--no-default", action="store_true", help="Do not set as default key")
    p_keygen.set_defaults(func=cmd_keygen)

    p_keys = sub.add_parser("keys", help="List keys")
    p_keys.set_defaults(func=cmd_keys)

    p_def = sub.add_parser("set-default", help="Set default key by ID")
    p_def.add_argument("key_id")
    p_def.set_defaults(func=cmd_set_default)

    p_enc = sub.add_parser("encrypt", help="Encrypt PII in a text file and embed watermarks")
    p_enc.add_argument("--input", "-i", required=True)
    p_enc.add_argument("--output", "-o", required=True)
    p_enc.add_argument("--key-id", "-k", default=None, help="Key ID to use (defaults to current default)")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt PII tokens in a processed text file")
    p_dec.add_argument("--input", "-i", required=True)
    p_dec.add_argument("--output", "-o", required=True)
    p_dec.set_defaults(func=cmd_decrypt)

    p_ins = sub.add_parser("inspect", help="Show embedded key/file IDs and token stats")
    p_ins.add_argument("--input", "-i", required=True)
    p_ins.set_defaults(func=cmd_inspect)

    return p


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())