#!/usr/bin/env python3
"""
Interface Visuelle et Graphique CryptoVault (GUI & Web App)
Palette : Rouge Sang (#990000, #DC2626), Rouge Vin / Bordeaux (#800020, #4A0404) et Blanc (#FFFFFF)
Associe une interface utilisateur moderne et réactive à l'exécution directe des lignes de commande CLI.
"""

import os
import sys
import json
import time
import subprocess
import tempfile
import webbrowser
from flask import Flask, render_template, request, jsonify

# Assurer l'accès à cryptolib et app
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from app.server import CryptoVaultServer
from app.client import CryptoVaultClient
from app.vault import FileVault, _load_private_key_from_dict
from cryptolib.pki import Certificate, KeyStore
from cryptolib.symmetric import aes_decrypt

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
app = Flask(__name__, template_folder=TEMPLATE_DIR)

DATA_DIR = os.path.join(BASE_DIR, ".server_data")
VAULT_DIR = os.path.join(BASE_DIR, ".vault_storage")
KEYSTORE_DIR = os.path.join(BASE_DIR, ".keystores")
os.makedirs(KEYSTORE_DIR, exist_ok=True)

# Instances partagées
server = CryptoVaultServer(data_dir=DATA_DIR)
vault = FileVault(vault_dir=VAULT_DIR)

# Sessions actives en mémoire pour la messagerie interactive
# {username: {"client": client_instance, "messages": [], "last_sent_package": None}}
active_sessions = {}

MESSAGES_FILE = os.path.join(DATA_DIR, "messages.json")

def load_messages():
    if os.path.exists(MESSAGES_FILE):
        try:
            with open(MESSAGES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_messages(msgs):
    try:
        with open(MESSAGES_FILE, "w", encoding="utf-8") as f:
            json.dump(msgs, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Erreur sauvegarde messages : {e}")


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/")
def index():
    return render_template("index.html")



@app.route("/api/status", methods=["GET"])
def get_status():
    users_list = []
    for uname, udata in server.users_db.items():
        cert_data = udata.get("cert", {})
        serial = cert_data.get("serial_number", -1)
        is_revoked = (serial in server.server_ca.revoked_serials)
        users_list.append({
            "username": uname,
            "serial": serial if serial != -1 else "N/A",
            "valid_to": cert_data.get("valid_to", 0),
            "revoked": is_revoked,
        })

    return jsonify({
        "root_ca": {
            "subject": server.root_ca.cert.subject,
            "serial_number": server.root_ca.cert.serial_number,
        },
        "server_ca": {
            "subject": server.server_ca.cert.subject,
            "serial_number": server.server_ca.cert.serial_number,
        },
        "users": users_list,
        "vault_files_count": len(vault.list_files()),
        "active_sessions": list(active_sessions.keys()),
    })


@app.route("/api/register", methods=["POST"])
def register_user():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "error": "Nom d'utilisateur et mot de passe requis."})

    try:
        ks_path = os.path.join(KEYSTORE_DIR, f"{username}_keystore.json")
        client = CryptoVaultClient(username, ks_path)
        client.register(password, server)
        return jsonify({"success": True, "keystore_path": ks_path})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/pki/revoke", methods=["POST"])
def revoke_cert():
    data = request.json or {}
    username = data.get("username", "").strip()
    if username not in server.users_db:
        return jsonify({"success": False, "error": f"Utilisateur '{username}' introuvable."})

    cert_data = server.users_db[username].get("cert", {})
    serial = cert_data.get("serial_number")
    if serial is None:
        return jsonify({"success": False, "error": "Numéro de série introuvable."})

    server.server_ca.revoke_certificate(serial)
    server._save_pki()
    if username in active_sessions:
        del active_sessions[username]
    return jsonify({"success": True, "serial": serial, "username": username})


@app.route("/api/pki/delete_user", methods=["POST"])
def delete_user():
    data = request.json or {}
    username = data.get("username", "").strip()
    if username not in server.users_db:
        return jsonify({"success": False, "error": f"Utilisateur '{username}' introuvable."})

    # Révoquer le certificat
    cert_data = server.users_db[username].get("cert", {})
    serial = cert_data.get("serial_number")
    if serial is not None:
        server.server_ca.revoke_certificate(serial)
        server._save_pki()

    # Supprimer l'utilisateur de la base
    del server.users_db[username]
    server._save_users()

    # Supprimer le keystore sur le disque
    ks_path = os.path.join(KEYSTORE_DIR, f"{username}_keystore.json")
    if os.path.exists(ks_path):
        try:
            os.remove(ks_path)
        except Exception:
            pass

    if username in active_sessions:
        del active_sessions[username]

    return jsonify({"success": True, "username": username})


@app.route("/api/session/messages", methods=["GET"])
def get_messages():
    user1 = request.args.get("user1", "").strip()
    user2 = request.args.get("user2", "").strip()
    all_msgs = load_messages()
    if not user1 or (user2 and user1 == user2):
        return jsonify([])

    # Sécurité : Seul un utilisateur ayant déverrouillé son KeyStore et actif peut lire ses messages
    if user1 not in active_sessions:
        return jsonify({
            "error": f"Session inactive pour '{user1}'. Vous devez déverrouiller votre KeyStore pour accéder à votre boîte de réception.",
            "locked": True,
            "messages": []
        }), 403

    filtered = []
    for m in all_msgs:
        s, r = m.get("sender"), m.get("recipient")
        if user2:
            if (s == user1 and r == user2) or (s == user2 and r == user1):
                filtered.append(m)
        else:
            if s == user1 or r == user1:
                filtered.append(m)
    return jsonify(filtered)


@app.route("/api/session/start", methods=["POST"])
def start_session():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    ks_path = os.path.join(KEYSTORE_DIR, f"{username}_keystore.json")
    if not os.path.exists(ks_path):
        return jsonify({"success": False, "error": f"KeyStore introuvable pour '{username}'. Inscrivez-le d'abord."})

    try:
        client = CryptoVaultClient(username, ks_path)
        client.login(password, server)
        active_sessions[username] = {
            "client": client,
            "messages": [],
            "last_sent_package": None
        }
        return jsonify({
            "success": True,
            "username": username,
            "session_key": client.session_key.hex(),
            "shared_secret": client.session_key.hex(),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/session/send", methods=["POST"])
def send_message():
    data = request.json or {}
    sender = data.get("sender", "").strip()
    recipient = data.get("recipient", "").strip()
    content = data.get("content", "").strip()

    if not sender:
        return jsonify({"success": False, "error": "Expéditeur requis : vous devez être authentifié avec une session active."}), 403

    if sender not in active_sessions:
        return jsonify({"success": False, "error": f"Accès refusé : la session pour '{sender}' est verrouillée. Déverrouillez son KeyStore d'abord."}), 403

    if not recipient:
        return jsonify({"success": False, "error": "Destinataire requis."})

    if sender == recipient:
        return jsonify({"success": False, "error": "L'expéditeur et le destinataire doivent être distincts."}), 400

    if recipient not in server.users_db:
        return jsonify({"success": False, "error": f"Destinataire '{recipient}' non inscrit sur le serveur."})

    recip_cert_data = server.users_db[recipient].get("cert", {})
    recip_serial = recip_cert_data.get("serial_number")
    if recip_serial in server.server_ca.revoked_serials:
        return jsonify({"success": False, "error": f"Le certificat de '{recipient}' est RÉVOQUÉ dans la CRL. Envoi interdit !"})

    client_sess = active_sessions[sender]
    client = client_sess["client"]

    try:
        seq_before = client.seq_out
        pkg = client.send_secure_message(content)
        pkg_hex = pkg.hex()
        client_sess["last_sent_package"] = pkg_hex

        now = time.time()
        time_str = time.strftime("%H:%M:%S", time.localtime(now))
        new_msg = {
            "id": int(now * 1000),
            "sender": sender,
            "recipient": recipient,
            "content": content,
            "seq": seq_before,
            "timestamp": now,
            "time_str": time_str,
            "package_hex": pkg_hex,
        }

        all_msgs = load_messages()
        all_msgs.append(new_msg)
        save_messages(all_msgs)

        client_sess["messages"].append({
            "sender": sender,
            "content": content,
            "seq": seq_before,
            "hex": pkg_hex[:40] + "..."
        })

        return jsonify({
            "success": True,
            "seq": seq_before,
            "package_hex": pkg_hex,
            "message": new_msg
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/session/replay", methods=["POST"])
def simulate_replay():
    data = request.json or {}
    pkg_hex = data.get("package_hex")

    if not active_sessions or not pkg_hex:
        return jsonify({"success": False, "error": "Aucun paquet à rejouer."})

    username = list(active_sessions.keys())[-1]
    client = active_sessions[username]["client"]

    try:
        pkg_bytes = bytes.fromhex(pkg_hex)
        # On tente de faire ingérer le paquet déjà consommé
        client.receive_secure_message(pkg_bytes)
        return jsonify({"success": True, "message": "Paquet accepté (anormal si déjà consommé)"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/session/eavesdrop", methods=["POST"])
def simulate_eavesdrop():
    data = request.json or {}
    pkg_hex = data.get("package_hex")
    if not pkg_hex:
        return jsonify({"success": False, "error": "Aucun paquet chiffré à intercepter."})

    try:
        pkg_bytes = bytes.fromhex(pkg_hex)
        # Eve (attaquant) intercepte le paquet et tente de déchiffrer avec sa propre clé rogue
        rogue_key = os.urandom(32)
        aes_decrypt(pkg_bytes, rogue_key, mode="GCM")
        return jsonify({"success": True, "error": "Anormal : déchiffrement réussi sans la clé !"})
    except Exception as e:
        return jsonify({
            "success": False,
            "blocked": True,
            "error": f"Interception échouée : Échec d'authentification GMAC (InvalidTag) ! Eve ne détient pas la clé de session $K$ : {e}"
        })


@app.route("/api/session/stop", methods=["POST"])
def stop_session():
    data = request.json or {}
    username = data.get("username")
    if username and username in active_sessions:
        del active_sessions[username]
    else:
        active_sessions.clear()
    return jsonify({"success": True, "message": "Session désactivée avec succès."})


@app.route("/api/vault/list", methods=["GET"])
def vault_list():
    username = request.args.get("username", "").strip()

    if username == "active":
        req_user = request.args.get("active_user", "").strip()
        if req_user and req_user in active_sessions:
            return jsonify(vault.list_files(username=req_user))
        return jsonify([])

    if username and username.lower() != "all":
        return jsonify(vault.list_files(username=username))
    return jsonify(vault.list_files())


@app.route("/api/vault/add", methods=["POST"])
def vault_add():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    filename = data.get("filename", "").strip()
    content_str = data.get("content", "")
    co_owners_input = data.get("co_owners", [])

    if isinstance(co_owners_input, str):
        co_owners_list = [u.strip() for u in co_owners_input.split(",") if u.strip()]
    else:
        co_owners_list = [u.strip() for u in co_owners_input if u.strip()]

    ks_path = os.path.join(KEYSTORE_DIR, f"{username}_keystore.json")
    if not os.path.exists(ks_path):
        return jsonify({"success": False, "error": f"KeyStore introuvable pour '{username}'."})

    try:
        ks_data = KeyStore.load(ks_path, password)
        priv_key = _load_private_key_from_dict(ks_data["private_key"])
        cert = Certificate.from_dict(ks_data["certificate"])

        # Préparer les co-propriétaires / destinataires initiaux
        co_recipients = []
        for co_u in co_owners_list:
            if co_u != username and co_u in server.users_db:
                recip_cert = Certificate.from_dict(server.users_db[co_u]["cert"])
                co_recipients.append((co_u, recip_cert))

        # Création temporaire du fichier à chiffrer avec son nom réel
        tmp_dir = tempfile.mkdtemp()
        tmp_path = os.path.join(tmp_dir, filename)
        with open(tmp_path, "wb") as f:
            f.write(content_str.encode("utf-8"))

        name = vault.add_file(
            filepath=tmp_path,
            owner_username=username,
            owner_priv_key=priv_key,
            owner_cert=cert,
            owner_chain=[server.server_ca.cert],
            sign=True,
            block_size=2048,
            co_recipients=co_recipients,
        )
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)

        entry = vault.index[name]
        return jsonify({
            "success": True,
            "filename": name,
            "merkle_root": entry["merkle_root"],
            "size_bytes": entry["size_bytes"],
            "owners": entry.get("owners", [username]),
            "authorized": list(entry.get("authorized_recipients", {}).keys())
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/vault/delete", methods=["POST"])
def vault_delete():
    data = request.json or {}
    filename = data.get("filename", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not filename or not username or not password:
        return jsonify({"success": False, "error": "Nom de fichier, utilisateur et mot de passe requis."})

    ks_path = os.path.join(KEYSTORE_DIR, f"{username}_keystore.json")
    if not os.path.exists(ks_path):
        return jsonify({"success": False, "error": f"KeyStore introuvable pour '{username}'."})

    try:
        # Vérification du mot de passe
        KeyStore.load(ks_path, password)
        vault.delete_file(filename, username)
        return jsonify({"success": True, "filename": filename, "deleted_by": username})
    except PermissionError as pe:
        return jsonify({"success": False, "error": str(pe)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/vault/clear_all", methods=["POST"])
def vault_clear_all():
    """Réinitialise et vide l'ensemble des fichiers de test du coffre-fort."""
    try:
        # Supprime tous les fichiers .vault dans VAULT_DIR
        for f in os.listdir(VAULT_DIR):
            fp = os.path.join(VAULT_DIR, f)
            if os.path.isfile(fp):
                os.remove(fp)
        # Réinitialise l'index du coffre
        vault.index = {}
        vault._save_index()
        return jsonify({"success": True, "message": "Le coffre-fort a été entièrement vidé et réinitialisé."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/system/reset_all", methods=["POST"])
def system_reset_all():
    """Réinitialisation totale des données de test (coffre-fort et boîte de messagerie)."""
    try:
        # Vider le coffre
        for f in os.listdir(VAULT_DIR):
            fp = os.path.join(VAULT_DIR, f)
            if os.path.isfile(fp):
                os.remove(fp)
        vault.index = {}
        vault._save_index()

        # Vider les messages
        save_messages([])

        return jsonify({"success": True, "message": "Base de test entièrement réinitialisée (coffre-fort et messages vidés)."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/vault/share", methods=["POST"])
def vault_share():
    data = request.json or {}
    filename = data.get("filename", "").strip()
    owner = data.get("owner", "").strip()
    owner_pwd = data.get("owner_password", "").strip()
    recipient = data.get("recipient", "").strip()

    if not filename or not owner or not owner_pwd or not recipient:
        return jsonify({"success": False, "error": "Paramètres manquants pour le partage (fichier, propriétaire, mot de passe, destinataire)."})

    ks_path = os.path.join(KEYSTORE_DIR, f"{owner}_keystore.json")
    if not os.path.exists(ks_path):
        return jsonify({"success": False, "error": f"KeyStore du propriétaire '{owner}' introuvable."})

    if recipient not in server.users_db:
        return jsonify({"success": False, "error": f"Destinataire '{recipient}' non inscrit sur le serveur."})

    try:
        ks_data = KeyStore.load(ks_path, owner_pwd)
        owner_priv = _load_private_key_from_dict(ks_data["private_key"])
        recip_cert = Certificate.from_dict(server.users_db[recipient]["cert"])
        vault.share_file(filename, owner, owner_priv, recipient, recip_cert)
        return jsonify({
            "success": True,
            "filename": filename,
            "owner": owner,
            "recipient": recipient,
            "authorized": list(vault.index[filename]["authorized_recipients"].keys())
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/vault/read", methods=["POST"])
def vault_read():
    data = request.json or {}
    filename = data.get("filename", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not filename or not username or not password:
        return jsonify({"success": False, "error": "Nom de fichier, utilisateur et mot de passe requis."})

    ks_path = os.path.join(KEYSTORE_DIR, f"{username}_keystore.json")
    if not os.path.exists(ks_path):
        return jsonify({"success": False, "error": f"KeyStore introuvable pour '{username}'."})

    try:
        ks_data = KeyStore.load(ks_path, password)
        user_priv = _load_private_key_from_dict(ks_data["private_key"])

        with tempfile.NamedTemporaryFile("wb", delete=False) as tmp_out:
            tmp_path = tmp_out.name

        valid_sig, author = vault.get_file(filename, username, user_priv, tmp_path)
        with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        os.remove(tmp_path)

        entry = vault.index.get(filename, {})
        return jsonify({
            "success": True,
            "filename": filename,
            "author": author,
            "signature_valid": valid_sig,
            "merkle_root": entry.get("merkle_root"),
            "authorized_recipients": list(entry.get("authorized_recipients", {}).keys()),
            "content": content
        })
    except PermissionError as pe:
        return jsonify({"success": False, "permission_denied": True, "error": str(pe)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/lab/run", methods=["POST"])
def run_lab():
    data = request.json or {}
    script = data.get("script", "").strip()
    allowed_scripts = [
        "attack_collision_birthday.py",
        "benchmark_numtheory.py",
        "attack_rsa_lab.py",
        "attack_dh_mitm.py",
        "attack_ecc_nonce.py",
        "attack_symmetric_lab.py",
        "demo_pki_lab.py",
        "attack_prng_lab.py",
    ]

    if script not in allowed_scripts:
        return jsonify({"error": "Script non autorisé."})

    script_path = os.path.join(BASE_DIR, "lab", script)
    t0 = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            cwd=BASE_DIR
        )
        duration = round(time.time() - t0, 3)
        return jsonify({"output": proc.stdout, "duration_sec": duration})
    except Exception as e:
        return jsonify({"output": f"Erreur : {e}", "duration_sec": 0})


@app.route("/api/cli/execute", methods=["POST"])
def run_cli():
    data = request.json or {}
    cmd = data.get("command", "").strip()

    # Sécurité basique pour le playground CLI
    if not cmd.startswith("python3"):
        return jsonify({"output": "Pour des raisons de sécurité, seules les commandes 'python3' sont autorisées."})

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            cwd=BASE_DIR
        )
        dur = round(time.time() - t0, 2)
        out = proc.stdout + f"\n[Code de sortie: {proc.returncode} en {dur}s]\n"
        return jsonify({"output": out})
    except Exception as e:
        return jsonify({"output": f"Erreur d'exécution : {e}\n"})


def main():
    import argparse
    parser = argparse.ArgumentParser(description="CryptoVault - Interface Visuelle & Ligne de Commande")
    parser.add_argument("--port", type=int, default=5000, help="Port d'écoute HTTP (défaut: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Hôte d'écoute (défaut: 127.0.0.1)")
    parser.add_argument("--no-browser", action="store_true", help="Ne pas ouvrir automatiquement le navigateur")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    print("=" * 70)
    print("     CRYPTOVAULT — INTERFACE VISUELLE (GUI) & LIGNES DE COMMANDES (CLI)")
    print("=" * 70)
    print(f"[+] Palette : Rouge Sang (#990000) & Rouge Vin (#800020) & Blanc (#FFFFFF)")
    print(f"[+] Serveur Web lancé sur : {url}")
    print(f"[+] Lignes de commande CLI 100% compatibles et exécutables en direct")
    print("=" * 70)

    if not args.no_browser:
        # Ouverture automatique dans le navigateur par défaut
        try:
            webbrowser.open(url)
        except Exception:
            pass

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
