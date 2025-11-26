# blockchain_client.py
# Client: wallet + UI, issue/verify certificate hashes. Strong path detection for templates/static.

import os, json, requests
from hashlib import sha256
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

# ---------- Robust path detection (fixes doubled folder on Windows) ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if os.path.basename(BASE_DIR).lower() == 'blockchain_client':
    ROOT_DIR = os.path.dirname(BASE_DIR)
    CLIENT_DIR = BASE_DIR
else:
    ROOT_DIR = BASE_DIR
    CLIENT_DIR = os.path.join(ROOT_DIR, 'blockchain_client')

TEMPLATES_DIR = os.path.join(CLIENT_DIR, 'templates')
STATIC_DIR    = os.path.join(CLIENT_DIR, 'static')

# fallbacks if moved
if not os.path.isdir(TEMPLATES_DIR):
    maybe = os.path.join(ROOT_DIR, 'templates')
    if os.path.isdir(maybe): TEMPLATES_DIR = maybe
if not os.path.isdir(STATIC_DIR):
    maybe = os.path.join(ROOT_DIR, 'static')
    if os.path.isdir(maybe): STATIC_DIR = maybe

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
CORS(app)
# Force Jinja to use exactly this path
if hasattr(app, 'jinja_loader') and hasattr(app.jinja_loader, 'searchpath'):
    app.jinja_loader.searchpath[:] = [TEMPLATES_DIR]

print("TEMPLATES_DIR =", TEMPLATES_DIR)
print("STATIC_DIR    =", STATIC_DIR)
print("Jinja search  =", getattr(app.jinja_loader, 'searchpath', []))

# ---------- Wallet helpers ----------
WALLET_PATH = os.path.join(ROOT_DIR, 'wallet.pem')
PUBLIC_PATH = os.path.join(ROOT_DIR, 'wallet.pub')

def ensure_keys():
    if not os.path.exists(WALLET_PATH) or not os.path.exists(PUBLIC_PATH):
        key = RSA.generate(2048)
        with open(WALLET_PATH,'w') as f: f.write(key.export_key().decode())
        with open(PUBLIC_PATH,'w') as f: f.write(key.publickey().export_key().decode())
    with open(WALLET_PATH) as f: priv = f.read()
    with open(PUBLIC_PATH) as f: pub = f.read()
    return priv, pub

def sign_message(private_pem: str, message: str) -> str:
    key = RSA.import_key(private_pem)
    signer = PKCS1_v1_5.new(key)
    d = SHA.new(message.encode('utf-8'))
    return signer.sign(d).hex()

DEFAULT_NODE = 'http://127.0.0.1:5001'

# ---------- Debug ----------
@app.get('/_debug_templates')
def _dbg():
    try: files = os.listdir(TEMPLATES_DIR)
    except Exception as e: files = [f'Error listing: {e}']
    return jsonify({"TEMPLATES_DIR": TEMPLATES_DIR, "FOUND_FILES": files,
                    "JINJA_SEARCHPATH": getattr(app.jinja_loader,'searchpath',[])})

# ---------- Home / Wallet ----------
@app.get('/')
def home(): return render_template('index.html')

@app.get('/wallet/new')
def wallet_new():
    priv, pub = ensure_keys()
    return jsonify({'private_key': priv, 'public_key': pub})

# ---------- Make Transaction (demo payment) ----------
@app.get('/make/transaction')
def make_tx_get(): return render_template('make_transaction.html')

@app.post('/generate/transaction')
def gen_tx():
    sender_pub = request.form['sender_public_key']
    sender_priv = request.form['sender_private_key']
    recipient_pub = request.form['recipient_public_key']
    amount = float(request.form['amount'])
    payload = {
        "sender_address": sender_pub,
        "recipient_address": recipient_pub,
        "amount": amount,
        "tx_type": "PAYMENT"
    }
    sig = sign_message(sender_priv, json.dumps(payload, sort_keys=True))
    return jsonify({'transaction':{
                        'sender_public_key': sender_pub,
                        'recipient_public_key': recipient_pub,
                        'amount': amount,
                        'tx_type':'PAYMENT'
                    },
                    'signature': sig})

# ---------- View Transactions ----------
@app.get('/view/transactions')
def view_txs(): return render_template('view_transactions.html')

# ---------- Helpers ----------
@app.post('/hash_file')
def hash_file():
    f = request.files.get('file')
    if not f: return jsonify({'ok':False,'error':'no file'}),400
    return jsonify({'ok':True,'sha256': sha256(f.read()).hexdigest()})

# ---------- Issue Certificate ----------
@app.route('/issue_certificate', methods=['GET','POST'])
def issue_certificate():
    priv, pub = ensure_keys()
    if request.method == 'GET':
        return render_template('issue_certificate.html', sender_public_key=pub, node=DEFAULT_NODE)

    node = request.form.get('node', DEFAULT_NODE)
    recipient = request.form.get('recipient_address','NONE')
    payload = {
        "sender_address": pub,
        "recipient_address": recipient,
        "amount": 0.0,
        "tx_type": "CERT_ISSUE",
        "doc_hash": request.form['doc_hash'].strip(),
        "issuer_id": request.form['issuer_id'].strip(),
        "student_ref": request.form['student_ref'].strip(),
        "program": request.form['program'].strip(),
        "issue_date": request.form['issue_date'].strip(),
        "nonce": int(request.form['nonce'])
    }
    payload["signature"] = sign_message(priv, json.dumps(payload, sort_keys=True))

    try:
        r = requests.post(f'{node}/transactions/new', json=payload, timeout=8)
        msg = r.json()
    except Exception as e:
        msg = {"message": f"error: {e}"}
    return render_template('result.html', result=msg)

# ---------- Verify Certificate ----------
@app.route('/verify_certificate', methods=['GET','POST'])
def verify_certificate():
    if request.method == 'GET':
        return render_template('verify_certificate.html', node=DEFAULT_NODE, result=None)
    node = request.form.get('node', DEFAULT_NODE)
    doc_hash = request.form['doc_hash'].strip().lower()
    try:
        result = requests.get(f'{node}/verify', params={'hash':doc_hash}, timeout=8).json()
    except Exception as e:
        result = {"ok":False,"error":str(e)}
    return render_template('verify_certificate.html', node=node, result=result)

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('-p','--port', default=8000, type=int)
    args = p.parse_args()
    app.run(host='0.0.0.0', port=args.port, debug=True)
