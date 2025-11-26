# blockchain.py
# Academic Certificate Notary (Transcript Hashes)
# Node: chain, tx validation, mining, consensus, /verify.

import json, hashlib, time, re, requests
from uuid import uuid4
from urllib.parse import urlparse
from flask import Flask, jsonify, request
from flask_cors import CORS

# RSA signature verification
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

def verify_signature(public_key_pem: str, signature_hex: str, message: str) -> bool:
    try:
        rsakey = RSA.import_key(public_key_pem)
        verifier = PKCS1_v1_5.new(rsakey)
        d = SHA.new(message.encode("utf-8"))
        return verifier.verify(d, bytes.fromhex(signature_hex))
    except Exception:
        return False

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.nonces = {}  # sender -> highest nonce
        self.new_block(previous_hash='1', proof=100)  # genesis

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        return hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]) if self.chain else '1'
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, payload: dict):
        required = ['sender_address','recipient_address','amount','signature']
        if not all(k in payload for k in required):
            raise ValueError('missing required fields')

        tx_type = payload.get('tx_type','PAYMENT')

        if tx_type in ('CERT_ISSUE','CERT_REVOKE'):
            doc_hash = str(payload.get('doc_hash',''))
            if not re.fullmatch(r'[0-9a-fA-F]{64}', doc_hash):
                raise ValueError('doc_hash must be 64-hex SHA256')
            try:
                nonce = int(payload.get('nonce',0))
            except Exception:
                raise ValueError('nonce must be integer')
            last = self.nonces.get(payload['sender_address'],-1)
            if nonce <= last:
                raise ValueError('nonce must be strictly increasing')

        to_sign = payload.copy()
        sig = to_sign.pop('signature')
        msg = json.dumps(to_sign, sort_keys=True)
        if not verify_signature(payload['sender_address'], sig, msg):
            raise ValueError('invalid signature')

        tx = {
            'sender': payload['sender_address'],
            'recipient': payload['recipient_address'],
            'amount': payload.get('amount',0),
            'tx_type': tx_type,
            'doc_hash': payload.get('doc_hash'),
            'issuer_id': payload.get('issuer_id'),
            'student_ref': payload.get('student_ref'),
            'program': payload.get('program'),
            'issue_date': payload.get('issue_date'),
            'nonce': payload.get('nonce'),
            'timestamp': time.time(),
        }
        tx['tx_id'] = hashlib.sha256(
            (tx['sender']+tx['recipient']+(tx['doc_hash'] or '')+str(tx['nonce'])+str(tx['timestamp'])).encode()
        ).hexdigest()

        self.current_transactions.append(tx)
        if tx_type in ('CERT_ISSUE','CERT_REVOKE'):
            self.nonces[payload['sender_address']] = int(payload['nonce'])

        return self.last_block['index'] + 1

    # very simple PoW
    def proof_of_work(self, last_proof):
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        return hashlib.sha256(f'{last_proof}{proof}'.encode()).hexdigest()[:4] == '0000'

    # networking/consensus
    def register_node(self, address):
        p = urlparse(address)
        if p.netloc: self.nodes.add(p.netloc)
        elif p.path: self.nodes.add(p.path)
        else: raise ValueError('invalid URL')

    def valid_chain(self, chain):
        last = chain[0]
        for i in range(1,len(chain)):
            block = chain[i]
            if block['previous_hash'] != self.hash(last): return False
            if not self.valid_proof(last['proof'], block['proof']): return False
            last = block
        return True

    def resolve_conflicts(self):
        max_len = len(self.chain)
        new_chain = None
        for node in self.nodes:
            try:
                r = requests.get(f'http://{node}/chain', timeout=3)
                if r.status_code != 200: continue
                data = r.json()
                if data['length'] > max_len and self.valid_chain(data['chain']):
                    max_len = data['length']; new_chain = data['chain']
            except Exception:
                continue
        if new_chain:
            self.chain = new_chain
            return True
        return False

app = Flask(__name__)
CORS(app)
node_identifier = str(uuid4()).replace('-','')
blockchain = Blockchain()

@app.get('/mine')
def mine():
    proof = blockchain.proof_of_work(blockchain.last_block['proof'])
    reward_tx = {
        'sender':'0','recipient':node_identifier,'amount':1,'tx_type':'PAYMENT',
        'doc_hash':None,'issuer_id':None,'student_ref':None,'program':None,'issue_date':None,
        'nonce':None,'timestamp':time.time(),
        'tx_id': hashlib.sha256((str(time.time())+node_identifier).encode()).hexdigest()
    }
    blockchain.current_transactions.append(reward_tx)
    block = blockchain.new_block(proof)
    return jsonify({
        'message':'New Block Forged','index':block['index'],'transactions':block['transactions'],
        'proof':block['proof'],'previous_hash':block['previous_hash']
    }),200

@app.post('/transactions/new')
def receive_tx():
    values = request.get_json()
    if not values: return jsonify({'message':'No JSON received'}),400
    try:
        idx = blockchain.new_transaction(values)
    except Exception as e:
        return jsonify({'message':str(e)}),400
    return jsonify({'message':f'Transaction will be added to Block {idx}'}),201

@app.get('/transactions/pending')
def pending():
    return jsonify({'pending': blockchain.current_transactions}),200

@app.get('/chain')
def chain():
    return jsonify({'chain': blockchain.chain, 'length': len(blockchain.chain)}),200

@app.post('/nodes/register')
def register():
    values = request.get_json()
    nodes = values.get('nodes')
    if not isinstance(nodes,list): return jsonify({'message':'Please supply a list of nodes'}),400
    for n in nodes: blockchain.register_node(n)
    return jsonify({'message':'New nodes added','total_nodes': list(blockchain.nodes)}),201

@app.get('/nodes/resolve')
def resolve():
    replaced = blockchain.resolve_conflicts()
    return jsonify({'message': 'Our chain was replaced' if replaced else 'Our chain is authoritative',
                    'chain': blockchain.chain}),200

@app.get('/verify')
def verify():
    h = (request.args.get('hash') or '').lower().strip()
    if not re.fullmatch(r'[0-9a-f]{64}', h):
        return jsonify({'ok':False,'error':'invalid hash'}),400
    matches=[]
    for block in blockchain.chain:
        for tx in block['transactions']:
            if tx.get('tx_type')=='CERT_ISSUE' and (tx.get('doc_hash') or '').lower()==h:
                matches.append({
                    'block_index': block['index'],
                    'issuer_id': tx.get('issuer_id'),
                    'student_ref': tx.get('student_ref'),
                    'program': tx.get('program'),
                    'issue_date': tx.get('issue_date'),
                    'tx_id': tx.get('tx_id'),
                    'timestamp': tx.get('timestamp'),
                })
    return jsonify({'ok':True,'matches':matches}),200

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-p','--port', default=5001, type=int)
    args = parser.parse_args()
    app.run(host='0.0.0.0', port=args.port)
