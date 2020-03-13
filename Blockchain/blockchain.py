from flask import Flask, render_template, jsonify, request
from argparse import ArgumentParser
from time import time
from flask_cors import CORS
from collections import OrderedDict
import binascii
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse


MINING_DIFFICULTY = 2
MINING_REWARD = 1
MINIG_SENDER = "The Blockchain"


class Blockchain:

    def __init__(self):
        self.posts = []
        self.posts_chain = []
        self.transactions = []
        self.transactions_chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace("-", "")
        self.create_posts_block(0, "00")
        self.create_transactions_block(0, "00")

    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def create_posts_block(self, nonce, previous_hash):
        block = {'block_number': len(self.posts_chain) + 1,
                 'timestamp': time(),
                 'posts': self.posts,
                 'nonce': nonce,
                 'previous_hash': previous_hash}
        self.posts = []
        self.posts_chain.append(block)
        return block

    def create_transactions_block(self, nonce, previous_hash):
        block = {'block_number': len(self.transactions_chain) + 1,
                 'timestamp': time(),
                 'transactions': self.transactions,
                 'nonce': nonce,
                 'previous_hash': previous_hash}
        self.transactions = []
        self.transactions_chain.append(block)
        return block

    @staticmethod
    def verify_signature(sender_public_key, signature, content):
        public_key = RSA.importKey(binascii.unhexlify(sender_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(content).encode('utf8'))
        try:
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False

    @staticmethod
    def valid_proof(list_of_content, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        guess = (str(list_of_content)+str(last_hash)+str(nonce)).encode('utf8')
        h = hashlib.new('sha256')
        h.update(guess)
        guess_hash = h.hexdigest()
        return guess_hash[:difficulty] == "0"*difficulty

    def posts_proof_of_work(self):
        last_block = self.posts_chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0
        while self.valid_proof(self.posts, last_hash, nonce) is False:
            nonce+=1
        return nonce

    def transactions_proof_of_work(self):
        last_block = self.transactions_chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1
        return nonce

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(block_string)
        return h.hexdigest()

    def resolve_conflict(self):
        neighbours = self.nodes
        new_posts_chain = None
        new_transactions_chain = None
        max_posts_length = len(self.posts_chain)
        max_transactions_length = len(self.transactions_chain)
        for node in neighbours:
            response = requests.get("http://" + node + "/chain")
            if response.status_code == 200:
                posts_chain_length = response.json()['posts_chain_length']
                posts_chain = response.json()['posts_chain']
                transactions_chain_length = response.json()['transactions_chain_length']
                transactions_chain = response.json()['transactions_chain']
                if posts_chain_length > max_posts_length and self.valid__posts_chain(posts_chain):
                    max_posts_length = posts_chain_length
                    new_posts_chain = posts_chain
                if transactions_chain_length > max_transactions_length and self.valid__posts_chain(transactions_chain):
                    max_transactions_length = transactions_chain_length
                    new_transactions_chain = transactions_chain
        check1 = check2 = None
        if new_posts_chain:
            valid_index = 0
            while True:
                if valid_index == len(self.posts_chain) or self.posts_chain[valid_index]['previous_hash'] != new_posts_chain[valid_index]['previous_hash']:
                    break
                valid_index+=1
            if valid_index!=len(new_posts_chain)-1 and valid_index != len(self.posts_chain):
                while valid_index!=len(self.posts_chain):
                    print(self.posts_chain[valid_index],1)
                    for post in self.posts_chain[valid_index]['posts']:
                        self.posts.append(post)
                    valid_index+=1
            self.posts_chain = new_posts_chain
            check1=1

        if new_transactions_chain:
            valid_index = 0
            while True:
                if valid_index == len(self.transactions_chain) or self.transactions_chain[valid_index]['previous_hash'] != new_transactions_chain[valid_index]['previous_hash']:
                    break
                valid_index+=1
            if valid_index!=len(new_transactions_chain)-1 and valid_index != len(self.transactions_chain):
                while valid_index!=len(self.transactions_chain):
                    for transaction in self.transactions_chain[valid_index]['transactions']:
                        self.transactions.append(transaction)
                    valid_index+=1
            self.transactions_chain = new_transactions_chain
            check2 = 1
        if check1 or check2:
            return True
        return False

    def valid__posts_chain(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            if block["previous_hash"] != self.hash(last_block) :
                return False
            posts = block['posts']
            post_elements = ['user_public_key', 'head', 'content']
            posts = [OrderedDict((k, post[k]) for k in post_elements) for post in posts]
            if not self.valid_proof(posts, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False
            last_block = block
            current_index += 1
        return True

    def valid_transactions_chain(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            if block["previous_hash"] != self.hash(last_block):
                return False
            transactions = {block['transactions'][:-1]}
            transaction_elements = ['sender_public_key', 'recipient_public_key', 'amount']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in
                            transactions]
            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False
            last_block = block
            current_index += 1
        return True

    def submit_post(self, user_public_key, signature, head, content):
        post = OrderedDict({
            'user_public_key': user_public_key,
            'head': head,
            'content': content,})
        signature_verification = self.verify_signature(user_public_key, signature, post)
        if signature_verification:
            self.posts.append(post)
            return len(self.posts_chain) + 1
        else:
            return False

    def submit_transaction(self, sender_public_key, recipient_public_key, signature, amount):
        transaction = OrderedDict({
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'amount': amount, })
        if sender_public_key == MINIG_SENDER:
            self.transactions.append(transaction)
            return len(self.transactions_chain) + 1
        else:
            signature_verification = self.verify_signature(sender_public_key, signature, transaction)
            if signature_verification:
                self.transactions.append(transaction)
                return len(self.transactions_chain) + 1
            else:
                return False


blockchain = Blockchain()

app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/configure')
def configure():
    return render_template('./configure.html')


@app.route('/posts/get', methods=['GET'])
def get_posts():
    posts = blockchain.posts
    response = {"posts": posts}
    return jsonify(response), 200


@app.route('/transactions/get', methods=['GET'])
def get_transaction():
    transactions = blockchain.transactions
    response = {"transactions": transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'posts_chain': blockchain.posts_chain,
        'posts_chain_length': len(blockchain.posts_chain),
        'transactions_chain': blockchain.transactions_chain,
        'transactions_chain_length': len(blockchain.transactions_chain)
    }
    return jsonify(response), 200


@app.route('/posts_chain', methods=['GET'])
def get_posts_chain():
    response = {
        'posts_chain': blockchain.posts_chain,
        'posts_chain_length': len(blockchain.posts_chain)
    }
    return jsonify(response), 200


@app.route('/transaction_chain', methods=['GET'])
def get_transactions_chain():
    response = {
        'transactions_chain': blockchain.transactions_chain,
        'transactions_chain_length': len(blockchain.transactions_chain)
    }
    return jsonify(response), 200


@app.route('/post/mine', methods=['GET'])
def post_chain_mine():
    nonce = blockchain.posts_proof_of_work()
    last_block = blockchain.posts_chain[-1]
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_posts_block(nonce, previous_hash)

    response = {
        "message": "New block created",
        "block_number": block["block_number"],
        "posts": block["posts"],
        "nonce": block["nonce"],
        "previous_hash": block["previous_hash"],
    }
    return jsonify(response), 200


@app.route('/transaction/mine', methods=['GET'])
def transaction_chain_mine():
    nonce = blockchain.transactions_proof_of_work()
    blockchain.submit_transaction(sender_public_key=MINIG_SENDER,
                                  recipient_public_key=blockchain.node_id,
                                  signature="",
                                  amount=MINING_REWARD)
    last_block = blockchain.transactions_chain[-1]
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_transactions_block(nonce, previous_hash)
    response = {
        "message": "New block created",
        "block_number": block["block_number"],
        "transactions": block["transactions"],
        "nonce": block["nonce"],
        "previous_hash": block["previous_hash"],
    }
    return jsonify(response), 200


@app.route('/post/new', methods=['POST'])
def new_post():
    values = request.form
    required = ["confirmation_user_public_key",
                "post_signature",
                "confirmation_head",
                "confirmation_content"]
    if not all (k in values for k in required):
        return "Missing values", 400
    post_result = blockchain.submit_post(values["confirmation_user_public_key"],
                                         values["post_signature"],
                                         values["confirmation_head"],
                                         values["confirmation_content"])
    if not post_result:
        response = {'message': 'Invalid ost'}
        return jsonify(response), 406
    else:
        response = {'message': 'Post will be added to the Block ' + str(post_result)}
        return jsonify(response), 201


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form
    required = ["confirmation_sender_public_key",
                "confirmation_recipient_public_key",
                "transaction_signature",
                "confirmation_amount"]
    if not all (k in values for k in required):
        return "Missing values", 400
    transaction_result = blockchain.submit_transaction(values["confirmation_sender_public_key"],
                                                       values["confirmation_recipient_public_key"],
                                                       values["transaction_signature"],
                                                       values["confirmation_amount"])
    if not transaction_result:
        response = {'message': 'Invalid Transaction'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to the Block ' + str(transaction_result)}
        return jsonify(response), 201


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {"nodes": nodes}
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", '').split(',')
    if nodes is None:
        return 'Error: Please supply a valid list of nodes', 400
    for node in nodes:
        blockchain.register_node(node)
    response = {
        'message': 'Nodes have been added',
        'total_nodes': [node for node in blockchain.nodes]
    }
    return jsonify(response), 200


@app.route('/nodes/resolve', methods=['GET'])
def resolve_nodes():
    if blockchain.resolve_conflict():
        response = {
            'message': "Conflict resolved"
        }
    else:
        response = {
            'message': "Already Longest Chain"
        }
    return jsonify(response), 200


@app.route('/get/post/<block>/<post>', methods=['POST'])
def view_post(block, post):
    req_post = blockchain.posts_chain[int(block)-1]['posts'][int(post)-1]
    data = {
        'user_public_key': req_post['user_public_key'],
        'head': req_post['head'],
        'content': req_post['content']
    }
    return jsonify(data), 200


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host="127.0.0.1", port=port, debug=True)
