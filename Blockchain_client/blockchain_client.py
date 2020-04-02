from flask import Flask, request, render_template, jsonify
from argparse import ArgumentParser
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import binascii
from collections import OrderedDict
import requests
import json


class Post:

    def __init__(self, user_public_key, user_private_key, head, content):
        self.user_public_key = user_public_key
        self.user_private_key = user_private_key
        self.head = head
        self.content = content

    def sign_post(self):
        private_key = RSA.importKey(binascii.unhexlify(self.user_private_key))
        signer = PKCS1_v1_5.new(private_key)
        hash = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(hash)).decode('ascii')

    def to_dict(self):
        return OrderedDict({
            'user_public_key': self.user_public_key,
            'head': self.head,
            'content': self.content,
        })


class Transaction:

    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount

    def sign_transection(self):
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        hash = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(hash)).decode('ascii')

    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'amount': self.amount,
        })


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/create/post', methods=['POST'])
def create_post():
    user_public_key = request.form['user_public_key']
    user_private_key = request.form['user_private_key']
    head = request.form['head']
    content = request.form['content']
    post = Post(user_public_key, user_private_key, head, content)
    response = {
        'post': post.to_dict(),
        'signature': post.sign_post()
    }
    return jsonify(response), 200


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    amount = request.form['amount']
    transaction = Transaction(sender_public_key, sender_private_key, recipient_public_key, amount)
    response = {
        'transaction': transaction.to_dict(),
        'signature': transaction.sign_transection()
    }
    return jsonify(response), 200


@app.route('/make/post')
def make_post():
    return render_template('make_post.html')


@app.route('/view/posts')
def view_posts():
    return render_template('view_posts.html')


@app.route('/view/transaction')
def view_transaction():
    return render_template('view_transaction.html')


@app.route('/view/post/<block>/<post>', methods=['POST'])
def view_post(block, post):
    url = request.form['node'] + "/get/post/" + block + "/" + post
    response = requests.post(url)
    data = json.loads(response.text)
    return render_template('view_post.html', data= data)


@app.route('/account/new')
def new_account():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format('DER'))).decode('ascii')
    }
    return jsonify(response), 200


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port
    app.run(host="127.0.0.1", port=port, debug=True)
