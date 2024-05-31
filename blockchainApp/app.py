import os
from flask import Flask, render_template, abort, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('./index.html')

#TODO: add block viewing page

#TODO: add PoW page

#TODO: add transaction page

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=False)