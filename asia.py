from flask import Flask, render_template, redirect, url_for, request, flash

app = Flask(__name__)


if __name__ == "__main__":
    app.run(host='127.0.0.1')