import os
from flask import Flask, render_template, url_for

app = Flask(__name__)

categories = [
    'Soccer', 'BasketBall', 'BaseBall', 'Frisbee', 'Snowboarding'
]


@app.route('/')
@app.route('/login')
def user_login():
    return render_template('index.html', categories=categories)


if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
