import os
from flask import Flask, render_template, url_for
from forms import RegistrationForm, LoginForm

app = Flask(__name__)

app.config['SECRET_KEY'] = '7e158f52147dd91eb8853151dea4da9a'

categories = [
    'Soccer', 'BasketBall', 'BaseBall', 'Frisbee', 'Snowboarding'
]


@app.route('/')
@app.route('/login')
def user_login():
    form1 = RegistrationForm()
    form2 = LoginForm()
    return render_template('index.html', categories=categories)


if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
