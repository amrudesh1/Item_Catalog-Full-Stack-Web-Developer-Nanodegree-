import os
from flask import Flask, render_template, url_for, flash, redirect
from forms import RegistrationForm, LoginForm

app = Flask(__name__)

app.config['SECRET_KEY'] = '7e158f52147dd91eb8853151dea4da9a'

categories = [
    'Soccer', 'BasketBall', 'BaseBall', 'Frisbee', 'Snowboarding'
]


@app.route('/')
@app.route('/login' ,methods=['GET', 'POST']) 
def user_login():
    form = LoginForm()
    return render_template('index.html', title='Login', form=form)


@app.route('/register', methods=['GET', 'POST'])
def user_registration():
    form = RegistrationForm()
    if form.validate_on_submit():
        flash(f'Account Created for {form.name.data}!', '_success_')
        return redirect(url_for('user_login'))
    return render_template('register.html', titile='Registration', form=form)


if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
