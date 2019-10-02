import os
from flask import Flask, render_template, url_for, flash, redirect
from forms import RegistrationForm, LoginForm
from models import User, Categories, Items, session
from flask_bcrypt import Bcrypt
from flask_login import login_user

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = '7e158f52147dd91eb8853151dea4da9a'


categories = [
    'Soccer', 'BasketBall', 'BaseBall', 'Frisbee', 'Snowboarding'
]


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def user_login():
    form = LoginForm()
    if form.validate_on_submit():
        user = session.query(User).filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash(f'Login Not Success!', 'danger')
    return render_template('index.html', title='Login', form=form)


@app.route('/register', methods=['GET', 'POST'])
def user_registration():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')

        user = User(name=form.name.data, email=form.email.data,
                    password=hashed_password)
        session.add(user)
        session.commit()
        flash(f'Account Created for {form.name.data}!', 'success')
        return redirect(url_for('user_login'))
    return render_template('register.html', titile='Registration', form=form)


if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
