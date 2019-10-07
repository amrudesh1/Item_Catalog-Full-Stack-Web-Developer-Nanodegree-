import os
from catalog_app import app, bcrypt
from catalog_app.forms import RegistrationForm, LoginForm
from catalog_app.models import User, Categories, Items, session
from flask_login import login_user, current_user, logout_user
from flask import render_template, url_for, flash, redirect

categories = [
    'Soccer', 'BasketBall', 'BaseBall', 'Frisbee', 'Snowboarding'
]


@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if current_user.is_authenticated:
        return redirect(url_for('homeMain'))
    form = LoginForm()
    if form.validate_on_submit():
        user = session.query(User).filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('homeMain'))
        else:
            flash(f'Login Not Success!', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/register', methods=['GET', 'POST'])
def user_registration():
    if current_user.is_authenticated:
        return redirect(url_for('homeMain'))
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


@app.route('/', methods=['GET', 'POST'])
def homeMain():
    return render_template('main.html', categorie=session.query(Categories).filter_by().all(),
                           current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('homeMain'))
