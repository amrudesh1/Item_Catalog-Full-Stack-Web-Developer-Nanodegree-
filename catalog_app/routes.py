import os
import random
import string
import json

import httplib2

from catalog_app import app, bcrypt
from catalog_app.forms import RegistrationForm, LoginForm
from catalog_app.models import User, Categories, Items, session
from flask_login import login_user, current_user, logout_user
from flask import render_template, \
    url_for, flash, redirect, request, make_response, jsonify
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import requests

GOOGLE_CLIENT_ID = '668405259059-sb3qfvqp75r1af4s' \
                   '578p181kbo3lvucs.apps.googleusercontent.com'


@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if current_user.is_authenticated:
        return redirect(url_for('homeMain'))
    form = LoginForm()
    if form.validate_on_submit():
        user = session.query(User).filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,
                                               form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('homeMain'))
        else:
            flash(f'Login Not Success!', 'danger')

    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', title='Login',
                           form=form, STATE=state, client_id=GOOGLE_CLIENT_ID)


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
@app.route('/home', methods=['GET', 'POST'])
def homeMain():
    if request.method == 'POST':
        print(request.form['name'])
        data = request.form['name']
        item = session.query(Items).filter_by(name=data).one()
        if item.user_id == current_user.id:
            session.delete(item)
            failed = False
            try:
                session.commit()
            except Exception as e:
                session.rollback()
                session.flush()
                failed = True
                if not failed:
                    flash(f'Deleted Successfully', 'success')
                else:
                    flash(f'Not Deleted Successfully', 'danger')

                return redirect(url_for('homeMain'))
        else:
            flash(f'User is not Authenticated to Delete the Item', 'danger')

    return render_template('main.html',
                           categorie=session.query(Categories).all(),
                           items=session.query(Items)
                           .order_by(Items.id.desc()).all(),
                           current_user=current_user)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    print(code)
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

        # Verify that the access token is used for the intended user.
    google_id = credentials.id_token['sub']
    if result['user_id'] != google_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
        # Verify that the access token is valid for this app.
    if result['issued_to'] != GOOGLE_CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_google_id = login_session.get('google_id')
    if stored_access_token is not None and google_id == stored_google_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['google_id'] = google_id

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    if "name" in data:
        login_session['username'] = data['name']
    else:
        name_corp = data['email'][:data['email'].find("@")]
        login_session['username'] = name_corp
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user_id = get_user_id(data["email"])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += "Hi" + login_session['username']
    return output


def gdisconnect():
    """Disconnect the Google account of the current logged-in user."""

    # Only disconnect the connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/logout')
def logout():
    if 'username' in login_session:
        gdisconnect()
        del login_session['google_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have been successfully logged out!")
        return redirect(url_for('homeMain'))
    else:
        logout_user()
        return redirect(url_for('homeMain'))


def get_user_id(email):
    """Get user ID by email.
    Argument:
        email (str) : the email of the user.
    """

    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except BaseException:
        return None


def create_user(login_session):
    """Crate a new user.
    Argument:
    login_session (dict): The login session.
    """

    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
    )
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


@app.route('/home/<string:categories_name>/items', methods=['GET', 'POST'])
def getCategories(categories_name):
    if request.method == 'POST':
        print(request.form['name'])
        data = request.form['name']
        item = session.query(Items).filter_by(name=data).one()
        session.delete(item)
        failed = False
        try:
            session.commit()
        except Exception as e:
            session.rollback()
            session.flush()
            failed = True

        if not failed:
            flash(f'Deleted Successfully', 'success')
        else:
            flash(f'Not Deleted Successfully', 'danger')

        return redirect(url_for('getCategories'))

    cat_id = session.query(Categories). \
        filter(Categories.category_name == categories_name).first()
    item = session.query(Items). \
        filter(Items.cat_id == cat_id.category_id).all()
    print(cat_id.category_id)
    return render_template('view_items.html',
                           categorie=session.query(Categories).all(),
                           items=item,
                           current_user=current_user)


@app.route('/home/<string:itemName>/edit', methods=['GET', 'POST'])
def editItem(itemName):
    if not current_user.is_authenticated:
        return redirect(url_for('homeMain'))
    name = ''
    desc = ''
    cat_id = ''
    print(itemName)
    item = session.query(Items).filter(Items.name == itemName).first()
    cat = session.query(Categories). \
        filter(Categories.category_id == item.cat_id).first()
    categories = session.query(Categories).all()
    if request.method == 'POST':
        for key in request.form:
            if key == 'ItemName':
                name = request.form[key]
                print(name)

            if key == 'ItemDesc':
                desc = request.form[key]
                print(desc)

            if key == 'ItemSelect':
                cat_id = request.form[key]
                print(cat_id)
        if item.user_id == current_user.id:
            print(name + ' ' + desc + ' ' + cat_id + "Data to be Updated")
            item = session.query(Items).filter_by(id=item.id).one()
            item.name = name
            item.description = desc
            item.cat_id = cat_id
            item.user_id = current_user.id
            session.add(item)
            failed = False
            try:
                session.commit()
            except Exception as e:
                session.rollback()
                session.flush()
                failed = True

            if not failed:
                flash(f'Updated Successfully', 'success')
            else:
                flash(f'Not Updated Successfully', 'danger')

            return redirect(url_for('homeMain'))
        else:
            flash(f'User is not Authenticated to Update this Item', 'danger')
    return render_template('edit_item.html',
                           item=item, cat=cat, categories=categories)


@app.route('/addItem', methods=['GET', 'POST'])
def addItem():
    if not current_user.is_authenticated:
        return redirect(url_for('homeMain'))
    name = ''
    desc = ''
    cat_id = ''
    categories = session.query(Categories).all()
    if request.method == 'POST':
        for key in request.form:
            if key == 'ItemName':
                name = request.form[key]
                print(name)

            if key == 'ItemDesc':
                desc = request.form[key]
                print(desc)

            if key == 'ItemSelect':
                cat_id = request.form[key]
                print(cat_id)

        item = Items(name=name,
                     description=desc,
                     user_id=current_user.id, cat_id=cat_id)
        session.add(item)
        try:
            session.commit()
        except Exception as e:
            session.rollback()
            session.flush()
            failed = True
            if not failed:
                flash(f'Added Successfully', 'success')
            else:
                flash(f'Not Added Successfully', 'danger')

        return redirect(url_for('homeMain'))

    return render_template('addItem.html', categories=categories)


@app.route('/home/categories/<int:category_id>/item/<int:item_id>/JSON')
def catalog_item_json(category_id, item_id):
    """Return JSON of a particular item in the catalog."""

    if exists_category(category_id) and exists_item(item_id):
        item = session.query(Items) \
            .filter_by(id=item_id, cat_id=category_id).first()
        if item is not None:
            return jsonify(item=item.serialize)
        else:
            return jsonify(
                error='item {} does not belong to category {}.'.format
                (item_id,
                 category_id))
    else:
        return jsonify(error='The item or the category does not exist.')


@app.route('/home/categories/JSON')
def categories_json():
    categories = session.query(Categories).all()
    return jsonify(categories=[i.serialize for i in categories])


@app.route('/home/addCategory', methods=['GET', 'POST'])
def add_category():
    if not current_user.is_authenticated:
        return redirect(url_for('homeMain'))
    name = ''
    if request.method == 'POST':
        for key in request.form:
            if key == 'ItemName':
                name = request.form[key]
                print(name)
        category = Categories(category_name=name, user_id=current_user.id)
        session.add(category)
        failed = False
        try:
            session.commit()
        except Exception as e:
            session.rollback()
            session.flush()
            failed = True

        if not failed:
            flash(f'Added Successfully', 'success')
        else:
            flash(f'Not Added Successfully', 'danger')
        return redirect(url_for('homeMain'))
    return render_template('add_category.html')


def exists_category(category_id):
    category = session.query(Categories). \
        filter_by(category_id=category_id).first()
    if category is not None:
        return True
    else:
        return False


def exists_item(item_id):
    item = session.query(Items).filter_by(id=item_id).first()
    if item is not None:
        return True
    else:
        return False
