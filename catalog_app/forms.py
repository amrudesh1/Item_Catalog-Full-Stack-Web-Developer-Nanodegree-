from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from catalog_app.models import User, session


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired()])
    email = StringField('Email', validators=[Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField(
        'Confirm Password', validators=[DataRequired(), EqualTo('password')])

    def validate_email(self, email):
        user = session.query(User).filter_by(email=email.data).first()
        if user:
            raise ValidationError('The Email is Already Registered.'
                                  ' Please Login with your Email.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
