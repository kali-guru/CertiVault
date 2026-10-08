from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp

class RegisterForm(FlaskForm):
    name = StringField('Full name', validators=[DataRequired(), Length(max=120)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64), Regexp(r'^[A-Za-z0-9_]+$')])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=254)])
    password = PasswordField('Password (at least 12 characters)', validators=[DataRequired(), Length(min=12, max=128)])
    confirm = PasswordField('Confirm password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create secure account')

class LoginForm(FlaskForm):
    identity = StringField('Username or email', validators=[DataRequired(), Length(max=254)])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=128)])
    submit = SubmitField('Sign in')

class UploadForm(FlaskForm):
    file = FileField('Document (up to 16 MiB)', validators=[FileRequired()])
    submit = SubmitField('Upload document')

class PasswordForm(FlaskForm):
    password = PasswordField('Key passphrase (your registration password)', validators=[DataRequired(), Length(max=128)])
    submit = SubmitField('Continue securely')

class EncryptForm(FlaskForm):
    recipient = SelectField('Recipient', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Encrypt for recipient')

class RevokeForm(FlaskForm):
    reason = SelectField('Revocation reason', choices=[(v, v.replace('_',' ').title()) for v in ['KEY_COMPROMISE', 'SUPERSEDED', 'ACCOUNT_DISABLED', 'ADMINISTRATIVE_REVOCATION']])
    password = PasswordField('Confirm your password', validators=[DataRequired()])
    submit = SubmitField('Permanently revoke certificate')

class ValidateForm(FlaskForm):
    certificate = FileField('Public certificate (PEM)', validators=[FileRequired()])
    submit = SubmitField('Validate certificate')

class ChallengeForm(FlaskForm):
    identity = StringField('Username or email', validators=[DataRequired(), Length(max=254)])
    submit = SubmitField('Create challenge')

class ProofForm(FlaskForm):
    challenge_id = StringField('Challenge ID', validators=[DataRequired(), Length(max=64)])
    certificate = FileField('Public certificate (PEM)', validators=[FileRequired()])
    signature = TextAreaField('Base64 challenge signature from local signing tool', validators=[DataRequired(), Length(max=2048)])
    submit = SubmitField('Verify proof and sign in')

class VerifyForm(FlaskForm):
    file = FileField('Original or modified document', validators=[FileRequired()])
    evidence = FileField('Signature evidence JSON', validators=[FileRequired()])
    signer = StringField('Expected signer username', validators=[DataRequired(), Length(max=64)])
    submit = SubmitField('Verify document and signer')
