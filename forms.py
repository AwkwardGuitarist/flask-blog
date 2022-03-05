from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, HiddenField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = HiddenField("Author")
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=10)])
    submit = SubmitField("Sign Me Up")


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=10)])
    submit = SubmitField("Sign In")


class CommentForm(FlaskForm):
    comment = CKEditorField("Leave A Comment", validators=[DataRequired()])
    submit = SubmitField("Leave Comment")