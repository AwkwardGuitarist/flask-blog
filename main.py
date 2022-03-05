from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os
import re
from functools import wraps
import bleach

app = Flask(__name__)

# To generate a secret_key python -c 'import secrets; print(secrets.token_hex())'
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
HASH_METHOD = "pbkdf2:sha256"

ckeditor = CKEditor(app)
Bootstrap(app)


# CONNECT TO DB
uri = os.environ.get("DATABASE_URL", "sqlite:///blog.db")  # or other relevant config var
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(1000), nullable=False, unique=True)
    password = db.Column(db.String(110), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = relationship('User', back_populates='posts')
    comments = relationship("Comment", back_populates="post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    text = db.Column(db.Text, nullable=False)
    author = relationship('User', back_populates='comments')
    post = relationship("BlogPost", back_populates="comments")


db.create_all()


login_manager = LoginManager()
login_manager.init_app(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# strips invalid tags/attributes
def strip_invalid_html(content):
    allowed_tags = ['a', 'abbr', 'acronym', 'address', 'b', 'br', 'div', 'dl', 'dt',
                    'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img',
                    'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'strike',
                    'span', 'strong', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
                    'thead', 'tr', 'tt', 'u', 'ul']
    allowed_attrs = {
        'a': ['href', 'target', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
    }
    cleaned = bleach.clean(content,
                           tags=allowed_tags,
                           attributes=allowed_attrs,
                           strip=True)
    return cleaned


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def check_if_admin(*args, **kwargs):
        if current_user.id != 1:
            abort(403, "Only admins can perform this action")
        else:
            return f(*args, **kwargs)
    return check_if_admin


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        h_and_s_password = generate_password_hash(password, HASH_METHOD, 16)
        user = User.query.filter_by(email=email).first()
        if user:
            flash("That email is already in use.", "error")
        else:
            user = User()
            # adding form values to table row
            user.name, user.email, user.password = name, email, h_and_s_password
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("You've successfully registered.", "success")
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Successfully signed in.", "success")
            return redirect(url_for('get_all_posts'))
        else:
            flash("Invalid username/password", "error")
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have signed out.", "success")
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for('login'))

        new_comment = Comment(author=current_user,
                              post=requested_post,
                              text=strip_invalid_html(form.comment.data))
        db.session.add(new_comment)
        db.session.commit()
        form.comment.data = ""
    comments = Comment.query.filter_by(post_id=post_id)
    return render_template("post.html", post=requested_post, comments=comments, form=form, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=strip_invalid_html(form.title.data),
            subtitle=strip_invalid_html(form.subtitle.data),
            body=strip_invalid_html(form.body.data),
            img_url=strip_invalid_html(form.img_url.data),
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = strip_invalid_html(edit_form.title.data)
        post.subtitle = strip_invalid_html(edit_form.subtitle.data)
        post.img_url = strip_invalid_html(edit_form.img_url.data)
        post.author = edit_form.author.data
        post.body = strip_invalid_html(edit_form.body.data)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
