from datetime import date, datetime
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

import os
current_year = datetime.now().year

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)
login_manager.init_app(app)



# CONFIGURE TABLES
# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = db.relationship('BlogPost', back_populates='author')
    comments = db.relationship('Comment', back_populates='comment_author')

class BlogPost(db.Model):
    __tablename__ = 'blog_posts'
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship('User', back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship('Comment', back_populates='parent_post')

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = db.relationship('User', back_populates='comments')

    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = db.relationship('BlogPost', back_populates='comments')




with app.app_context():
    db.create_all()

#Decorator for admin only status
def admin_only(function):
    @wraps(function)
    def decorated_function(*args):
        if not current_user.is_authenicated or not current_user.id==1:
            flash("You need to be an admin to access this page.")
            return redirect((url_for('login')))
        return function(*args)
    return decorated_function



@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():  # Check if the form submission is POST and valid
        email = form.email.data
        existing_user = User.query.filter_by(email=email).first()
        if existing_user is None:
            # User does not exist, so we can proceed with registration
            hash_salt_pw = generate_password_hash(form.password.data, method='pbkdf2:sha256:600000', salt_length=8)
            new_user = User(
                email=email,
                password=hash_salt_pw,
                name=form.name.data,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash("You are now registered and can log in.")
            return redirect(url_for('get_all_posts'))
        else:
            # User exists, don't allow to register again
            flash("Email already registered. Please log in.")
            return redirect(url_for('login'))
    # If it's GET or form is not valid, render the registration form again
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated, current_year=current_year)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form['password']
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            return redirect(url_for('get_all_posts'))

        elif user is None:
            flash('That email is not registered')
            return redirect(url_for('login'), form=form)

        elif check_password_hash(user.password, password) is False:
            flash('That password is incorrect')
            return redirect(url_for('login'), form=form)

    return render_template("login.html", form=form, logged_in=current_user.is_authenticated, current_year=current_year)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    #result = db.session.execute(db.select(BlogPost))
    posts = BlogPost.query.all() #result.scalars().all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, current_year=current_year)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    all_comments = Comment.query.filter_by(post_id=post_id).all()
    if form.validate_on_submit():
        new_comment = Comment(
            text=form.body.data,
            author_id=current_user.id,
            post_id=post_id,
        )
        db.session.add(new_comment)
        db.session.commit()
        flash("Your comment has been added.")
        return redirect(url_for('show_post', post_id=post_id))  # Redirect to avoid resubmitting the form
    return render_template("post.html", form=form, post=requested_post, all_comments=all_comments, logged_in=current_user.is_authenticated, current_year=current_year)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated, current_year=current_year)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated, current_year=current_year)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated, current_year=current_year)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated, current_year=current_year)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
