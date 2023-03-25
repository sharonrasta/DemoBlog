from functools import wraps
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

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['TEMPLATES_AUTO_RELOAD'] = True
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    def __init__(self):
        super().__init__()

    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('Users.id'))
    comments = relationship("Comment", back_populates="post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('Users.id'))
    comment_author = relationship("User", back_populates="comments")
    post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))



with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)




def admin_only(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return func(*args, **kwargs)
    return decorator


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    new_user = User()
    form = RegisterForm()
    if form.validate_on_submit():
        new_user.email = form.email.data
        new_user.name = form.name.data
        new_user.password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
        user_exist = User.query.filter_by(email=new_user.email).first()
        if user_exist is not None:
            flash("You've already signed up with that email, log in instead!", "register")
            return redirect(url_for("register"))
        db.session.add(new_user)
        db.session.commit()
        new_user = load_user(new_user.id)
        login_user(new_user)
        print()
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login_form', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        ret_user = User.query.filter_by(email=email).scalar()
        if not ret_user:
            flash("This email does not exist, please try again.", "login_form")
            return redirect(url_for("login"))
        password_true = check_password_hash(ret_user.password, password)
        if not password_true:
            flash("Incorrect password, please try again.", "login_form")
            return redirect(url_for("login"))
        if password_true:
            user = load_user(ret_user.id)
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    gravatar = Gravatar(app,
                        size=100,
                        rating='g',
                        default='retro',
                        force_default=False,
                        force_lower=False,
                        use_ssl=False,
                        base_url=None)
    comments = Comment.query.all()
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment()
        if not current_user.is_authenticated:
            flash("You need to log in or register to comment", "comment")
            return redirect(url_for("show_post", post_id=post_id))
        comment.author_id = current_user.id
        comment.text = form.comment.data
        comment.post_id = post_id
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, form=form, comments=comments, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
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
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author_id = post.author.id
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
