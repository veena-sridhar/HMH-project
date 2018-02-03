import re
from datetime import datetime

from flask import render_template, flash, redirect, request, url_for, g
from app import app, db
from app.forms import LoginForm, RegistrationForm, EditProfileForm, EntryForm, ResetPasswordRequestForm, ResetPasswordForm
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Post, Entry
from werkzeug.urls import url_parse
from app.algos import get_polarity_and_subjectivity, get_text_metrics, get_depression_factor
from app.forms import ResetPasswordRequestForm
from app.email import send_password_reset_email
from flask_babel import get_locale
from guess_language import guess_language

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
    g.locale = str(get_locale())

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    return render_template('index.html',
                            title = 'Home',
                            user = current_user)
    # page = request.args.get('page', 1, type = int)
    # posts = current_user.get_own_entries().paginate(page, app.config['POSTS_PER_PAGE'], False)
    # next_url = url_for('user', username = username, page = posts.next_num) if posts.has_next else None
    # prev_url = url_for('user', username = username, page = posts.prev_num) if posts.has_prev else None
    # return render_template('user.html',
    #                         user = user,
    #                         posts = posts.items,
    #                         next_url = next_url,
    #                         prev_url = prev_url)


@app.route('/login', methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():

        # Verify User
        user = User.query.filter_by(username = form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))

        # Login
        login_user(user, remember = form.remember_me.data)

        # Redirect
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)

    return render_template('login.html', title = 'Sign In', form = form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods = ['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():

        # Set Password
        user = User(username = form.username.data, email = form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        # Redirect
        flash('Congratulations, {} you are now a registered user!'.format(form.username.data))
        return redirect(url_for('login'))

    return render_template('register.html', title = 'Register', form = form)


@app.route('/reset_password_request', methods = ['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title = 'Reset Password', form = form)


@app.route('/reset_password/<token>', methods = ['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form = form)


@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username = username).first_or_404()
    page = request.args.get('page', 1, type = int)
    posts = user.get_own_entries().paginate(page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('user', username = username, page = posts.next_num) if posts.has_next else None
    prev_url = url_for('user', username = username, page = posts.prev_num) if posts.has_prev else None

    return render_template('user.html',
                            user = current_user,
                            posts = posts.items,
                            next_url = next_url,
                            prev_url = prev_url)


@app.route('/create', methods = ['GET', 'POST'])
@login_required
def create():
    if not current_user.is_authenticated:
        return redirect(url_for('index'))

    form = EntryForm()
    if form.validate_on_submit():

        

        # Textblob sentiment analysis
        p_and_s = get_polarity_and_subjectivity(form.content.data)
        polarity = p_and_s["polarity"]
        subjectivity = p_and_s["subjectivity"]

        # Senticnet4 - Extract Word Concept information
        word_metrics = get_text_metrics(form.content.data)

        mood_tags = ' '.join(word_metrics["moodtags"])
        word_semantics = ' '.join(word_metrics["semantics"])

        attention = word_metrics["other_measurements"]["attention"]
        sensitivity = word_metrics["other_measurements"]["sensitivity"]
        pleasantness = word_metrics["other_measurements"]["pleasantness"]
        aptitude = word_metrics["other_measurements"]["aptitude"]

        depression_factor = get_depression_factor(form.content.data)

        language = guess_language(form.content.data)
        if language == 'UNKNOWN' or len(language) > 5:
            language = ''

        # Build the Entry
        entry = Entry(title = form.title.data,
                      content = form.content.data,
                      slug = re.sub('[^\w]+', '-', form.title.data.lower()),
                      is_published = (not form.is_draft.data),
                      timestamp = datetime.utcnow(),
                      author = current_user,
                      language = language,

                      # Metric Info below
                      polarity = polarity,
                      subjectivity = subjectivity,
                      mood_tags = mood_tags,
                      word_semantics = word_semantics,
                      attention = attention,
                      sensitivity = sensitivity,
                      pleasantness = pleasantness,
                      aptitude = aptitude,
                      depression_factor = depression_factor)

        db.session.add(entry)
        db.session.commit()

        # Redirect
        flash('New Entry Composed!')
        return redirect(url_for('entries', username = current_user.username))

    return render_template('create.html', title = 'Create New Entry', form = form)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html',
                            title='Edit Profile',
                            form=form)


@app.route('/entries/<username>')
@login_required
def entries(username):
    user = User.query.filter_by(username = username).first_or_404()
    page = request.args.get('page', 1, type = int)
    posts = current_user.get_own_entries().paginate(page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('entries', username = username, page = posts.next_num) if posts.has_next else None
    prev_url = url_for('entries', username = username, page = posts.prev_num) if posts.has_prev else None
    return render_template('entries.html',
                            user = user,
                            posts = posts.items,
                            next_url = next_url,
                            prev_url = prev_url)


