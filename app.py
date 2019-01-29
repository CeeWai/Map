from __future__ import print_function
import os, time, requests, geocoder, json, datetime, pickle, os.path
from geopy.geocoders import Nominatim
from flask import Flask, render_template, redirect, url_for, request, session, jsonify, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, DateTimeField, SubmitField, FileField, TextAreaField, DateField
from flask_wtf.file import FileRequired, FileAllowed
from wtforms.validators import InputRequired, Email, Length, DataRequired, ValidationError
from wtforms.widgets import TextArea, CheckboxInput
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from geojson import Point, Feature, FeatureCollection
from mapbox import Geocoder
from flask_dance.contrib.twitter import make_twitter_blueprint, twitter
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.consumer.backend.sqla import OAuthConsumerMixin, SQLAlchemyBackend
from flask_dance.consumer import oauth_authorized
from sqlalchemy.orm.exc import NoResultFound
from flask_admin.form.widgets import DateTimePickerWidget
from time import time
from flask_moment import Moment
from flask_uploads import UploadSet, configure_uploads, IMAGES
from datetime import datetime
from hashlib import md5


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"
ACCESS_KEY = 'pk.eyJ1IjoiY2Vld2FpIiwiYSI6ImNqbng3eDcyZDByeXgzcHBnY2w0cGloM2sifQ.NsvAT34SplBxuUvZsvUSKA'
photos = UploadSet('photos', IMAGES)
app.config['UPLOADED_PHOTOS_DEST'] = 'static/img'
configure_uploads(app, photos)
moment = Moment(app)
app.config['POSTS_PER_PAGE'] = 10


subs = db.Table('subs',
    db.Column('id', db.Integer, db.ForeignKey('user.id')),
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'))
)

requesters = db.Table('friends_requests',
    db.Column('request_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('requested_id', db.Integer, db.ForeignKey('user.id'))
)

friends = db.Table('friend',
    db.Column('friend_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('friend_w_id', db.Integer, db.ForeignKey('user.id'))
)

twitter_blueprint = make_twitter_blueprint(api_key='', api_secret='')

github_blueprint = make_github_blueprint(client_id='461d29fc867322082b41', client_secret='4d1bb977e8ab2a65700f35a739191651dd1ccbeb')

google_blueprint = make_google_blueprint(client_id='1017274687523-9tpt3p5ulut97imugt8nbmp9s3i40059.apps.googleusercontent.com',
client_secret='2-HFuLG07YIcULFlkxDZ6taj')

Client_ID = '1017274687523-tne2685hgpicn869d7dqv875f3ffprns.apps.googleusercontent.com'
Client_Secret = '3cMVk9sFvW4nDbbsV9_pNHJl'

app.register_blueprint(twitter_blueprint, url_prefix='/twitter_login')

app.register_blueprint(github_blueprint, url_prefix='/github_login')

app.register_blueprint(google_blueprint, url_prefix='/google_login')


@app.route('/google')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))

    account_info = google.get('/user')
    account_info_json = account_info.json()

    return '<h1> Your Google name is {}'.format(account_info_json['login'])


@oauth_authorized.connect_via(google_blueprint)
def google_logged_in(blueprint, token):
    account_info = blueprint.session.get("/oauth2/v2/userinfo")
    if account_info.ok:
        account_info_json = account_info.json()
        #to-fix
        #email = account_info_json['email']
        image_file = account_info_json['picture']
        username = account_info_json['name']
        query = User.query.filter_by(username=username)
        try:
            user = query.one()
        except NoResultFound:
            user = User(image_file=image_file, username=username)
            db.session.add(user)
            db.session.commit()

        login_user(user, remember=True)


@app.route('/github')
def github_login():
    if not github.authorized:
        return redirect(url_for('github.login'))

    account_info = github.get('/user')
    account_info_json = account_info.json()

    return '<h1> Your Github name is {}'.format(account_info_json['login'])


@oauth_authorized.connect_via(github_blueprint)
def github_logged_in(blueprint, token):

    account_info = blueprint.session.get('/user')

    if account_info.ok:
        account_info_json = account_info.json()
        username = account_info_json['login']
        email = account_info_json['email']
        image_file = account_info_json['avatar_url']

        query = User.query.filter_by(username=username)

        try:
            user = query.one()
        except NoResultFound:
            user = User(username=username, email=email, image_file=image_file)
            db.session.add(user)
            db.session.commit()

        login_user(user)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), default=None)
    birthday = db.Column(db.String(64), default=None)
    country = db.Column(db.String(64), default=None)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    image_file = db.Column(db.String(20), default='https://moonvillageassociation.org/wp-content/uploads/2018/06/default-profile-picture1-744x744.jpg')
    password = db.Column(db.String(80))
    businessboolean = db.Column(db.Boolean('Agree'), default=False)
    brandName = db.Column(db.String(50), default=None)
    brandDesc = db.Column(db.String(150), default=None)
    address = db.Column(db.String(200), default=None)
    hotline = db.Column(db.Integer(), default=None)
    b_email = db.Column(db.String(50), default=None)
    website = db.Column(db.String(100), default=None)
    operatingHours = db.Column(db.String(200), default=None)
    image = db.Column(db.String(200), default=None)
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    reply = db.relationship('Postreply', backref='author', lazy='dynamic')
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    post = db.relationship("BusinessPosts", backref=db.backref("author"))
    subscriptions = db.relationship('Event', secondary=subs, passive_deletes=True, backref=db.backref('subscribers', lazy='dynamic'))

    requested = db.relationship(
        'User', secondary=requesters,
        primaryjoin=(requesters.c.request_id == id),
        secondaryjoin=(requesters.c.requested_id == id),
        backref=db.backref('requesters', lazy='dynamic'), lazy='dynamic')
    friend = db.relationship(
        'User', secondary=friends,
        primaryjoin=(friends.c.friend_id == id),
        secondaryjoin=(friends.c.friend_w_id == id),
        backref=db.backref('friends', lazy='dynamic'), lazy='dynamic')
    messages_sent = db.relationship('Message',
                                    foreign_keys='Message.sender_id',
                                    backref='author', lazy='dynamic')
    messages_received = db.relationship('Message',
                                        foreign_keys='Message.recipient_id',
                                        backref='recipient', lazy='dynamic')
    last_message_read_time = db.Column(db.DateTime)
    notifications = db.relationship('Notification', backref='user',
                                    lazy='dynamic')

    def new_messages(self):
        last_read_time = self.last_message_read_time or datetime(1900, 1, 1)
        return Message.query.filter_by(recipient=self).filter(
            Message.timestamp > last_read_time).count()

    def add_notification(self, name, data):
        self.notifications.filter_by(name=name).delete()
        n = Notification(name=name, payload_json=json.dumps(data), user=self)
        db.session.add(n)
        return n

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def requests(self, user):
        if not self.is_requesting(user):
            self.requested.append(user)

    def delete_request(self, user):
        if self.is_requesting(user):
            self.requested.remove(user)

    def is_requesting(self, user):
        return self.requested.filter(
            requesters.c.requested_id == user.id
        ).count() > 0

    def accept_f(self, user):
        if not self.is_friend(user):
            self.friend.append(user)
            user.friend.append(self)
            self.requesters.remove(user)

    def decline_f(self, user):
        if not self.is_friend(user):
            self.requesters.remove(user)

    def is_friend(self, user):
        return self.friend.filter(
            friends.c.friend_w_id == user.id
        ).count() > 0

    def delete_friend(self, user):
        if self.is_friend(user):
            self.friend.remove(user)
            user.friend.remove(self)

    def friends_posts(self):
        friend = Post.query.join(
            friends, (friends.c.friend_id == Post.user_id)).filter(
                friends.c.friend_w_id == self.id)
        own = Post.query.filter_by(user_id=self.id)
        return friend.union(own).order_by(Post.timestamp.desc())

    def friends_u(self):
        friend = User.query.join(
            friends, (friends.c.friend_id == User.id)).filter(
                friends.c.friend_w_id == self.id)
        return friend.order_by(User.username.desc())

    def requests_u(self):
        request_u = User.query.join(
            requesters, (requesters.c.request_id == User.id)).filter(
                requesters.c.requested_id == self.id)
        return request_u.order_by(User.username.desc())

    def set_brandName(self, brandName):
        self.brandName = brandName

    def set_brandDesc(self, brandDesc):
        self.brandDesc = brandDesc

    def set_address(self, address):
        self.address = address

    def set_hotline(self, hotline):
        self.hotline = hotline

    def set_b_email(self, b_email):
        self.b_email = b_email

    def set_website(self, website):
        self.website = website

    def set_operatingHours(self, operatingHours):
        self.operatingHours = operatingHours

    def set_image(self, image):
        self.image = image

    def attend(self, theEvent):
        if self not in theEvent.subscribers:
            theEvent.subscribers.append(self)

    def unattend(self, theEvent):
        if self in theEvent.subscribers:
            theEvent.subscribers.remove(self)

    def __repr__(self):
        return f"User('{self.username}'), '{self.email}', '{self.image_file}'"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    image = db.Column(db.String(140))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    replies = db.relationship('Postreply', backref='Postreply', lazy='dynamic')
    likes = db.Column(db.Integer, default='0')

    def like(self):
        self.likes += 1

    def __repr__(self):
        return '<Post {}>'.format(self.body)


class Postreply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    def __repr__(self):
        return '<Reply {}>'.format(self.body)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return '<Message {}>'.format(self.body)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.Float, index=True, default=time)
    payload_json = db.Column(db.Text)

    def get_data(self):
        return json.loads(str(self.payload_json))




class OAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.Integer(), db.ForeignKey(User.id))
    user = db.relationship(User)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


github_blueprint.backend = SQLAlchemyBackend(OAuth, db.session, user=current_user, user_required=False)

google_blueprint.backend = SQLAlchemyBackend(OAuth, db.session, user=current_user, user_required=False)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(25), nullable=False)
    area = db.Column(db.String(50), nullable=False)
    owner_id = db.Column(db.Integer)
    start_date = db.Column(db.String(100))
    end_date = db.Column(db.String(100))
    desc = db.Column(db.String(1000), nullable=False)
    event_image = db.Column(db.String(20), nullable=False, default='anothereventdefault.jpg')

    def __repr__(self):
        return f"Event('{self.title}'), '{self.area}', '{self.start_date}', '{self.end_date}', '{self.desc}'," \
               f" '{self.owner_id}', '{self.event_image}' "


class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated


# Add your view from the admin dashboard here
#admin = Admin(app, index_view=AdminIndexView())
#admin.add_view(ModelView(User, db.session))
#admin.add_view(ModelView(Event, db.session))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


class EventForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(min=1, max=50)], render_kw={"placeholder": "Title"})
    area = StringField('Area', validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Area"})
    start_date = DateTimeField('Starting Time', format="20%y-%m-%d %H:%M:%S",
    render_kw={"placeholder": "Year-Month-Day Hour:Minutes:Seconds"}, widget=DateTimePickerWidget())
    end_date = DateTimeField('Ending Time', format="20%y-%m-%d %H:%M:%S",
    render_kw={"placeholder": "Year-Month-Day Hour:Minutes:Seconds"}, widget=DateTimePickerWidget())
    desc = StringField('Description', validators=[InputRequired()], widget=TextArea(),
    render_kw={"placeholder": "Description"})
    submit = SubmitField('Create Event')


class EditEventForm(FlaskForm):
    title = StringField('Title', validators=[Length(min=1, max=50)], render_kw={"placeholder": "Title"})
    area = StringField('Area', validators=[Length(min=4, max=50)], render_kw={"placeholder": "Area"})
    start_date = DateTimeField('Starting Time', format="20%y-%m-%d %H:%M:%S",
    render_kw={"placeholder": "Year-Month-Day Hour:Minutes:Seconds"}, widget=DateTimePickerWidget())
    end_date = DateTimeField('Ending Time', format="20%y-%m-%d %H:%M:%S",
    render_kw={"placeholder": "Year-Month-Day Hour:Minutes:Seconds"}, widget=DateTimePickerWidget())
    desc = StringField('Description', widget=TextArea(),
    render_kw={"placeholder": "Description"})
    image = FileField('Event Image')
    submit = SubmitField('Edit Event')


class EditProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    birthday = DateField('Birthday', format='%d/%m/%Y', validators=[DataRequired()])
    country = StringField('Country', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=16)])
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    submit = SubmitField('Submit')

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError('Please use a different username.')


class PostForm(FlaskForm):
    post = TextAreaField('Say something', validators=[
        DataRequired(), Length(min=1, max=140)])
    photo = FileField(validators=[DataRequired(), FileRequired(),
        FileAllowed(['jpg', 'png'], 'Images only!')])
    submit = SubmitField('Submit')


class ReplyForm(FlaskForm):
    Reply = TextAreaField('Reply', validators=[
        DataRequired(), Length(min=1, max=140)])
    submit = SubmitField('Reply')


class MessageForm(FlaskForm):
    message = TextAreaField('Message', validators=[
        DataRequired(), Length(min=0, max=140)])
    submit = SubmitField('Submit')



class joinEvent(FlaskForm):
    submit = SubmitField('Join Event')


class delEvent(FlaskForm):
    submit = SubmitField()


event_markers_list = []


def create_event_markers():
    event_markers = []
    for event in db.session.query(Event).all():
        g = geocoder.mapbox(event.area, key=ACCESS_KEY)
        point = Point([g.lng, g.lat])
        properties = {
            "description": event.desc,
            'title': event.title,
            'icon': 'campsite',
            'marker-color': '#3bb2d0',
            'event_image': event.event_image
        }
        feature = Feature(properties=properties, geometry=point)
        if current_user in event.subscribers.all():
            event_markers.append(feature)
            event_markers_list.append(event.event_image)
            print(event.title, g.lng, g.lat)
    return event_markers


@app.route('/')
def index():
    eventList = db.session.query(Event).all()
    event_locations = create_event_markers()
    event_markers_image = event_markers_list
    pointList = []
    for event in Event.query.all():
        g = geocoder.mapbox(event.area, key=ACCESS_KEY)
        thelng = str(g.lng)
        thelat = str(g.lat)
        #theURL = 'https://www.google.com/maps?q=' + thelat + ',' + thelng + '&ll=' + thelat + ',' + thelng + '&z=13'
        ip = geocoder.ip('me')
        reversegeocode = geocoder.mapbox([ip.lat, ip.lng], method='reverse', key=ACCESS_KEY)
        theURL = 'https://www.google.com/maps/dir/?api=1&origin=' + reversegeocode.address + '&destination=' + event.area + '&travelmode=walking'
        pointList.append(theURL)
    return render_template('map.html', eventList=eventList, event_locations=event_locations, event_markers_image=event_markers_image, pointList=pointList)


@app.route('/index', methods=['GET', 'POST'])
@login_required
def index1():
    form = PostForm()
    form2 = ReplyForm()
    if form.validate_on_submit():
        p = form.photo.data
        filename = secure_filename(p.filename)
        p.save('static/uploads/' + filename)
        post = Post(body=form.post.data, author=current_user, image=filename)
        db.session.add(post)
        db.session.commit()
        flash('Your post is now live!')
        return redirect(url_for('index1'))
    page = request.args.get('page', 1, type=int)
    posts = current_user.friends_posts().paginate(page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('index1', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('index1', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('index1.html', title='Home', form=form, form2=form2, posts=posts.items, next_url=next_url, prev_url=prev_url)


@app.route('/explore')
@login_required
def explore():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.timestamp.desc()).paginate(page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('explore', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('explore', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template("index1.html", title='Explore', posts=posts.items, next_url=next_url, prev_url=prev_url)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                print(current_user)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
#        return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect('dashboard')
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)


@app.route('/createEvents', methods=['GET', 'POST'])
@login_required
def event():
    form = EventForm()

    if form.validate_on_submit():
        new_event = Event(title=form.title.data, area=form.area.data, start_date=form.start_date.data, end_date=form.end_date.data, desc=form.desc.data, owner_id=current_user.id)
        db.session.add(new_event)
        new_event.subscribers.append(current_user)
        db.session.commit()

        return redirect('joinEvents')

    return render_template('createEvents.html', form=form)


@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = user.posts.order_by(Post.timestamp.desc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('user', username=user.username, page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('user', username=user.username, page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('user.html', user=user, posts=posts.items, next_url=next_url, prev_url=prev_url)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        current_user.birthday = form.birthday.data
        current_user.name = form.name.data
        current_user.country = form.country.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
        form.name.data = current_user.name
        form.country.data = current_user.country
    return render_template('edit_profile.html', title='Edit Profile', form=form)

@app.route('/request/<username>')
@login_required
def request1(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found'.format(username))
        return redirect(url_for('index'))

    if user == current_user:
        flash('You cannot friend yourself.')
        return redirect(url_for('user', username=username))

    current_user.requests(user)
    db.session.commit()
    flash('You have friend requested {}!'.format(username))
    return redirect(url_for('user', username=username))


@app.route('/unrequest/<username>')
@login_required
def unrequest(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found'.format(username))
        return redirect(url_for('index'))

    if user == current_user:
        flash('You cannot request yourself.')
        return redirect(url_for('user', username=username))

    current_user.delete_request(user)
    db.session.commit()
    flash('You have delete this request to {}!'.format(username))
    return redirect(url_for('user', username=username))


@app.route('/accept/<username>')
@login_required
def accept_friend(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found'.format(username))
        return redirect(url_for('index'))

    current_user.accept_f(user)
    db.session.commit()
    flash('{} is your friend now!'.format(username))
    return redirect(url_for('user', username=current_user.username))


@app.route('/decline/<username>')
@login_required
def decline_friend(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found'.format(username))
        return redirect(url_for('index'))

    current_user.decline_f(user)
    db.session.commit()
    flash('You have decline the friend request from {}!'.format(username))
    return redirect(url_for('user', username=current_user.username))


@app.route('/delete/<username>')
@login_required
def delete_friend(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found'.format(username))
        return redirect(url_for('index'))

    current_user.delete_friend(user)
    db.session.commit()
    flash('You are no longer friend with {}!'.format(username))
    return redirect(url_for('user', username=current_user.username))


@app.route('/friends/<username>')
@login_required
def friend_c(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    all_friends = user.friends_u().paginate(page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('friend_c', username=user.username, page=all_friends.next_num) \
        if all_friends.has_next else None
    prev_url = url_for('friend_c', username=user.username, page=all_friends.prev_num) \
        if all_friends.has_prev else None
    return render_template('friends.html', user=user, all_friends=all_friends.items, next_url=next_url, prev_url=prev_url)


@app.route('/requests/<username>')
@login_required
def requests(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    all_requests = user.requests_u().paginate(page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('requests', username=user.username, page=all_requests.next_num) \
        if all_requests.has_next else None
    prev_url = url_for('requests', username=user.username, page=all_requests.prev_num) \
        if all_requests.has_prev else None
    return render_template('request.html', user=user, requests=all_requests.items, next_url=next_url, prev_url=prev_url)


@app.route('/send_message/<recipient>', methods=['GET', 'POST'])
@login_required
def send_message(recipient):
    user = User.query.filter_by(username=recipient).first_or_404()
    form = MessageForm()
    if form.validate_on_submit():
        msg = Message(author=current_user, recipient=user,
                      body=form.message.data)
        db.session.add(msg)
        user.add_notification('unread_message_count', user.new_messages())
        db.session.commit()
        flash('Your message has been sent.')
        return redirect(url_for('user', username=recipient))
    return render_template('send_message.html', title='Send Message',
                           form=form, recipient=recipient)


@app.route('/user/<username>/popup')
@login_required
def user_popup(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user_popup.html', user=user)


@app.route('/messages')
@login_required
def messages():
    current_user.last_message_read_time = datetime.utcnow()
    current_user.add_notification('unread_message_count', 0)
    db.session.commit()
    page = request.args.get('page', 1, type=int)
    messages = current_user.messages_received.order_by(
        Message.timestamp.desc()).paginate(
            page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('messages', page=messages.next_num) \
        if messages.has_next else None
    prev_url = url_for('messages', page=messages.prev_num) \
        if messages.has_prev else None
    return render_template('messages.html', messages=messages.items,
                           next_url=next_url, prev_url=prev_url)


@app.route('/notifications')
@login_required
def notifications():
    since = request.args.get('since', 0.0, type=float)
    notifications = current_user.notifications.filter(
        Notification.timestamp > since).order_by(Notification.timestamp.asc())
    return jsonify([{
        'name': n.name,
        'data': n.get_data(),
        'timestamp': n.timestamp
    } for n in notifications])


@app.route('/posts/<postid>', methods=["GET", "POST"])
@login_required
def posts(postid):
    form = ReplyForm()
    post = Post.query.filter_by(id=postid).first()
    if form.validate_on_submit():
        form = Postreply(body=form.Reply.data, author=current_user, post_id=postid)
        db.session.add(form)
        db.session.commit()
        flash('Your reply is Live')
        return redirect(url_for('posts', postid=post.id))
    page = request.args.get('page', 1, type=int)
    replies = post.replies.order_by(Postreply.id.asc()).paginate(page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('posts', page=replies.next_num, postid=post.id) \
        if replies.has_next else None
    prev_url = url_for('posts', page=replies.prev_num, postid=post.id) \
        if replies.has_prev else None
    return render_template('post.html', post=post, form=form, reply_db=replies.items, next_url=next_url, prev_url=prev_url)


@app.route('/post/<postid>')
@login_required
def liking(postid):
    post = Post.query.filter_by(id=postid).first()
    post.like()
    db.session.commit()
    return redirect(url_for('posts', postid=post.id))


@app.route('/joinEvents')
@login_required
def joinEvents():
    eventList = db.session.query(Event).all()
    firstEvent = Event.query.first()
    pointList = []
    for event in Event.query.all():
        g = geocoder.mapbox(event.area, key=ACCESS_KEY)
        thelng = str(g.lng)
        thelat = str(g.lat)
        #theURL = 'https://www.google.com/maps?q=' + thelat + ',' + thelng + '&ll=' + thelat + ',' + thelng + '&z=13'
        ip = geocoder.ip('me')
        reversegeocode = geocoder.mapbox([ip.lat, ip.lng], method='reverse', key=ACCESS_KEY)
        theURL = 'https://www.google.com/maps/dir/?api=1&origin=' + reversegeocode.address + '&destination=' + event.area + '&travelmode=walking'
        pointList.append(theURL)
    print(pointList)
    return render_template('joinEvents.html', eventList=eventList, firstEvent=firstEvent, pointList=pointList)


@app.route('/joinEvents/delEvent/<eventid>')
@login_required
def delEvent(eventid):
    eventid = int(eventid)
    event = Event.query.filter_by(id=eventid).first()
    Event.query.filter_by(id=eventid).delete()
    db.session.commit()

    return redirect('joinEvents')


@app.route('/joinEvents/editEvents/<eventid>', methods=['GET', 'POST'])
@login_required
def editEvent(eventid):
    form = EditEventForm()
    eventid = eventid
    theEvent = Event.query.filter_by(id=eventid).first()
    if form.validate_on_submit():
        eventid = int(eventid)
        event = Event.query.filter_by(id=eventid)
        event.delete()
        new_event = Event(title=form.title.data, area=form.area.data, start_date=form.start_date.data,
                          end_date=form.end_date.data, desc=form.desc.data, owner_id=current_user.id)
        db.session.add(new_event)
        db.session.commit()

        return redirect('joinEvents')

    return render_template('editEvents.html', form=form, eventid=eventid, theEvent=theEvent)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/joinEvents/jointheparty/<eventid>')
@login_required
def joinEvent(eventid):
    eventid = int(eventid)
    event = Event.query.filter_by(id=eventid).first()
    event.subscribers.append(current_user)
    db.session.commit()
    return redirect(url_for('joinEvents'))


@app.route('/joinEvents/unattend/<eventid>')
@login_required
def unattendEvent(eventid):
    eventid = int(eventid)
    event = Event.query.filter_by(id=eventid).first()
    event.subscribers.remove(current_user)
    db.session.commit()
    return redirect(url_for('joinEvents'))


@app.route('/about_us')
def aboutUs():
    return render_template('about_us.html')


@app.route('/joinEvents/attendingList/<eventid>')
def showList(eventid):
    eventid = int(eventid)
    eventList = db.session.query(Event).all()
    firstEvent = Event.query.filter_by(id=eventid).first()
    theOpen = True
    pointList = []
    for event in Event.query.all():
        g = geocoder.mapbox(event.area, key=ACCESS_KEY)
        thelng = str(g.lng)
        thelat = str(g.lat)
        #theURL = 'https://www.google.com/maps?q=' + thelat + ',' + thelng + '&ll=' + thelat + ',' + thelng + '&z=13'
        ip = geocoder.ip('me')
        reversegeocode = geocoder.mapbox([ip.lat, ip.lng], method='reverse', key=ACCESS_KEY)
        theURL = 'https://www.google.com/maps/dir/?api=1&origin=' + reversegeocode.address + '&destination=' + event.area + '&travelmode=walking'
        pointList.append(theURL)
    return render_template('joinEvents.html', eventList=eventList, firstEvent=firstEvent, theOpen=theOpen, pointList=pointList)


# Business Posts
class BusinessPosts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    #blogger = current_user
    #bloggerImg = current_user.image_file
    blog = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    blog_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    postImage = db.Column(db.String(200))


# STORE PHOTOS IN DATABASE AND STATIC FOLDER
# BUSINESS GALLERY
photos = UploadSet('photos', IMAGES)
app.config['UPLOADED_PHOTOS_DEST'] = 'static/galleries'
configure_uploads(app, photos)


# WTForms
class BusinessForms(FlaskForm):
    brandName = StringField('Brand Name', validators=[DataRequired()])
    brandDesc = StringField('Brand Description', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    hotline = StringField('Hotline', validators=[DataRequired()])
    b_email = StringField('E-mail', validators=[DataRequired(), Email()])
    website = StringField('Website', validators=[DataRequired()])
    operatingHours = StringField('Operating Hours', validators=[DataRequired()])
    submit = SubmitField("Create profile!")

    def validate_brandName(self, brandName):
        user = User.query.filter_by(brandName=brandName.data).first()
        if user is not None:
            raise ValidationError('Please use a different Brand Name.')

    def validate_hotline(self, hotline):
        user = User.query.filter_by(hotline=hotline.data).first()
        if user is not None:
            raise ValidationError('Please use a different Hotline.')

    def validate_b_email(self, b_email):
        user = User.query.filter_by(b_email=b_email.data).first()
        if user is not None:
            raise ValidationError('Please use a different E-Mail.')

    def validate_website(self, website):
        user = User.query.filter_by(website=website.data).first()
        if user is not None:
            raise ValidationError('Please use a different Website.')


class PostStatus(FlaskForm):
    post = TextAreaField('Say something...', validators=[
        DataRequired(), Length(min=1, max=140)])
    submit = SubmitField('Submit')


# APP ROUTES
# REGISTER BUSINESS PAGE
@app.route("/register", methods=["POST", "GET"])
def register():
    form = BusinessForms()
    if form.validate_on_submit() and 'photo' in request.files:
        image = photos.save(request.files["photo"])
        user = User.query.filter_by(id=current_user.id).first()
        user.brandName = form.brandName.data
        user.brandDesc = form.brandDesc.data
        user.address = form.address.data
        user.hotline = form.hotline.data
        user.b_email = form.b_email.data
        user.website = form.website.data
        user.operatingHours = form.operatingHours.data
        user.image = image
        user.businessboolean = True
        db.session.commit()
        return redirect(url_for("businessprof", name=form.brandName.data))
    return render_template("RegisterProfile.html", form=form)


@app.route("/theBusiness", methods=["POST", "GET"])
def theBusiness():
    if current_user.businessboolean == True:
        return redirect("/profile/" + current_user.brandName)
    else:
        return redirect("register")


# BUSINESS PROFILE PAGE
@app.route("/profile/<name>", methods=["POST", "GET"])
def businessprof(name):
    business = User.query.filter_by(brandName=name).first()
    form = PostStatus()
    posts = BusinessPosts.query.filter_by(blog_id=business.id).all()
    if form.validate_on_submit():
        try:image = photos.save(request.files["photo"])
        except:
            image = None
        post1 = BusinessPosts(blog=form.post.data, author=business, postImage=image)  # current_user
        db.session.add(post1)
        db.session.commit()
        return redirect(url_for('businessprof', name=name))

    return render_template("BusinessProf.html", name=business, form=form, posts=posts)


# UPDATE BUSINESS PROFILE
@app.route("/profile/<name>/update", methods=["POST", "GET"])
def updatebusiness(name):
    businessName = User.query.filter_by(brandName=name).first()
    form = BusinessForms()
    if form.validate_on_submit() and 'photo' in request.files:
        image = photos.save(request.files["photo"])
        businessName.set_brandName(form.brandName.data)
        businessName.set_brandDesc(form.brandDesc.data)
        businessName.set_address(form.address.data)
        businessName.set_hotline(form.hotline.data)
        businessName.set_b_email(form.b_email.data)
        businessName.set_website(form.website.data)
        businessName.set_operatingHours(form.operatingHours.data)
        businessName.set_image(image)
        db.session.add(businessName)
        db.session.commit()
        return redirect(url_for("businessprof", name=form.brandName.data))
    return render_template("UpdateProfile.html", form=form, name=businessName)


class Listing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(15), unique=True)
    description = db.Column(db.String(500))
    hoursMon = db.Column(db.String(50))
    hoursTues = db.Column(db.String(50))
    hoursWed = db.Column(db.String(50))
    hoursThurs = db.Column(db.String(50))
    hoursFri = db.Column(db.String(50))
    hoursSat = db.Column(db.String(50))
    hoursSun = db.Column(db.String(50))
    address = db.Column(db.String(100))
    atmosphere = db.Column(db.String(25))
    paymentMode = db.Column(db.String(20))


class forms(FlaskForm):
    name = StringField('ShopName', validators=[InputRequired()])
    description = StringField('ShopDescription')
    hoursMon = StringField('shophoursMon')
    hoursTues = StringField('shophoursTues')
    hoursWed = StringField('shophoursWed')
    hoursThurs = StringField('shophoursThurs')
    hoursFri = StringField('shophoursFri')
    hoursSat = StringField('shophoursSat')
    hoursSun = StringField('shophoursSun')
    address = StringField('shopAddress', validators=[InputRequired()])
    atmosphere = StringField('shopAtmosphere', validators=[InputRequired()])
    paymentMode = StringField('shoppaymentMode', validators=[InputRequired()])
    submit = SubmitField('Submit')


@app.route('/listings')
def listing():
    all_listing = Listing.query.all()
    return render_template('listings.html', list=all_listing)


@app.route('/listings/<shopname>')
def shop(shopname):

    shop = Listing.query.filter_by(name=shopname).first()

    return render_template('Shop.html', shop=shop)


@app.route('/forms', methods=['GET', 'POST'])
def add_form():

    form = forms()

    if form.validate_on_submit():
        listing = Listing(name=form.name.data, description=form.description.data, hoursMon=form.hoursMon.data, hoursTues=form.hoursTues.data, hoursWed=form.hoursWed.data, hoursThurs=form.hoursThurs.data, hoursFri=form.hoursFri.data, hoursSat=form.hoursSat.data, hoursSun=form.hoursSun.data, address=form.address.data, atmosphere=form.atmosphere.data, paymentMode=form.paymentMode.data)
        db.session.add(listing)
        db.session.commit()
        return redirect(url_for('listing'))

    return render_template('form.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
