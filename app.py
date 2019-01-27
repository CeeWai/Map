from __future__ import print_function
import os, time, requests, geocoder, json, datetime, pickle, os.path
from geopy.geocoders import Nominatim
from flask import Flask, render_template, redirect, url_for, request, session, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, DateTimeField, SubmitField, FileField
from wtforms.validators import InputRequired, Email, Length, DataRequired
from wtforms.widgets import TextArea
from flask_sqlalchemy import SQLAlchemy
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


subs = db.Table('subs',
    db.Column('id', db.Integer, db.ForeignKey('user.id')),
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'))
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
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    image_file = db.Column(db.String(20), default='https://moonvillageassociation.org/wp-content/uploads/2018/06/default-profile-picture1-744x744.jpg')
    password = db.Column(db.String(80))
    subscriptions = db.relationship('Event', secondary=subs, passive_deletes=True, backref=db.backref('subscribers', lazy='dynamic'))

    def attend(self, theEvent):
        if self not in theEvent.subscribers:
            theEvent.subscribers.append(self)

    def unattend(self, theEvent):
        if self in theEvent.subscribers:
            theEvent.subscribers.remove(self)

    def __repr__(self):
        return f"User('{self.username}'), '{self.email}', '{self.image_file}'"


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
admin = Admin(app, index_view=AdminIndexView())
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Event, db.session))


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
        theURL = 'https://www.google.com/maps?q=' + thelat + ',' + thelng + '&ll=' + thelat + ',' + thelng + '&z=13'
        pointList.append(theURL)
    return render_template('map.html', eventList=eventList, event_locations=event_locations, event_markers_image=event_markers_image, pointList=pointList)


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


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username, image_file=current_user.image_file)


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
        theURL = 'https://www.google.com/maps?q=' + thelat + ',' + thelng + '&ll=' + thelat + ',' + thelng + '&z=13'
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


@app.route('/aboutUs')
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
        theURL = 'https://www.google.com/maps?q=' + thelat + ',' + thelng + '&ll=' + thelat + ',' + thelng + '&z=13'
        pointList.append(theURL)
    return render_template('joinEvents.html', eventList=eventList, firstEvent=firstEvent, theOpen=theOpen, pointList=pointList)


if __name__ == '__main__':
    app.run(debug=True)
