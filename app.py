import os, time, requests, geocoder, json
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
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
ACCESS_KEY = 'pk.eyJ1IjoiY2Vld2FpIiwiYSI6ImNqbng3eDcyZDByeXgzcHBnY2w0cGloM2sifQ.NsvAT34SplBxuUvZsvUSKA'

subs = db.Table('subs',
    db.Column('id', db.Integer, db.ForeignKey('user.id')),
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'))
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(80), nullable=False)
    subscriptions = db.relationship('Event', secondary=subs, passive_deletes=True, backref=db.backref('subscribers', lazy='dynamic'))

    def attend(self, theEvent):
        if self not in theEvent.subscribers:
            theEvent.subscribers.append(self)

    def unattend(self, theEvent):
        if self in theEvent.subscribers:
            theEvent.subscribers.remove(self)

    def __repr__(self):
        return f"User('{self.username}'), '{self.email}', '{self.image_file}'"


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(25), nullable=False)
    area = db.Column(db.String(50), nullable=False)
    owner_id = db.Column(db.Integer)
    start_date = db.Column(db.String(100), nullable=False)
    end_date = db.Column(db.String(100), nullable=False)
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
    start_date = DateTimeField('Starting Time', format="%y/%m/%d/%H:%M", validators=[DataRequired()],
    render_kw={"placeholder": "Year/Month/Day/Hour:Minutes"})
    end_date = DateTimeField('Ending Time', format="%y/%m/%d/%H:%M", validators=[DataRequired()],
    render_kw={"placeholder": "Year/Month/Day/Hour:Minutes"})
    desc = StringField('Description', validators=[InputRequired()], widget=TextArea(),
    render_kw={"placeholder": "Description"})
    submit = SubmitField('Create Event')


class EditEventForm(FlaskForm):
    title = StringField('Title', validators=[Length(min=1, max=50)], render_kw={"placeholder": "Title"})
    area = StringField('Area', validators=[Length(min=4, max=50)], render_kw={"placeholder": "Area"})
    start_date = DateTimeField('Starting Time', format="20%y-%m-%d %H:%M:%S",
    render_kw={"placeholder": "Year-Month-Day Hour:Minutes:Seconds"})
    end_date = DateTimeField('Ending Time', format="20%y-%m-%d %H:%M:%S",
    render_kw={"placeholder": "Year-Month-Day Hour:Minutes:Seconds"})
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
    return render_template('map.html', eventList=eventList, event_locations=event_locations, event_markers_image=event_markers_image)


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
    return render_template('joinEvents.html', eventList=eventList, firstEvent=firstEvent)


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


@app.route('/joinEvents/attendingList/<eventid>')
def showList(eventid):
    eventid = int(eventid)
    eventList = db.session.query(Event).all()
    firstEvent = Event.query.filter_by(id=eventid).first()
    theOpen = True
    return render_template('joinEvents.html', eventList=eventList, firstEvent=firstEvent, theOpen=theOpen)


if __name__ == '__main__':
    app.run(debug=True, port="80")
