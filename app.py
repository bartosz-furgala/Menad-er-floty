from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField, FloatField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import os


#Konfiguracja aplikacji
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fleet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#Modele danych
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    street = db.Column(db.String(150), nullable=False)
    city = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"{self.street}, {self.city}"

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    make = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    registration_number = db.Column(db.String(20), unique=True, nullable=False)

    trips = db.relationship('Trip', backref='vehicle', cascade='all, delete-orphan')
    refuels = db.relationship('Refuel', backref='vehicle', cascade='all, delete-orphan')

class Trip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_loc_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    end_loc_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False)
    distance = db.Column(db.Float, nullable=False)

    start_loc = db.relationship('Location', foreign_keys=[start_loc_id])
    end_loc = db.relationship('Location', foreign_keys=[end_loc_id])

class Refuel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False)
    liters = db.Column(db.Float, nullable=False)
    price = db.Column(db.Float, nullable=False)

#Formularze
class LoginForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired(), Length(1,150)])
    password = PasswordField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zaloguj')

class UserForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired(), Length(1,150)])
    password = PasswordField('Hasło', validators=[DataRequired(), EqualTo('confirm', message='Hasła muszą się zgadzać')])
    confirm = PasswordField('Potwierdź hasło')
    role = SelectField('Rola', choices=[('admin','Admin'),('user','Użytkownik')], validators=[DataRequired()])
    submit = SubmitField('Zapisz')

class LocationForm(FlaskForm):
    street = StringField('Ulica', validators=[DataRequired()])
    city = StringField('Miasto', validators=[DataRequired()])
    submit = SubmitField('Dodaj lokalizację')

class VehicleForm(FlaskForm):
    make = StringField('Marka', validators=[DataRequired()])
    model = StringField('Model', validators=[DataRequired()])
    year = IntegerField('Rok produkcji', validators=[DataRequired()])
    registration_number = StringField('Numer rejestracyjny', validators=[DataRequired(), Length(1, 20)])
    submit = SubmitField('Dodaj pojazd')

class TripForm(FlaskForm):
    start_loc = SelectField('Punkt startowy', coerce=int, validators=[DataRequired()])
    end_loc = SelectField('Punkt końcowy', coerce=int, validators=[DataRequired()])
    distance = FloatField('Dystans [km]', validators=[DataRequired()])
    submit = SubmitField('Zapisz przejazd')

class RefuelForm(FlaskForm):
    liters = FloatField('Litry', validators=[DataRequired()])
    price = FloatField('Kwota [PLN]', validators=[DataRequired()])
    submit = SubmitField('Zapisz tankowanie')

#Ładowanie użytkownika
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Trasy aplikacji
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Błędne dane logowania', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template(f'dashboard_{current_user.role}.html')

@app.route('/users', methods=['GET','POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    form = UserForm()
    users = User.query.all()
    if form.validate_on_submit():
        u = User(username=form.username.data, role=form.role.data)
        u.set_password(form.password.data)
        db.session.add(u)
        db.session.commit()
        flash('Użytkownik dodany', 'success')
        return redirect(url_for('manage_users'))
    if request.args.get('delete'):
        u = User.query.get(int(request.args.get('delete')))
        if u and u.username != 'admin':
            db.session.delete(u)
            db.session.commit()
            flash('Użytkownik usunięty', 'info')
        return redirect(url_for('manage_users'))
    return render_template('users.html', form=form, users=users)

@app.route('/locations', methods=['GET','POST'])
@login_required
def manage_locations():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    form = LocationForm()
    locs = Location.query.all()
    if form.validate_on_submit():
        db.session.add(Location(street=form.street.data, city=form.city.data))
        db.session.commit()
        flash('Lokalizacja dodana', 'success')
        return redirect(url_for('manage_locations'))
    if request.args.get('delete'):
        loc = Location.query.get(int(request.args.get('delete')))
        if loc:
            db.session.delete(loc)
            db.session.commit()
            flash('Lokalizacja usunięta', 'info')
        return redirect(url_for('manage_locations'))
    return render_template('locations.html', form=form, locs=locs)

@app.route('/vehicles', methods=['GET','POST'])
@login_required
def manage_vehicles():
    form = VehicleForm()
    vehicles = Vehicle.query.all()
    if current_user.role == 'admin' and form.validate_on_submit():
        db.session.add(Vehicle(make=form.make.data, model=form.model.data, year=form.year.data, registration_number=form.registration_number.data))
        db.session.commit()
        flash('Pojazd dodany', 'success')
        return redirect(url_for('manage_vehicles'))
    if current_user.role == 'admin' and request.args.get('delete'):
        v = Vehicle.query.get(int(request.args.get('delete')))
        if v:
            db.session.delete(v)
            db.session.commit()
            flash('Pojazd usunięty', 'info')
        return redirect(url_for('manage_vehicles'))
    return render_template('vehicles.html', form=form, vehicles=vehicles)

@app.route('/vehicles/<int:vid>', methods=['GET','POST'])
@login_required
def vehicle_detail(vid):
    v = Vehicle.query.get_or_404(vid)
    trip_form = TripForm()
    refuel_form = RefuelForm()
    locs = Location.query.all()
    choices = [(l.id, f"{l.street}, {l.city}") for l in locs]
    trip_form.start_loc.choices = trip_form.end_loc.choices = choices

    #dodawanie przejazdu
    if trip_form.submit.data and trip_form.validate_on_submit():
        t = Trip(
            start_loc_id=trip_form.start_loc.data,
            end_loc_id=trip_form.end_loc.data,
            distance=trip_form.distance.data,
            vehicle=v
        )
        db.session.add(t)
        db.session.commit()
        flash('Przejazd dodany', 'success')
        return redirect(url_for('vehicle_detail', vid=vid))

    #dodawanie tankowania
    if refuel_form.submit.data and refuel_form.validate_on_submit():
        r = Refuel(vehicle=v, liters=refuel_form.liters.data, price=refuel_form.price.data)
        db.session.add(r)
        db.session.commit()
        flash('Tankowanie dodane', 'success')
        return redirect(url_for('vehicle_detail', vid=vid))

    #usuwanie przejazdu (tylko admin)
    if request.args.get('del_trip') and current_user.role == 'admin':
        trip = Trip.query.get(int(request.args.get('del_trip')))
        if trip:
            db.session.delete(trip)
            db.session.commit()
            flash('Przejazd usunięty', 'info')
        return redirect(url_for('vehicle_detail', vid=vid))

    #usuwanie tankowania (tylko admin)
    if request.args.get('del_refuel') and current_user.role == 'admin':
        ref = Refuel.query.get(int(request.args.get('del_refuel')))
        if ref:
            db.session.delete(ref)
            db.session.commit()
            flash('Tankowanie usunięte', 'info')
        return redirect(url_for('vehicle_detail', vid=vid))

    return render_template(
        'vehicle_detail.html',
        vehicle=v,
        trip_form=trip_form,
        refuel_form=refuel_form,
        trips=v.trips,
        refuels=v.refuels
    )

#Uruchomienie i inicjalizacja bazy
def init_db():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
