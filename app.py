from ast import Return
import bcrypt
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, SelectField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = '8f8866aec15fb97de69229e4'
app.config['UPLOAD_FOLDER'] = 'static/files'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view ="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#crating database tables.

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique = True)
    password = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), nullable=False)
    phone_number = db.Column(db.Integer, nullable=False)
    is_superuser = db.Column(db.Integer, nullable=False)

class Vehicle_User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, nullable=False)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), nullable=False)
    phone_number = db.Column(db.Integer, nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Vehicles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    model = db.Column(db.String(20), nullable=False) 
    brand = db.Column(db.String(20), nullable=False)
    licence_card = db.Column(db.String(300), nullable=False)

class Anotations(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, nullable=False)
    anotations = db.Column(db.String(1000), nullable=False)


db.create_all()

#creating app forms
class RegisterForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"Username"})
    
    password = PasswordField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"Password"})
    
    first_name = StringField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"First name"})
    
    last_name = StringField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"Last name"})
    
    email = StringField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"Email"})
    
    phone_number = StringField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"Phone number"})
    
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError(
                "that username already exists"
            )


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"Username"})
    
    password = PasswordField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"Password"})
    
    submit = SubmitField("Log in")

class RegisterVehicleUserForm(FlaskForm):
    first_name = StringField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"First name"})
    
    last_name = StringField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"Last name"})
    
    vehicle_id = StringField(
        validators=[InputRequired()], 
        render_kw={"placeholder":"Vehicle Id"})
    
    email = StringField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"Email"})
    
    phone_number = StringField(
        validators=[InputRequired(),Length(min=4,max=20)], 
        render_kw={"placeholder":"Phone number"})
    
    role = SelectField(
        validators=[InputRequired()],
        choices=[('Student'),('Administrative'),('Employee'),('Teacher')],
        validate_choice=False,
        render_kw={"placeholdel":"Role"}
    )
    
    submit = SubmitField("Register")

class RegistVehicleForm(FlaskForm):
    user_id = StringField("user_id",
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"ID Here"})
    brand = StringField("brand",
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"Brand here"})
    model = StringField(
        validators=[InputRequired(),Length(min=4, max=20)], 
        render_kw={"placeholder":"Model Here"})    
    file = FileField("licence Card (jpg only)", validators=[InputRequired()])
    submit = SubmitField("Register")

class AnotationsForm(FlaskForm):
    vehicle_id = StringField(validators=[InputRequired()], render_kw={"placeholder":"Vehicle ID"})
    textfield = TextAreaField(validators=[InputRequired()], render_kw={"placeholder":"Ingresa Anotacion"})
    submit = SubmitField("Create Anotation")


#app urls 

@app.route("/home")
@app.route("/")
def hello_world():
    return render_template('home.html')

@app.route("/login", methods = ['POST', 'GET'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user:
            if bcrypt.check_password_hash(user.password, password=request.form["contra"]):
                login_user(user)
                return redirect(url_for("dashboard"))
    """
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("dashboard"))
    """
    return render_template('accounts/login_page.html')

@app.route("/singup", methods = ['POST', 'GET'])
def registration():
    if request.method == 'POST':
        hashed_password = bcrypt.generate_password_hash(request.form["contra"])
        new_user = User(
            username= request.form["username"],
            password= hashed_password,
            first_name= request.form["first_name"],
            last_name=request.form["last_name"],
            email= request.form["email"],
            phone_number= request.form["phone_number"],
            is_superuser= 1  
            )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    """
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
            username= form.username.data,
            password= hashed_password,
            first_name= form.first_name.data,
            last_name=form.last_name.data,
            email= form.email.data,
            phone_number= form.phone_number.data,
            is_superuser= 1  
            )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    """
    return render_template('accounts/singup_page.html')

@app.route("/dashboard", methods = ['POST', 'GET'])
@app.route("/dashboard/vehiculos", methods = ['POST', 'GET'])
@login_required
def dashboard():
    form2 = AnotationsForm()
    form = RegistVehicleForm()
    vehicles = Vehicles.query

    if form2.validate_on_submit():
        new_anotation=Anotations(
            vehicle_id = int(form2.vehicle_id.data),
            anotations = form2.textfield.data
        )

    if form.validate_on_submit():
        file = form.file.data
        path = os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['UPLOAD_FOLDER'],secure_filename(file.filename))
        file.save(path)
        new_vehicle = Vehicles(
            user_id = int(form.user_id.data),
            model = form.model.data,
            brand = form.brand.data,
            licence_card = path
        )
        try:
            db.session.add(new_vehicle)
            db.session.commit()
            return redirect(url_for('dashboard'))
        except:
            return "error"
    return render_template("User_pages/dashboard.html",form=form, vehicles=vehicles, form2=form2 )


@app.route("/dashboard/usuarios/delete/<int:id>")
def vuserdelete(id):
    if id is None:
        return redirect(url_for("user"))
    user_to_delete = Vehicle_User.query.get_or_404(id)
    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect(url_for("user"))

@app.route("/dashboard/usuarios/update/<int:id>", methods = ['POST', 'GET'])
def vuserupdate(id):
    user_to_update = Vehicle_User.query.get_or_404(id)
    if user_to_update:
        if request.method == "POST":
            user_to_update.first_name = request.form['fname']
            user_to_update.last_name = request.form["lname"]
            user_to_update.email = request.form["email"] 
            user_to_update.phone = request.form["phone"]
            user_to_update.vehicle_id = request.form["vehicleid"]
            db.session.commit()
            return redirect(url_for("user"))
    return render_template("User_pages/update_vuser.html")
    
@app.route("/dashboard/usuarios", methods = ['POST', 'GET'])
@login_required
def user():
    users = Vehicle_User.query
    form = RegisterVehicleUserForm() 
    if form.validate_on_submit():
        new_vehicle_user = Vehicle_User(
            vehicle_id= int(form.vehicle_id.data),
            first_name = form.first_name.data,
            last_name = form.last_name.data,
            email = form.email.data,
            phone_number = int(form.phone_number.data),
            role = form.role.data
        )
       
        db.session.add(new_vehicle_user)
        db.session.commit()
        return redirect(url_for('user'))
      
    return render_template("User_pages/user.html", users=users, form=form)

@app.route("/logout",methods = ['POST', 'GET'])
def logout():
    logout_user()
    return redirect(url_for("login")) 

@app.route("/admin", methods = ['POST', 'GET'])
@login_required
def admin():
    users = User.query
    is_superuser = current_user.is_superuser
    if is_superuser == 2:
        return render_template("User_pages/admin.html", users=users)
    else:
        flash("you must be admin to acces to the admin page")
        return redirect(url_for("dashboard"))

@app.route("/delete/<int:id>")
@login_required
def delete(id):
    user_to_delete = User.query.get_or_404(id)
    
    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect(url_for('admin'))

@app.route("/update/<int:id>", methods = ['POST', 'GET'])
@login_required
def update(id):
    user_to_update = User.query.get_or_404(id)
    if request.method == "POST":
        user_to_update.username = request.form["username"]
        user_to_update.first_name = request.form["fname"]
        user_to_update.email = request.form["email"]
        user_to_update.phone_number = request.form["phone"]

        db.session.commit()
        return redirect(url_for('admin'))
    return render_template("User_pages/update_user.html")    



if __name__ == "__main__":
    app.run(debug=True)