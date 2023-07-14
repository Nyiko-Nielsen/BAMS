import math

from flask import Flask, session, render_template, request, url_for, redirect, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from sqlalchemy import ForeignKey, inspect,create_engine
from flask_bcrypt import Bcrypt
import openpyxl

import datetime
from datetime import date
from datetime import datetime
import schedule
import time
from sqlalchemy.orm import relationship
from datetime import timedelta
import os
from sqlalchemy import text
import pandas as pd
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer 
   
application = Flask(__name__)
application.app_context().push()
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bams.sqlite3'
engine = create_engine(application.config['SQLALCHEMY_DATABASE_URI'])
application.config['SESSION_COOKIE_SECURE'] = True
application.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
application.config['SECRET_KEY'] = "random Letago is the 0ne I w@nt string"
application.config['UPLOAD_FOLDER'] = 'uploads'  # Folder to store the uploaded files
application.config['ALLOWED_EXTENSIONS'] = {'xlsx', 'csv'}  # Allowed file extensions
# Upload folder
UPLOAD_FOLDER = 'static/files'
application.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy()
# Configure server parameters
application.config['MAIL_SERVER'] = 'smtp.gmail.com'
application.config['MAIL_PORT'] = 465
application.config['MAIL_USERNAME'] = 'nyiko.maswanganyi@nielsen.com'
application.config['MAIL_PASSWORD'] = 'iyiytvhyrxvheqek'
application.config['MAIL_USE_TLS'] = False
application.config['MAIL_USE_SSL'] = True
# Generate a unique token serializer
serializer = URLSafeTimedSerializer(application.config['SECRET_KEY'])

mail = Mail(application)
login_manager = LoginManager()
login_manager.init_app(application)
bcrypt = Bcrypt(application)
# initialize the app with the extension
db.init_app(application)

# Define User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    usertype = db.Column(db.String(250),nullable=False, default="viewer")
    respondents = relationship('Respondent', backref='user')
# Define Respondent model
class Respondent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(250))
    surname = db.Column(db.String(250) )
    contact_number = db.Column(db.Integer,default=" number unavailable" )
    alt_contact_number = db.Column(db.Integer,default="alternate number unavailable" )
    address = db.Column(db.String(250), default="address unavailable" )
    birthday = db.Column(db.String(250), default="birthday unavailable")
    consent_to_join = db.Column(db.String(250) ,default="yes" )
    panel_joined_date = db.Column(db.Date, default=date.today)
    recipients = relationship('Recipient', backref='respondent')
# Define days model
class Days(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    holiday_name = db.Column(db.String(250))
    message = db.Column(db.String(1000)) 
    day = db.Column(db.Date)
    recipients = relationship('Recipient', backref='day')
# Define Recipient model    
class Recipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    days_id = db.Column(db.Integer, db.ForeignKey('days.id'))
    respondent_id = db.Column(db.Integer, db.ForeignKey('respondent.id'))
    date_sent=db.Column(db.DateTime, default=datetime.now())
   



with application.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    # Load a user from the database based on the user ID
    return User.query.get(int(user_id))


@application.route('/')
def root():
    return redirect(url_for('login'))


@application.route('/home')
 
def home():
    # If user exists and has logged in
    if current_user.is_authenticated:
        return render_template('home.html',email=current_user.email)
    else:
        flash('You need to log in to access this page', 'error')
        return redirect(url_for('login'))


@application.route('/register', methods=["GET", "POST"])
def register():
    # Handle user registration form submission
    if request.method == "POST":
        email = request.form.get("email")
        email = email.lower()
        password = request.form.get("password")
        
        password2 = request.form.get('password2')
        #check if already registered
        user = User.query.filter_by(email=email).first()
        if user:
            flash('User already registered!', 'success')
        # Check password length
        if len(password) < 8:
            flash('Password should be at least 8 characters long', 'error')
            return redirect(url_for('register'))
        if password != password2:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))
        if not (email.endswith('@nielsen.com') or email.endswith('@venturebliss.co.bw')):
            flash('invalid company email: email must end with @nielsen.com or @venturebliss.co.bw', 'error')
            return redirect(url_for('register'))
        # Check for at least one uppercase letter
        if not any(char.isupper() for char in password):
            flash('Password should contain at least one uppercase letter', 'error')
            return redirect(url_for('register'))

        # Check for at least one lowercase letter
        if not any(char.islower() for char in password):
            flash('Password should contain at least one lowercase letter', 'error')
            return redirect(url_for('register'))

        # Check for at least one digit
        if not any(char.isdigit() for char in password):
            flash('Password should contain at least one digit', 'error')
            return redirect(url_for('register'))

        # Check if the password contains any special characters
        if not any(char.isalpha() for char in password):
            flash('password should contain at least one special character', 'error')
            return redirect(url_for("register"))
        
        token = serializer.dumps(email )
        token2 = serializer.dumps(password )
        # Send the password reset email
        auth_link = url_for('user_added', token=token,token2=token2, _external=True)
        message = Message('user authentification', sender='nyiko.maswanganyi@nielsen.com', recipients=[email])
        message.body = f'Click the following link to activate your account: {auth_link}'
        mail.send(message)

        flash('A user registration link has been sent to your email.')
        return redirect(url_for('login'))
    return render_template('registration.html')

@application.route('/user_added/<token>/<token2>', methods=["GET", "POST"])
def user_added(token,token2):
        admin_list=['nyiko.maswanganyi@nielsen.com','kabo@venturebliss.co.bw','richard.newcombe@nielsen.com']
        try:
            # Verify and validate the token
            email = serializer.loads(token , max_age=3600)
            # Verify and validate the token
            password = serializer.loads(token2 , max_age=3600)
        except:
            flash('The password reset link is invalid or has expired.')
            return redirect(url_for('register'))
        #if user is not an admin
        for email1 in admin_list:
          if email == email1:
          # Hash the password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(email=email, password=hashed_password,usertype='admin')
            db.session.add(user)
            db.session.commit()
            #if user is an admin
        else:
             hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
             user = User(email=email, password=hashed_password )
             
             db.session.add(user)
             db.session.commit()   

        flash('Your account is now active!','success')
        message = Message('account active', sender='nyiko.maswanganyi@nielsen.com', recipients=[email])
        message.body = 'Your account is now active'
        mail.send(message)
        return redirect(url_for("login"))
    
        return render_template('added.html')


@application.route("/login", methods=["GET", "POST"])
def login():
    # Handle user login form submission
    if request.method == "POST":
        email = request.form.get("email")
        email = email.lower()
        password = request.form.get("password")
        # Find the user with the provided email
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            # Log in the user
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for("home"))
        else:
            flash('Invalid email or password', 'error')

    return render_template('index.html')

 

table_names = None
result = None
query=None
@application.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    global result

    global table_names
    table_names = inspect(db.engine).get_table_names()
    keyword=['delete', 'update', 'insert', 'create', 'drop']
    if request.method == 'POST':
        global query
        query = request.form.get('query')
        print(current_user.usertype)
        print(query)
        #if you're not an admin you can't make changes in the database
        if current_user.usertype != "admin" and 'select' not in query.lower():
            for word in keyword:
             if word in query.lower():
                flash('You need admin rights to make changes to the database!', 'error')
                return redirect(url_for('dashboard'))

        #if you're an admin you can make changes in the database
        elif current_user.usertype == "admin" and 'select' not in query.lower():
         for word in keyword:
          if word in query.lower():
           try: 
                db.session.execute(text(query))
                db.session.commit()

                if 'respondent' in query.lower():
                    result = db.session.execute(text('SELECT * FROM respondent'))
                if 'days' in query.lower():
                    result = db.session.execute('SELECT * FROM days')
                if 'recipient' in query.lower():
                    result = db.session.execute('SELECT * FROM recipient')    
                if 'user' in query.lower():
                    result = db.session.execute('SELECT * FROM user')
                if 'create' in query.lower():
                    flash('Database Table created', 'success')
                    return redirect(url_for('dashboard'))
                if 'drop' in query.lower():
                    flash('Database Table dropped','success')
                    return redirect(url_for('dashboard'))
           except Exception as e:
               flash(f'An error occurred: {str(e)}', 'error')
               db.session.rollback()
               return redirect(url_for('dashboard'))

        else:
            try:
                result = db.session.execute(text(query))
                db.session.commit()
                print("else statement")
            except Exception as e:
                flash(f'An error occurred: {str(e)}', 'error')
                db.session.rollback()
                return redirect(url_for('dashboard'))
    # Export the query results to an Excel file
    if 'export' in request.args and query is not None :

        df = pd.read_sql(query, db.engine)
        print("these are the file contents",df.head())
        filename = 'query_results.xlsx'
        filepath = os.path.join(application.config['UPLOAD_FOLDER'], filename)
        df.to_excel(filepath, index=False)
        print('downloaded')
        return redirect(url_for('download', filename=filename))
    
    return render_template('dashboard.html', table_names=table_names, result=result)


@application.route("/download/<filename>", methods=["GET"])
def download(filename):
    uploads_folder = application.config['UPLOAD_FOLDER']
    filepath = os.path.join(uploads_folder, filename)
    return send_file(filepath, as_attachment=True, download_name=filename)


@application.route("/logout")
def logout():
    logout_user()
    # Clear the user's session data
    session.clear()
    flash('Your session ended and you were logged out', 'success')
    return redirect(url_for("login"))




@application.route("/upload", methods=['POST', 'GET'])
def uploadFiles():
    # get the uploaded file
    uploaded_file = request.files['myfile']
    if uploaded_file.filename != '':
        file_path = os.path.join(application.config['UPLOAD_FOLDER'], uploaded_file.filename)
        # set the file path

        uploaded_file.save(file_path)
        parseCSV(file_path)
        # save the file
    return redirect(url_for('home'))


def is_valid_phone_number(input):
    input_str = str(input)
    if input_str.isdigit():
        return True
    if isinstance(input, float) and not math.isnan(input):
        return True
    print(input, ': ', type(input))
    return False


def parseCSV(file_path):
    # CSV Column Names
    col_names = ['Name', 'Surname', 'Contact Number', 'Alternate Number', 'Address', 'Birthday', 'Consent', 'Join Date']
    # Use Pandas to parse the CSV file
    
    # Read the CSV file with the detected encoding
    csvData = pd.read_csv(file_path, names=col_names, header=None,skiprows=[0]  )
    # Loop through the Rows
    counter=0
    for _,row in csvData.iterrows():
        contact_number=row['Contact Number']
        alt_contact_number=row['Alternate Number']

        # print(contact_number, ": ", alt_contact_number)
        # print(type(contact_number), ": ", type(alt_contact_number))
        if not is_valid_phone_number(contact_number):
            if not is_valid_phone_number(alt_contact_number):
                # save row to the invalid data file and send it to person later
                continue
        exist1 = Respondent.query.filter_by(contact_number=contact_number).first()
        alt_contact_number_exists =  alt_contact_number is not None
        exist2 = None
        if alt_contact_number_exists:
            exist2 = Respondent.query.filter_by(alt_contact_number=alt_contact_number).first()
        
        if exist1 is not None or exist2 is not None:

            # print("exists", row)
            pass
        else: 
            print("not exists", row)
            try:
                respondent = Respondent(
                user_id=current_user.id,
                name=row['Name'],
                surname=row['Surname'],
                contact_number= (row['Contact Number']),
                alt_contact_number= (row['Alternate Number']),
                address=row['Address'],
                birthday=row['Birthday'],
                consent_to_join=row['Consent'],
                panel_joined_date=datetime.now()
                )
                db.session.add(respondent)
                db.session.commit()
                counter=counter+1

            except Exception as e:
                 flash(f'An error occurred: {str(e)}', 'error')
                 db.session.rollback()    
    flash('Database updated: ' +str(counter) +' rows','Success')


@application.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == "POST":
        email = request.form.get("email")
        email = email.lower()
        user = User.query.filter_by(email=email).first()
        if not (email.endswith('@nielsen.com') or email.endswith('@venturebliss.co.bw')):
            flash('invalid company email: email must end with @nielsen.com or @venturebliss.co.bw', 'error')
            return redirect(url_for('forgot'))
        if user:
            token = serializer.dumps(email, salt='password-reset')

            # Send the password reset email
            reset_link = url_for('reset_password', token=token, _external=True)
            message = Message('Password Reset', sender='nyiko.maswanganyi@nielsen.com', recipients=[email])
            message.body = f'Click the following link to reset your password: {reset_link}'
            mail.send(message)
    
            flash('A password reset link has been sent to your email.')
            
        else:
             flash('Provide an existing email','error')
        
    return render_template('forgot.html' )
    
    

@application.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Verify and validate the token
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        password2 = request.form['password2']

       
        if len(password) < 8:
            flash('Password should be at least 8 characters long', 'error')
            return redirect(url_for('reset_password', token=token))
        if password != password2:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_password', token=token))
        
        # Check for at least one uppercase letter
        if not any(char.isupper() for char in password):
            flash('Password should contain at least one uppercase letter', 'error')
            return redirect(url_for('reset_password', token=token))

        # Check for at least one lowercase letter
        if not any(char.islower() for char in password):
            flash('Password should contain at least one lowercase letter', 'error')
            return redirect(url_for('reset_password', token=token))

        # Check for at least one digit
        if not any(char.isdigit() for char in password):
            flash('Password should contain at least one digit', 'error')
            return redirect(url_for('reset_password', token=token))

        # Check if the password contains any special characters
        if not any(char.isalpha() for char in password):
            flash('password should contain at least one special character', 'error')
            return redirect(url_for('reset_password', token=token))
        # Find the user by email
        user = User.query.filter_by(email=email).first()
        hashed_password = bcrypt.generate_password_hash(password2).decode('utf-8')
        # Update the user's password
        user.password =hashed_password 
        db.session.commit()

        flash('Your password has been successfully reset.')
        return redirect(url_for('login'))

    return render_template('reset.html', token=token)
 
 
current_day=date.today() 
 
def task1():
            respondents = Respondent.query.all()
            days=Days.query.all()
            for unique_day in days:
                print(str(unique_day.day) == str(current_day) )
                if  str(unique_day.day) == str(current_day) :
                    for respondent in respondents:
                        email = 'nyikotaker@gmail.com'
                        message = Message('Bliss Venture Panel', sender='nyiko.maswanganyi@nielsen.com', recipients=[email])
                        message.body = unique_day.message 
                        mail.send(message)
                        sent = Recipient(date_sent=datetime.now())
                        db.session.add(sent)
                        db.session.commit() 
                        
                    
def task2():
     respondents = Respondent.query.all()
     for respondent in respondents:
         email = respondent.name
         message = Message('Nielsen Panel', sender='nyiko.maswanganyi@nielsen.com', recipients=[email])
         message.body = 'Happy generic message'
         mail.send(message)
     
         db.session.begin(subtransactions=True)
         sent= Recipient(date_sent=datetime.now())
         db.session.add(sent)
         db.session.commit()  


# Create the background scheduler
schedule.every().day.at("07:00").do(task1)
schedule.every(26).weeks.do(task2)


#Keep the program running
if __name__ == '__main__':
    application.run(debug=True )

while True:
    schedule.run_pending()
    time.sleep(1)