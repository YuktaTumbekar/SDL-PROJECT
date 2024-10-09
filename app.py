
#main

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pdfplumber
import pandas as pd
import os
import re
import requests
import cv2
import numpy as np
from pdf2image import convert_from_path

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # "student" or "professor"

# Create database tables
def create_tables():
    db.create_all()

with app.app_context():
    create_tables()  # Create tables within the application context

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('upload_file'))
        flash('Login Unsuccessful. Please check username and password')
    return render_template('login.html')

# Route for the registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_password = generate_password_hash(password)  # No method argument
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration Successful!')
        return redirect(url_for('login'))
    return render_template('register.html')

# Route for the input form
@app.route('/', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        # Get data from the form
        name = request.form['name']
        enrollment_no = request.form['enrollment_no']
        year = request.form['year']
        branch = request.form['branch']
        course = request.form['course']
        marks = request.form['marks']
        certificate = request.files['certificate']

        if certificate:
            # Save uploaded file
            cert_path = os.path.join(app.config['UPLOAD_FOLDER'], certificate.filename)
            certificate.save(cert_path)

            # Process certificate by extracting the QR code and verifying it
            qr_data = extract_qr_from_pdf(cert_path)
            
            if qr_data:
                # Verify the certificate using the QR code data
                is_valid = verify_certificate(qr_data)
                # Update the Excel sheet with the results
                update_excel(name, is_valid, enrollment_no, branch, year, course, marks)
                # Determine the verification status to display to the user
                verification_status = "Authentic" if is_valid else "Non-Authentic"
            else:
                print(f"No QR code found in {certificate.filename}.")
                update_excel(name, False, enrollment_no, branch, year, course, marks)
                verification_status = "Non-Authentic"

            # Return the result to the user
            return render_template('result.html', status=verification_status)

    return render_template('upload.html')

# Set upload folder
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Functionality for extracting and verifying QR code from certificate
def extract_qr_from_pdf(pdf_file):
    images = convert_from_path(pdf_file)
    for image in images:
        image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(image)
        if data:
            return data
    return None

def verify_certificate(qr_url):
    try:
        response = requests.get(qr_url)
        return response.status_code == 200
    except Exception:
        return False

def update_excel(student_name, is_authentic, enrollment_no, branch, year, course, marks):
    try:
        df = pd.read_excel('certificate_verification_.xlsx')
    except FileNotFoundError:
        df = pd.DataFrame(columns=['Name', 'Enrollment No', 'Branch', 'Year', 'Course', 'Marks', 'Certificate_Verification'])
    
    status = "Authentic" if is_authentic else "Non-Authentic"
    new_row = {
        'Name': student_name,
        'Enrollment No': enrollment_no,
        'Branch': branch,
        'Year': year,
        'Course': course,
        'Marks': marks,
        'Certificate_Verification': status
    }
    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    df.to_excel('certificate_verification_.xlsx', index=False)

# Route to download the Excel sheet
@app.route('/download')
@login_required
def download_excel():
    return redirect(url_for('static', filename='certificate_verification_.xlsx'))

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)





