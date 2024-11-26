import os
import MySQLdb
from MySQLdb.cursors import DictCursor
from flask_mysqldb import MySQL
from argon2 import PasswordHasher
<<<<<<< HEAD
=======
from argon2 import exceptions
>>>>>>> repo-a/main
from cryptography.fernet import Fernet, InvalidToken
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import argon2
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import re
import traceback
import logging
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp

def is_password_strong(password):
    # At least 8 characters
    if len(password) < 8:
        return False
    # Contains both uppercase and lowercase letters
    if not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password):
        return False
    # Contains digits
    if not re.search(r'\d', password):
        return False
    # Contains special characters (excluding spaces)
    if not re.search(r'[^\w\s]', password):
        return False
    # Password is strong
    return True

def send_email(to_email, subject, message):
    sender_email = "bot067744@gmail.com"
    sender_password = "ytwj euls irhw nrzo"  # Use a real app password or environment-secured password
    sender_name = "verificationbot"

    # Create MIMEText message
    msg = MIMEText(message, 'html')
    msg['Subject'] = subject
    msg['From'] = f"{sender_name} <{sender_email}>"
    msg['To'] = to_email

    # Send email via SMTP
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        print("Email sent successfully.")
    except Exception as e:
        print("Failed to send email:", e)
        raise #For raising the exception

app = Flask(__name__)
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = ""
app.config['MYSQL_DB'] = "users"
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['SECRET KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['WTF_CSRF_ENABLED'] = False

mysql = MySQL(app)

# PasswordHasher instance with custom parameters
ph = PasswordHasher(memory_cost=102400, time_cost=1, parallelism=8)
# Initialize CSRF Protection

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OTPVerificationForm(FlaskForm):
    otp = StringField('OTP', validators=[
        DataRequired(message="Please enter the OTP."),
        Length(min=6, max=6, message='OTP must be exactly 6 digits.'),
        Regexp('^\d{6}$', message='OTP must contain only numbers.')
    ])
    submit = SubmitField('Verify OTP')

class ResendOTPForm(FlaskForm):
    submit = SubmitField('Resend OTP')

# Home Route
@app.route('/home')
def home():
    if 'user_id' in session:
        user_id = session['user_id']
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT username FROM accounts WHERE Id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        username = user['username'] if user else "Unknown"
        return render_template("home.html", username=username)
    else:
        return redirect(url_for('login'))

@app.route("/", methods=["POST", "GET"])
def index():
    return render_template('login.html')

#Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form['username']
        email = request.form['email']
        master_pass = request.form['master_pass']
        confirm_master_pass = request.form['confirm_master_pass']
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']

        # Validate master password and confirm password match
        if master_pass != confirm_master_pass:
            flash("Master passwords do not match.", "error")
            return redirect(url_for('register'))

        # Validate master password strength
        if not is_password_strong(master_pass):
            flash("Master password is not strong enough.", "error")
            return redirect(url_for('register'))

<<<<<<< HEAD
=======
        # **Check if username already exists**
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT Id FROM accounts WHERE username = %s", (username,))
        user_with_same_username = cur.fetchone()
        cur.close()

        if user_with_same_username:
            flash("Username already exists. Please choose a different username.", "error")
            return redirect(url_for('register'))

        # **Check if email already exists**
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT Id FROM accounts WHERE email = %s", (email,))
        user_with_same_email = cur.fetchone()
        cur.close()

        if user_with_same_email:
            flash("Email already registered. Please use a different email address.", "error")
            return redirect(url_for('register'))

>>>>>>> repo-a/main
        # Hash the master password and security answer
        hashed_master_pass = ph.hash(master_pass)
        hashed_security_answer = ph.hash(security_answer)

        # Generate email verification token (e.g., UUID or random string)
        email_verification_token = str(uuid.uuid4())

        # Insert the new user into the database with email unverified
<<<<<<< HEAD
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO accounts (username, email, master_pass, security_question, security_answer, email_verified, email_verification_token)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (username, email, hashed_master_pass, security_question, hashed_security_answer, False, email_verification_token))
        mysql.connection.commit()
        cur.close()
=======
        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO accounts (username, email, master_pass, security_question, security_answer, email_verified, email_verification_token)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (username, email, hashed_master_pass, security_question, hashed_security_answer, False, email_verification_token))
            mysql.connection.commit()
            cur.close()
        except Exception as e:
            print(f"Error inserting new user: {e}")
            flash("An error occurred during registration. Please try again.", "error")
            return redirect(url_for('register'))
>>>>>>> repo-a/main

        # Send email verification
        verification_link = url_for('verify_email', token=email_verification_token, _external=True)
        subject = "Email Verification"
        message = f"""
        <p>Hi {username},</p>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="{verification_link}">{verification_link}</a></p>
        <p>Please do not reply to this email. If you did not request this verification, please contact our support team at djl0466@dlsud.edu.ph.</p>
        <p>Best regards,<br>Kryptos***</p>
        """
        send_email(email, subject, message)

        flash("Registration successful! Please check your email to verify your account.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

#verify email
@app.route('/verify_email/<token>')
def verify_email(token):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM accounts WHERE email_verification_token = %s", (token,))
    user = cur.fetchone()
    if user:
        cur.execute("UPDATE accounts SET email_verified = %s, email_verification_token = NULL WHERE Id = %s", (True, user['Id']))
        mysql.connection.commit()
        cur.close()
        flash("Email verified successfully! You can now log in.", "success")
        return redirect(url_for('login'))
    else:
        cur.close()
        flash("Invalid or expired verification link.", "error")
        return redirect(url_for('register'))
    
<<<<<<< HEAD
=======
#recover password
@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        email = request.form['email']
        try:
            # Check if email exists in the database
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT * FROM accounts WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()

            if user:
                # Generate OTP and expiry time
                otp = random.randint(100000, 999999)
                otp_expiry = datetime.now() + timedelta(minutes=5)

                # Update reset_otp and reset_otp_expiry in the database
                cur = mysql.connection.cursor()
                cur.execute("UPDATE accounts SET reset_otp = %s, reset_otp_expiry = %s WHERE email = %s",
                            (otp, otp_expiry, email))
                mysql.connection.commit()
                cur.close()

                # Send OTP email
                subject = "Your Password Reset OTP"
                message = f"""
                <p>Dear {user['username']},</p>
                <p>Your OTP for password reset is: <strong>{otp}</strong></p>
                <p>This OTP is valid for the next 5 minutes.</p>
                <p>Please do not reply to this email. If you did not request this, please ignore this email.</p>
                <p>Best regards,<br>Kryptos</p>
                """
                send_email(email, subject, message)

                flash("An OTP has been sent to your email address.", "success")
                session['reset_email'] = email  # Store email in session for the next steps
                return redirect(url_for('verify_reset_otp'))
            else:
                flash("Email address not found.", "error")
                return redirect(url_for('recover_password'))
        except Exception as e:
            print(f"Error during password recovery: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for('recover_password'))

    return render_template('recover_password.html')   

#verify reset OTP
@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if 'reset_email' not in session:
        flash("Session expired. Please start the password recovery process again.", "error")
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        otp_input = request.form['otp']
        email = session['reset_email']

        try:
            # Fetch the OTP and expiry from the database
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT reset_otp, reset_otp_expiry FROM accounts WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()

            if user:
                reset_otp = user['reset_otp']
                reset_otp_expiry = user['reset_otp_expiry']

                # Check if OTP is valid and not expired
                if reset_otp == otp_input and datetime.now() < reset_otp_expiry:
                    session['otp_verified'] = True
                    return redirect(url_for('security_question'))
                else:
                    flash("Invalid or expired OTP. Please try again.", "error")
                    return redirect(url_for('verify_reset_otp'))
            else:
                flash("User not found.", "error")
                return redirect(url_for('recover_password'))
        except Exception as e:
            print(f"Error during OTP verification: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for('verify_reset_otp'))

    return render_template('verify_reset_otp.html')

#security question
@app.route('/security_question', methods=['GET', 'POST'])
def security_question():
    if 'otp_verified' not in session or 'reset_email' not in session:
        flash("Session expired. Please start the password recovery process again.", "error")
        return redirect(url_for('recover_password'))

    email = session['reset_email']

    try:
        # Fetch the security question from the database
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT security_question FROM accounts WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            security_question = user['security_question']
        else:
            flash("User not found.", "error")
            return redirect(url_for('recover_password'))
    except Exception as e:
        print(f"Error fetching security question: {e}")
        flash("An error occurred. Please try again.", "error")
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        security_answer_input = request.form['security_answer']

        try:
            # Fetch the hashed security answer from the database
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT security_answer FROM accounts WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()

            if user:
                security_answer_hash = user['security_answer']

                # Use ph.verify to compare the input with the hashed answer
                try:
                    ph.verify(security_answer_hash, security_answer_input)
                    session['security_verified'] = True
                    return redirect(url_for('reset_password'))
                except exceptions.VerifyMismatchError:
                    # Incorrect security answer
                    flash("Incorrect security answer. Please try again.", "error")
                    return redirect(url_for('security_question'))
                except Exception as e:
                    # Handle other exceptions
                    print(f"Error during security answer verification: {e}")
                    flash("An error occurred. Please try again.", "error")
                    return redirect(url_for('security_question'))
            else:
                flash("User not found.", "error")
                return redirect(url_for('recover_password'))
        except Exception as e:
            print(f"Error during security answer verification: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for('security_question'))

    return render_template('security_question.html', security_question=security_question)

#reset_password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'security_verified' not in session or 'reset_email' not in session:
        flash("Session expired. Please start the password recovery process again.", "error")
        return redirect(url_for('recover_password'))

    email = session['reset_email']

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return redirect(url_for('reset_password'))

        try:
            # Hash the new password
            hashed_password = ph.hash(new_password)

            # Update the user's password in the database
            cur = mysql.connection.cursor()
            cur.execute("UPDATE accounts SET master_pass = %s WHERE email = %s", (hashed_password, email))
            mysql.connection.commit()
            cur.close()

            # Clear the session variables
            session.pop('reset_email', None)
            session.pop('otp_verified', None)
            session.pop('security_verified', None)

            flash("Your password has been reset successfully. You can now log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error resetting password: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for('reset_password'))

    return render_template('reset_password.html')

>>>>>>> repo-a/main
#settings
@app.route('/settings')
def settings():
    return render_template('settings.html')

# Login Route with Enhanced Error Handling, Account Lockout Notification, and Email Verification
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['master_pass']  # Renamed for clarity

        try:
            # Fetch user from the database
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT * FROM accounts WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()

            if user:
                # Check if email is verified
                if not user.get('email_verified'):
                    flash("Please verify your email before logging in.", "error")
                    return redirect(url_for('login'))

                # Check if account is locked
                lockout_until = user.get('lockout_until')
                if lockout_until:
                    # Parse lockout_until to datetime if necessary
                    if isinstance(lockout_until, str):
                        try:
                            lockout_until = datetime.strptime(lockout_until, '%Y-%m-%d %H:%M:%S')
                        except ValueError as ve:
                            print(f"Error parsing lockout_until: {ve}")
                            lockout_until = None
                    if lockout_until and datetime.now() < lockout_until:
                        flash("Account is temporarily locked due to multiple failed login attempts. Please try again later.", "error")
                        return redirect(url_for('login'))

                # Proceed with password verification
                try:
                    ph.verify(user['master_pass'], master_password)
                    # Password is correct
                    # Reset failed attempts on successful login
                    cur = mysql.connection.cursor()
                    cur.execute("UPDATE accounts SET failed_attempts = 0, lockout_until = NULL WHERE Id = %s", (user['Id'],))
                    mysql.connection.commit()
                    cur.close()

                    # Generate OTP and expiry time
                    otp = random.randint(100000, 999999)
                    otp_expiry = datetime.now() + timedelta(minutes=5)

                    # Update OTP and expiry in the accounts table
                    cur = mysql.connection.cursor()
                    cur.execute("UPDATE accounts SET otp = %s, otp_expiry = %s WHERE Id = %s", (otp, otp_expiry, user['Id']))
                    mysql.connection.commit()
                    cur.close()

                    # Send OTP email
                    subject = "Your OTP for Login"
                    message = f"""
                    <p>Dear {user['username']},</p>
                    <p>Your OTP for login is: <strong>{otp}</strong></p>
                    <p>This OTP is valid for the next 5 minutes.</p>
                    <p>Please do not reply to this email. If you did not request this OTP, please contact our support team at djl0466@dlsud.edu.ph.</p>
                    <p>Best regards,<br>Kryptos***</p>
                    """
                    send_email(user['email'], subject, message)

                    session['temp_user_id'] = user['Id']
                    flash("OTP sent to your email!", "success")
                    return redirect(url_for('otp_verification'))
                except argon2.exceptions.VerifyMismatchError:
                    # Password is incorrect
                    # Increment failed_attempts
                    cur = mysql.connection.cursor()
                    cur.execute("UPDATE accounts SET failed_attempts = failed_attempts + 1 WHERE Id = %s", (user['Id'],))
                    mysql.connection.commit()

                    # Fetch updated failed_attempts
                    cur = mysql.connection.cursor(DictCursor)
                    cur.execute("SELECT failed_attempts FROM accounts WHERE Id = %s", (user['Id'],))
                    updated_user = cur.fetchone()
                    cur.close()
                    failed_attempts = updated_user['failed_attempts']

                    if failed_attempts >= 5:
                        try:
                            # Lock account for 1 day
                            lockout_until = datetime.now() + timedelta(days=1)
                            lockout_until_str = lockout_until.strftime('%Y-%m-%d %H:%M:%S')

                            cur = mysql.connection.cursor()
                            cur.execute("UPDATE accounts SET lockout_until = %s WHERE Id = %s", (lockout_until_str, user['Id']))
                            mysql.connection.commit()
                            cur.close()
                        except Exception as e:
                            print(f"Error updating lockout_until: {e}")
                            traceback.print_exc()
                            flash("An error occurred during login. Please try again.", "error")
                            return redirect(url_for('login'))

                        # Send account lockout email notification
                        try:
                            subject = "Your Account Has Been Locked"
                            message = f"""
                            <p>Dear {user['username']},</p>
                            <p>Your account has been locked due to 5 invalid login attempts.</p>
                            <p>If this was not you, please consider changing your password immediately.</p>
                            <p>You will be able to attempt login again after 1 day.</p>
                            <p>If you need assistance, please contact our support team at djl0466@dlsud.edu.ph.</p>
                            <p>Best regards,<br>Kryptos***</p>
                            """
                            send_email(user['email'], subject, message)
                        except Exception as e:
                            print(f"Error sending lockout email: {e}")
                            traceback.print_exc()
                            # Decide if you want to proceed even if the email fails

                        flash("Account locked due to multiple failed login attempts. Please check your email for more information.", "error")
                    else:
                        remaining_attempts = 5 - failed_attempts
                        flash(f"Incorrect password. {remaining_attempts} attempt(s) remaining.", "error")
                    return redirect(url_for('login'))
                except Exception as e:
                    print(f"Error during password verification: {e}")
                    traceback.print_exc()  # This will print the full traceback
                    flash("An error occurred during login. Please try again.", "error")
                    return redirect(url_for('login'))
            else:
                # Username not found
                flash("Username not found. Please check and try again.", "error")
                return redirect(url_for('login'))
        except Exception as e:
            print(f"Error during login process: {e}")
            traceback.print_exc()  # This will print the full traceback
            flash("An error occurred during login. Please try again.", "error")
            return redirect(url_for('login'))

    return render_template('login.html')






# OTP Verification Route
@app.route('/otp_verification', methods=['GET', 'POST'])
def otp_verification():
    if 'temp_user_id' not in session:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for('login'))

    form = OTPVerificationForm()
    resend_form = ResendOTPForm()

    if form.validate_on_submit():
        entered_otp = form.otp.data
        user_id = session['temp_user_id']

        try:
            with mysql.connection.cursor(DictCursor) as cur:
                cur.execute("SELECT otp, otp_expiry FROM accounts WHERE Id = %s", (user_id,))
                user = cur.fetchone()

                if not user:
                    flash("User not found.", "error")
                    logger.error(f"User with ID {user_id} not found during OTP verification.")
                    return redirect(url_for('login'))

                stored_otp = user.get('otp')
                otp_expiry = user.get('otp_expiry')

                if not stored_otp or not otp_expiry:
                    flash("OTP not found. Please request a new one.", "error")
                    logger.warning(f"OTP or expiry not found for user ID {user_id}.")
                    return redirect(url_for('resend_otp'))

                if datetime.now() > otp_expiry:
                    flash("OTP has expired. Please request a new one.", "error")
                    logger.info(f"OTP expired for user ID {user_id}.")
                    return redirect(url_for('resend_otp'))

                if entered_otp == str(stored_otp):
                    # OTP is correct
                    session.pop('temp_user_id', None)
                    session['user_id'] = user_id  # Assuming 'user_id' is the key for logged-in users
                    flash("Logged in successfully!", "success")
                    logger.info(f"User ID {user_id} logged in successfully.")
                    return redirect(url_for('home'))
                else:
                    flash("Invalid OTP. Please try again.", "error")
                    logger.warning(f"Invalid OTP entered for user ID {user_id}.")
                    return redirect(url_for('otp_verification'))
        except Exception as e:
            logger.error(f"Error during OTP verification for user ID {user_id}: {e}")
            flash("An error occurred during OTP verification. Please try again.", "error")
            return redirect(url_for('otp_verification'))

    # Fetch user's email to display
    user_id = session['temp_user_id']
    try:
        with mysql.connection.cursor(DictCursor) as cur:
            cur.execute("SELECT email FROM accounts WHERE Id = %s", (user_id,))
            user = cur.fetchone()
            email = user.get('email') if user else 'your email'
    except Exception as e:
        logger.error(f"Error fetching email for user ID {user_id}: {e}")
        email = 'your email'

    return render_template('otp_verification.html', email=email, form=form, resend_form=resend_form)

<<<<<<< HEAD
#Route to Request Password Reset       
@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        email = request.form['email']

        # Check if the email exists in the database
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM accounts WHERE email = %s", (email,))
        account = cur.fetchone()

        if account:
            # Generate a 6-digit OTP
            otp = str(random.randint(100000, 999999))
            otp_expiry = datetime.now() + timedelta(minutes=10)  # OTP valid for 10 minutes

            # Store the OTP and expiry in the database
            cur.execute("UPDATE accounts SET reset_otp = %s, reset_otp_expiry = %s WHERE email = %s",
                        (otp, otp_expiry, email))
            mysql.connection.commit()

            # Send email with OTP
            subject = "Your Password Reset OTP"
            message = f"""
            <p>Dear {account['username']},</p>
            <p>Your OTP for password reset is: <strong>{otp}</strong></p>
            <p>This OTP is valid for the next 10 minutes.</p>
            <p>Please do not reply to this email. If you did not request this OTP, please contact our support team at djl0466@dlsud.edu.ph.</p>
            <p>Best regards,<br>Kyrptos***</p>
            """
            send_email(email, subject, message)

            # Store the user's email temporarily in the session
            session['reset_email'] = email

            flash("An OTP has been sent to your email.", "success")
            return redirect(url_for('verify_reset_otp'))
        else:
            flash("Email not found.", "error")
            return redirect(url_for('recover_password'))
    return render_template('recover_password.html')
=======

>>>>>>> repo-a/main

# Resend OTP Route
@app.route('/resend_otp', methods=['GET','POST'])
def resend_otp():
    if 'temp_user_id' not in session:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for('login'))

    user_id = session['temp_user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Fetch user email
        cur.execute("SELECT email, username FROM accounts WHERE Id = %s", (user_id,))
        user = cur.fetchone()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for('login'))

        # Generate a new OTP
        otp = random.randint(100000, 999999)
        otp_expiry = datetime.now() + timedelta(minutes=5)

        # Update OTP and expiry in the accounts table
        cur.execute("UPDATE accounts SET otp = %s, otp_expiry = %s WHERE Id = %s", (otp, otp_expiry, user_id))
        mysql.connection.commit()

        # Send OTP email
        subject = "Your OTP for Login (Resent)"
        message = f"""
        <p>Dear {user['username']},</p>
        <p>Your new OTP for login is: <strong>{otp}</strong></p>
        <p>This OTP is valid for the next 5 minutes.</p>
        <p>Please do not reply to this email. If you did not request this OTP, please contact our support team at djl0466@dlsud.edu.ph</p>
        <p>Best regards,<br>Kyrptos***</p>
        """
        send_email(user['email'], subject, message)
        
        flash("A new OTP has been sent to your email.", "success")
        return redirect(url_for('otp_verification'))
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error resending OTP: {e}")
        flash("Failed to resend OTP. Please try again.", "error")
        return redirect(url_for('otp_verification'))
    finally:
        cur.close()
        
<<<<<<< HEAD
# Route to Verify OTP and Proceed to Security Password Verification
@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if 'reset_email' not in session:
        flash("Session expired. Please request a new OTP.", "error")
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        otp_input = request.form['otp']
        email = session['reset_email']

        # Fetch the OTP and expiry from the database
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT reset_otp, reset_otp_expiry FROM accounts WHERE email = %s", (email,))
        account = cur.fetchone()
        cur.close()

        # Check if OTP is valid and not expired
        if account and account['reset_otp'] == otp_input and account['reset_otp_expiry'] > datetime.now():
            # OTP is valid
            session['otp_verified'] = True  # Set session variable to indicate OTP verification
            flash("OTP verified. Please enter your security password.", "success")
            return redirect(url_for('verify_security_password'))
        else:
            flash("Invalid or expired OTP. Please try again.", "error")
            return redirect(url_for('verify_reset_otp'))
    return render_template('verify_reset_otp.html')
=======
>>>>>>> repo-a/main

#resend otp

def resend_otp():
    if 'temp_user_id' not in session:
        flash("Session expired. Please log in again.", "error")
        logger.warning("Attempt to resend OTP without valid session.")
        return redirect(url_for('login'))

    user_id = session['temp_user_id']

    try:
        with mysql.connection.cursor(DictCursor) as cur:
            # Fetch user email and username
            cur.execute("SELECT username, email FROM accounts WHERE Id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                flash("User not found.", "error")
                logger.error(f"User with ID {user_id} not found during resend OTP.")
                return redirect(url_for('login'))

            # Generate a new OTP
            otp = random.randint(100000, 999999)
            otp_expiry = datetime.now() + timedelta(minutes=5)

            # Update OTP and expiry in the accounts table
            cur.execute("UPDATE accounts SET otp = %s, otp_expiry = %s WHERE Id = %s", (otp, otp_expiry, user_id))
            mysql.connection.commit()
            logger.info(f"Generated new OTP for user {user['username']} (ID: {user_id}).")

            # Send OTP email
            subject = "Your OTP for Login (Resent)"
            message = f"""
            <p>Dear {user['username']},</p>
            <p>Your new OTP for login is: <strong>{otp}</strong></p>
            <p>This OTP is valid for the next 5 minutes.</p>
            <p>Please do not reply to this email. If you did not request this OTP, please contact our support team at djl0466@dlsud.edu.ph.</p>
            <p>Best regards,<br>Kryptos***</p>
            """
            send_email(user['email'], subject, message)
            logger.info(f"Resent OTP email to {user['email']}.")

            flash("A new OTP has been sent to your email.", "success")
            return redirect(url_for('otp_verification'))
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Error resending OTP for user ID {user_id}: {e}")
        flash("Failed to resend OTP. Please try again.", "error")
        return redirect(url_for('otp_verification'))
        
#UPDATED
@app.route('/passwordvault')
def passwordvault():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cur = mysql.connection.cursor(DictCursor)  # Use DictCursor to fetch results as dictionaries

    # Fetch categories (keys with their associated encryption keys)
    cur.execute("SELECT key_id, key_name, `key` FROM `keys`")
    categories = cur.fetchall()

    passwords_by_category = {}
    for category in categories:
        key_id = category['key_id']
        key_name = category['key_name']
        encryption_key = category['key']

        # Print the encryption key being used for this category
        print(f"Using encryption key for key_id {key_id}, key_name {key_name}: {encryption_key}")

        fernet = Fernet(encryption_key)  # Initialize Fernet with the encryption key

        # Fetch passwords associated with this key_id
        cur.execute("SELECT password_id, site, login_name, passwords, title FROM passwords WHERE key_id = %s", (key_id,))
        encrypted_passwords = cur.fetchall()

        # Decrypt passwords for this category
        decrypted_passwords = []
        for password in encrypted_passwords:
            # Print the encrypted password before decryption
            print(f"Encrypted password for password_id {password['password_id']}: {password['passwords']}")
            
            try:
                # Attempt decryption
                decrypted_password = fernet.decrypt(password['passwords'].encode()).decode()
                decrypted_passwords.append({
                    'id': password['password_id'],
                    'site': password['site'],
                    'title': password['title'],
                    'login_name': password['login_name'],
                    'passwords': decrypted_password  # Add decrypted password
                })
            except InvalidToken:
                # Log error if decryption fails
                print(f"Decryption failed for password_id {password['password_id']} with key_id {key_id}")
                decrypted_passwords.append({
                    'id': password['password_id'],
                    'site': password['site'],
                    'title': password['title'],
                    'login_name': password['login_name'],
                    'passwords': "[Decryption Failed]"  # Placeholder if decryption fails
                })

        passwords_by_category[key_id] = decrypted_passwords

    cur.close()

    return render_template('passwordvault.html', categories=categories, passwords_by_category=passwords_by_category)


@app.route('/fetch_keys', methods=['GET'])
def fetch_keys():

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not authenticated'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT * FROM `keys` WHERE Id = %s", (user_id,))
        keys = cur.fetchall()
        if keys:
            keys_list = [{'key_name': key[2], 'key': key[3]} for key in keys]
            return jsonify({'success': True, 'keys': keys_list})
        else:
            return jsonify({'success': False, 'message': 'No keys found'}), 404
    finally:
        cur.close()

def get_keys_from_database(user_id):
    # Create a new database cursor
    cur = mysql.connection.cursor()
    
    # SQL query to fetch keys
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM `keys` WHERE user_id = %s", (user_id,))
    keys = cur.fetchall()
    cur.close()

    if keys:
        keys_list = [{'key_name': key[1], 'key': key[2]} for key in keys]
        return jsonify({'success': True, 'keys': keys_list})
    else:
        return jsonify({'success': False, 'message': 'No keys found'}), 404

@app.route('/verify_master_password', methods=['POST'])
def verify_master_password():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'User not authenticated'}), 401
    
    master_password = request.form.get('masterPassword')
    # Query the database to get the hashed master password for the user
    cur = mysql.connection.cursor()
    cur.execute("SELECT master_pass FROM accounts WHERE Id = %s", (user_id,))
    stored_password = cur.fetchone()
    cur.close()

    if stored_password and ph.verify(stored_password[0], master_password):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Incorrect password'}), 403


@app.route('/button_action', methods=['POST'])
def button_action():
    print("Received POST to /button_action")
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    key_name = request.form['key_name']
    print(f"Attempting to insert key for account_id: {user_id}")  # Log the user_id being used

    return generate_key(key_name, user_id)

def generate_key(key_name, account_id):
    print("Attempting to insert key for account_id:", account_id)  # Debug output

    # First, check if the account ID actually exists in the accounts table
    cur = mysql.connection.cursor()
    cur.execute("SELECT Id FROM accounts WHERE Id = %s", (account_id,))
    if not cur.fetchone():
        cur.close()
        print(f"No account found for ID {account_id}")  # Debug output
        return jsonify({'message': 'No account found with the given ID'}), 400

    key = Fernet.generate_key()
    key_string = key.decode()  # Convert bytes to string for storage

    try:
        cur.execute("INSERT INTO `keys` (id, key_name, `key`) VALUES (%s, %s, %s)", (account_id, key_name, key_string))
        mysql.connection.commit()
        print("Key inserted successfully")  # Success output
        return jsonify({'message': 'Key generated successfully'}), 200
    except Exception as e:
        mysql.connection.rollback()
        print(f"Failed to insert into database: {e}")  # Error output
        return jsonify({'message': 'Database insertion failed: ' + str(e)}), 500
    finally:
        cur.close()


@app.route('/fetch_containers', methods=['GET'])
def fetch_containers():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']

    cur = mysql.connection.cursor()
    try:
        # Fetch records from the passwords table for the logged-in user
        cur.execute("SELECT site, login_name , title FROM `passwords` WHERE key_id = %s", (user_id,))
        records = cur.fetchall()
        
        if not records:
            return jsonify({'message': 'No containers found'}), 404

        containers = []
        for record in records:
            site, login_name, title = record
            containers.append({
                'site': site,
                'login_name': login_name,
                'title': title
            })

        return jsonify({'success': True, 'containers': containers}), 200
    except Exception as e:
        print(f"General error: {str(e)}")
        return jsonify({'message': 'Failed to fetch data: ' + str(e)}), 500
    finally:
        cur.close()


@app.route('/add_container', methods=['POST'])
def add_container():
    # Step 1: Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    site = request.form.get('url')
    login_name = request.form.get('email')
    password = request.form.get('password')
    key_name = request.form.get('key_name')
    title = request.form.get('title')

    # Step 2: Validate required fields
    if not site or not login_name or not password or not key_name or not title:
        return jsonify({'message': 'Required fields are missing'}), 400

    print(f"Received data: site={site}, login_name={login_name}, password={password}, key_name={key_name}, title={title}")

    cur = mysql.connection.cursor()
    try:
        # Step 3: Fetch key_id and encryption key using only key_name
        cur.execute("SELECT key_id, `key` FROM `keys` WHERE key_name = %s", (key_name,))
        key_record = cur.fetchone()

        if not key_record:
            print("Key not found")
            return jsonify({'message': 'Key not found'}), 404

        key_id, encryption_key = key_record
        print(f"Fetched key_id: {key_id} and encryption key for key_name: {key_name}")

        # Step 4: Encrypt the password
        fernet = Fernet(encryption_key)
        encrypted_password = fernet.encrypt(password.encode()).decode()
        print(f"Encrypted password: {encrypted_password}")

        # Step 5: Insert into the passwords table with the correct key_id
        cur.execute("INSERT INTO `passwords` (key_id, site, login_name, passwords, title) VALUES (%s, %s, %s, %s, %s)", 
                    (key_id, site, login_name, encrypted_password, title))
        mysql.connection.commit()
        print("Data inserted successfully")
        
        return jsonify({'message': 'Container added successfully'}), 200
    except Exception as e:
        mysql.connection.rollback()
        print(f"Database insertion failed: {str(e)}")
        return jsonify({'message': f'Database insertion failed: {str(e)}'}), 500
    finally:
        cur.close()


@app.route('/verify_key', methods=['POST'])
def verify_key():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    key_name = request.form['key_name']

    cur = mysql.connection.cursor()
    try:
        # Fetch the encryption key from the keys table using the provided key_name
        cur.execute("SELECT `key` FROM `keys` WHERE Id = %s AND key_name = %s", (user_id, key_name))
        key_record = cur.fetchone()

        if not key_record:
            return jsonify({'message': 'Key not found'}), 404

        encryption_key = key_record[0]
        return jsonify({'message': 'Key verified', 'encryption_key': encryption_key}), 200
    except Exception as e:
        print(f"General error: {str(e)}")
        return jsonify({'message': 'Failed to verify key: ' + str(e)}), 500
    finally:
        cur.close()

@app.route('/decrypt_password', methods=['POST'])
def decrypt_password():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    site = request.form.get('site')
    login_name = request.form.get('login_name')
    key_name = request.form.get('key_name')
    title = request.form.get('title')

    if not all([site, login_name, key_name, title]):
        return jsonify({'message': 'Missing data in request'}), 400

    cur = mysql.connection.cursor()
    try:
        # Fetch the encryption key from the keys table using the provided key_name
        cur.execute("SELECT `key` FROM `keys` WHERE Id = %s AND key_name = %s", (user_id, key_name))
        key_record = cur.fetchone()

        if not key_record:
            return jsonify({'message': 'Key not found'}), 404

        encryption_key = key_record[0]

        # Fetch the encrypted password from the passwords table
        cur.execute("SELECT `passwords` FROM `passwords` WHERE key_id = %s AND site = %s AND login_name = %s AND title = %s", (user_id, site, login_name, title))
        password_record = cur.fetchone()

        if not password_record:
            return jsonify({'message': 'Password not found'}), 404

        encrypted_password = password_record[0]
        fernet = Fernet(encryption_key)
        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()

        return jsonify({'message': 'Password decrypted', 'password': decrypted_password}), 200
    except Exception as e:
        print(f"General error: {str(e)}")
        return jsonify({'message': 'Failed to decrypt password: ' + str(e)}), 500
    finally:
        cur.close()

#UPDATED - TO BE DELETED, GOAL IS TO CONNECT THE FIXED BUTTON TO THE ADD CONTAINER TO BE EFFICIENT    
@app.route('/add_password', methods=['POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    key_id = request.form.get('key_id')
    site = request.form.get('site')
    login_name = request.form.get('login_name')
    password = request.form.get('passwords')
    new_key_name = request.form.get('new_key_name')

    # Check for required fields
    if not site or not login_name or not password:
        return "Required fields are missing", 400

    cur = mysql.connection.cursor()

    # Check if a new key is to be created
    if key_id == 'new' and new_key_name:
        # Insert new key and retrieve the generated Key_id
        cur.execute("INSERT INTO keys (id, key_name, key) VALUES (%s, %s, %s)", 
                    (user_id, new_key_name, ''))  # Assuming 'key' field can be left empty
        mysql.connection.commit()
        key_id = cur.lastrowid  # Get the last inserted Key_id

    # Insert the new password entry
    cur.execute("INSERT INTO passwords (key_id, site, login_name, passwords, title) VALUES (%s, %s, %s, %s, %s)", 
                (key_id, site, login_name, password, site))
    mysql.connection.commit()
    cur.close()

    return redirect(url_for('passwordvault'))


@app.route('/get_key_id', methods=['POST'])
def get_key_id():
    key_name = request.form.get('key_name')
    # Assume you have a function or query to get the key_id based on key_name
    key = Key.query.filter_by(name=key_name).first()
    if key:
        return jsonify({'key_id': key.id})
    else:
        return jsonify({'error': 'Key not found'}), 404

@app.route('/delete_password/<int:password_id>', methods=['DELETE'])
def delete_password(password_id):
    cur = mysql.connection.cursor()

    try:
        # Attempt to delete the password entry by password_id
        cur.execute("DELETE FROM passwords WHERE password_id = %s", (password_id,))
        mysql.connection.commit()

        if cur.rowcount == 0:
            print(f"No password found with id {password_id}")
            return jsonify({'success': False, 'message': 'Password not found'}), 404

        print(f"Password with id {password_id} deleted successfully")
        return jsonify({'success': True, 'message': 'Password deleted successfully'}), 200

    except Exception as e:
        mysql.connection.rollback()
        print(f"Error deleting password: {e}")
        return jsonify({'success': False, 'message': f'Failed to delete password: {str(e)}'}), 500
    finally:
        cur.close()

#NEW UPDATE - UPDATE FUNCTION
@app.route('/get_password/<int:password_id>', methods=['GET'])
def get_password(password_id):
    # Step 1: Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        # Step 2: Fetch the encrypted password and associated key from the database
        query = """
            SELECT passwords.password_id, passwords.key_id, passwords.passwords, passwords.site, passwords.login_name,
                   passwords.title, `keys`.key_name, `keys`.`key`
            FROM passwords
            JOIN `keys` ON passwords.key_id = `keys`.key_id
            JOIN accounts ON `keys`.id = accounts.Id
            WHERE passwords.password_id = %s AND accounts.Id = %s
        """
        cur.execute(query, (password_id, user_id))
        result = cur.fetchone()

        if not result:
            print("Password not found or unauthorized access")
            return jsonify({'success': False, 'message': 'Password not found or unauthorized access'}), 404

        # Step 3: Get the encrypted password and encryption key
        encrypted_password = result['passwords']
        key_id = result['key_id']
        key_name = result['key_name']
        encryption_key = result['key']

        print(f"Fetched encrypted password for password_id {password_id} with key_id {key_id} and key_name '{key_name}'")

        # Step 4: Attempt to decrypt with the key associated with the key_name
        decryption_success = False
        try:
            fernet = Fernet(encryption_key.encode())
            decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
            decryption_success = True
            print(f"Successfully decrypted password_id {password_id} with key_name '{key_name}'")
        except InvalidToken:
            print(f"Decryption failed with key_name '{key_name}' for password_id {password_id}")
            decryption_success = False

        # Step 5: If decryption failed, attempt with other keys from the database
        if not decryption_success:
            # Fetch all keys except the one already tried
            cur.execute("SELECT key_id, key_name, `key` FROM `keys` WHERE key_id != %s", (key_id,))
            all_keys = cur.fetchall()
            for key_record in all_keys:
                alternative_key_name = key_record['key_name']
                alternative_encryption_key = key_record['key']
                try:
                    fernet = Fernet(alternative_encryption_key.encode())
                    decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
                    decryption_success = True
                    print(f"Successfully decrypted password_id {password_id} with alternative key_name '{alternative_key_name}'")

                    # Re-encrypt with the correct key (original key associated with password)
                    correct_fernet = Fernet(encryption_key.encode())
                    new_encrypted_password = correct_fernet.encrypt(decrypted_password.encode()).decode()

                    # Update the password in the database with new encrypted password
                    update_query = """
                        UPDATE passwords
                        SET passwords = %s
                        WHERE password_id = %s
                    """
                    cur.execute(update_query, (new_encrypted_password, password_id))
                    mysql.connection.commit()
                    print(f"Re-encrypted and updated password_id {password_id} with key_name '{key_name}'")
                    break
                except InvalidToken:
                    print(f"Decryption failed with alternative key_name '{alternative_key_name}' for password_id {password_id}")
                    continue  # Try next key
            else:
                # If all keys fail
                print(f"Decryption failed for password_id {password_id} with all known keys")
                return jsonify({'success': False, 'message': 'Failed to decrypt the password'}), 500

        # Step 6: Prepare the response data
        response_data = {
            'password_id': password_id,
            'title': result['title'],
            'login_name': result['login_name'],
            'password': decrypted_password,  # Decrypted password
            'site': result['site'],
            'keys_name': key_name,
            'key_id': key_id,
            'url': result.get('url', '')
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f"Error retrieving password: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while retrieving the password'}), 500
    finally:
        cur.close()

#NEW UPDATE - UPDATE PASSWORD 2

@app.route('/update_password/<int:password_id>', methods=['POST'])
def update_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    key_id = request.form.get('key_id')
    site = request.form.get('site')
    login_name = request.form.get('login_name')
    password = request.form.get('passwords')
    title = request.form.get('title')

    # Check for required fields
    if not site or not login_name or not password:
        return "Required fields are missing", 400

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        # Fetch the encryption key based on key_id
        cur.execute("SELECT `key`, key_name FROM `keys` WHERE key_id = %s", (key_id,))
        key_record = cur.fetchone()

        if not key_record:
            print(f"Encryption key not found for key_id {key_id}")
            return jsonify({'message': 'Encryption key not found'}), 404

        encryption_key = key_record['key']
        key_name = key_record['key_name']
        print(f"Using encryption key for key_id {key_id}, key_name {key_name}: {encryption_key}")

        # Encrypt the password
        fernet = Fernet(encryption_key.encode())
        encrypted_password = fernet.encrypt(password.encode()).decode()
        print(f"Encrypted password for password_id {password_id}: {encrypted_password}")

        # Update only if the password belongs to the logged-in user
        query = """
            UPDATE passwords
            JOIN `keys` ON passwords.key_id = `keys`.key_id
            JOIN accounts ON `keys`.id = accounts.Id
            SET passwords.key_id = %s,
                passwords.site = %s,
                passwords.login_name = %s,
                passwords.passwords = %s,
                passwords.title = %s
            WHERE passwords.password_id = %s AND accounts.Id = %s
        """
        cur.execute(query, (key_id, site, login_name, encrypted_password, title, password_id, user_id))
        mysql.connection.commit()
        print(f"Password updated successfully for password_id {password_id}")
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error updating password: {str(e)}")
        return jsonify({'message': f'Error updating password: {str(e)}'}), 500
    finally:
        cur.close()

    return redirect(url_for('passwordvault'))

@app.route('/delete_key/<int:key_id>', methods=['DELETE'])
def delete_key(key_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        # Ensure the key belongs to the logged-in user
        cur.execute("SELECT key_id FROM `keys` WHERE key_id = %s AND id = %s", (key_id, user_id))
        key = cur.fetchone()

        if not key:
            return jsonify({'success': False, 'message': 'Key not found or unauthorized'}), 404

        # Delete all associated passwords
        cur.execute("DELETE FROM passwords WHERE key_id = %s", (key_id,))

        # Delete the key itself
        cur.execute("DELETE FROM `keys` WHERE key_id = %s", (key_id,))

        mysql.connection.commit()
        return jsonify({'success': True, 'message': 'Key and associated data deleted successfully'}), 200
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error deleting key with key_id={key_id}: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while deleting the key. Please try again.'}), 500
    finally:
        cur.close()
        
#SETTINGS ROUTE
#update email route
@app.route('/change_email', methods=['POST'])
def change_email():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401
<<<<<<< HEAD
    new_email = request.form['email']
    user_id = session['user_id']
    cur = mysql.connection.cursor()
    cur.execute("UPDATE accounts SET email = %s WHERE Id = %s", (new_email, user_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Email updated successfully'})
=======

    new_email = request.form['email']
    user_id = session['user_id']

    # Check if the new email is already in use
    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SELECT Id FROM accounts WHERE email = %s", (new_email,))
    existing_user = cur.fetchone()
    if existing_user:
        cur.close()
        return jsonify({'message': 'Email is already in use. Please use a different email address.'}), 400

    # Generate a new email verification token
    email_verification_token = str(uuid.uuid4())

    # Update the user's record with new_email and email_verification_token
    try:
        cur.execute("""
            UPDATE accounts
            SET new_email = %s, email_verification_token = %s
            WHERE Id = %s
        """, (new_email, email_verification_token, user_id))
        mysql.connection.commit()
    except Exception as e:
        print(f"Error updating email: {e}")
        return jsonify({'message': 'An error occurred while updating the email.'}), 500
    finally:
        cur.close()

    # Send a verification email to the new email address
    verification_link = url_for('verify_new_email', token=email_verification_token, _external=True)
    subject = "Email Verification for Email Change"
    message = f"""
    <p>Hi,</p>
    <p>You have requested to change your email address. Please click the link below to verify your new email address:</p>
    <p><a href="{verification_link}">{verification_link}</a></p>
    <p>If you did not request this change, please ignore this email.</p>
    <p>Best regards,<br>Kryptos***</p>
    """
    try:
        send_email(new_email, subject, message)
    except Exception as e:
        print(f"Error sending verification email: {e}")
        return jsonify({'message': 'Failed to send verification email. Please try again later.'}), 500

    return jsonify({'message': 'A verification email has been sent to your new email address. Please verify to complete the email change.'}), 200

#verify new email
@app.route('/verify_new_email/<token>', methods=['GET'])
def verify_new_email(token):
    cur = mysql.connection.cursor(DictCursor)
    try:
        # Find the user with the matching verification token
        cur.execute("SELECT Id, new_email FROM accounts WHERE email_verification_token = %s", (token,))
        user = cur.fetchone()

        if user:
            # Update the email and clear temporary fields
            cur.execute("""
                UPDATE accounts
                SET email = %s, new_email = NULL, email_verification_token = NULL
                WHERE Id = %s
            """, (user['new_email'], user['Id']))
            mysql.connection.commit()
            flash("Your email address has been updated successfully.", "success")
        else:
            flash("Invalid or expired verification link.", "error")
    except Exception as e:
        print(f"Error verifying new email: {e}")
        flash("An error occurred during email verification.", "error")
    finally:
        cur.close()
    return redirect(url_for('home'))
>>>>>>> repo-a/main

#Update Username Route
@app.route('/change_username', methods=['POST'])
def change_username():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401
<<<<<<< HEAD
    new_username = request.form['username']
    user_id = session['user_id']
    cur = mysql.connection.cursor()
    cur.execute("UPDATE accounts SET username = %s WHERE Id = %s", (new_username, user_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Username updated successfully'})
=======

    new_username = request.form['username']
    user_id = session['user_id']

    # Input validation (optional)
    if not new_username:
        return jsonify({'message': 'Username cannot be empty.'}), 400

    try:
        cur = mysql.connection.cursor(DictCursor)

        # Check if the new username already exists
        cur.execute("SELECT Id FROM accounts WHERE username = %s", (new_username,))
        existing_user = cur.fetchone()

        if existing_user:
            cur.close()
            return jsonify({'message': 'Username already exists. Please choose a different username.'}), 400

        # Update the username
        cur.execute("UPDATE accounts SET username = %s WHERE Id = %s", (new_username, user_id))
        mysql.connection.commit()
        cur.close()

        return jsonify({'message': 'Username updated successfully'}), 200

    except Exception as e:
        print(f"Error updating username: {e}")
        return jsonify({'message': 'An error occurred while updating the username.'}), 500
>>>>>>> repo-a/main

#Update master password route
@app.route('/change_master_password', methods=['POST'])
def change_master_password():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    current_master_password = request.form.get('current_master_password')
    new_master_password = request.form.get('new_master_password')
    confirm_master_password = request.form.get('confirm_master_password')

    if new_master_password != confirm_master_password:
        return jsonify({'message': 'New passwords do not match'}), 400

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Fetch the current master password hash from the database
        cur.execute("SELECT master_pass FROM accounts WHERE Id = %s", (user_id,))
        account = cur.fetchone()

        if not account or not ph.verify(account['master_pass'], current_master_password):
            return jsonify({'message': 'Current master password is incorrect'}), 403

        # Debug print: Current plaintext password (from user input)
        print(f"Current master password (plaintext): {current_master_password}")

        # Debug print: New plaintext password (from user input)
        print(f"New master password (plaintext): {new_master_password}")

        # Hash the new master password
        hashed_new_master_pass = ph.hash(new_master_password)

        # Update the master password in the database
        cur.execute("UPDATE accounts SET master_pass = %s WHERE Id = %s", (hashed_new_master_pass, user_id))
        mysql.connection.commit()

        return jsonify({'message': 'Master password updated successfully'})
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error updating master password: {e}")
        return jsonify({'message': 'Failed to update master password', 'error': str(e)}), 500
    finally:
        cur.close()
        
<<<<<<< HEAD
# Route to Reset Password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'otp_verified' not in session or 'security_password_verified' not in session or 'reset_email' not in session:
        flash("Unauthorized access. Please verify OTP and security password first.", "error")
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = ph.hash(new_password)
        email = session['reset_email']

        # Update the password and clear the OTP fields
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("""
            UPDATE accounts SET password = %s, reset_otp = NULL, reset_otp_expiry = NULL WHERE email = %s
        """, (hashed_password, email))
        mysql.connection.commit()
        cur.close()

        # Clear session variables
        session.pop('otp_verified', None)
        session.pop('security_password_verified', None)
        session.pop('reset_email', None)

        flash("Your password has been reset successfully.", "success")
        return redirect(url_for('login'))
    return render_template('reset_password.html')
=======
#update_security_question
@app.route('/update_security_question', methods=['POST'])
def update_security_question():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    current_master_password = request.form['current_master_password']
    new_security_question = request.form['new_security_question']
    new_security_answer = request.form['new_security_answer']

    # Input validation
    if not all([current_master_password, new_security_question, new_security_answer]):
        return jsonify({'message': 'All fields are required.'}), 400

    try:
        # Fetch the user's current master password hash
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT master_pass FROM accounts WHERE Id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()

        if not user:
            return jsonify({'message': 'User not found.'}), 404

        # Verify the current master password
        try:
            ph.verify(user['master_pass'], current_master_password)
        except exceptions.VerifyMismatchError:
            return jsonify({'message': 'Incorrect master password.'}), 403

        # Hash the new security answer
        hashed_security_answer = ph.hash(new_security_answer)

        # Update the security question and answer in the database
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE accounts
            SET security_question = %s, security_answer = %s
            WHERE Id = %s
        """, (new_security_question, hashed_security_answer, user_id))
        mysql.connection.commit()
        cur.close()

        return jsonify({'message': 'Security question and answer updated successfully.'}), 200

    except Exception as e:
        print(f"Error updating security question: {e}")
        return jsonify({'message': 'An error occurred while updating the security question.'}), 500
>>>>>>> repo-a/main

'''@app.route('/delete_password/<int:password_id>', methods=['DELETE'])
def delete_password(password_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor()

    # Delete only if the password belongs to the logged-in user
    query = """
        DELETE passwords FROM passwords
        JOIN keys ON passwords.key_id = keys.key_id
        WHERE passwords.password_id = %s AND keys.id = %s
    """
    cur.execute(query, (password_id, user_id))
    mysql.connection.commit()
    cur.close()

    return jsonify({'success': True})'''

@app.route('/logout')
def logout():
    session.clear()  # Clear the user session
    return redirect(url_for('login'))  # Redirect to home page or login page

if __name__ == "__main__":
    app.run(debug=True)
