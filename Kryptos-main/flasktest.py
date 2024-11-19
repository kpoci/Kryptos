import os
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import argon2
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors
from argon2 import PasswordHasher
from MySQLdb.cursors import DictCursor
from cryptography.fernet import Fernet, InvalidToken
import re
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'users'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  # Ensure DictCursor is set
mysql = MySQL(app)

# PasswordHasher instance
ph = PasswordHasher(memory_cost=102400, time_cost=1, parallelism=8)

# Helper function to send email
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

# Route for Initial Page - Redirect to Login
@app.route('/')
def index():
    return redirect(url_for('login'))

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

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        master_pass = request.form['master_pass']
        security_password = request.form['security_password']

        # Check if the username or email already exists
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM accounts WHERE username = %s OR email = %s", (username, email))
        account = cur.fetchone()

        if account:
            if account['username'] == username and account['email'] == email:
                flash("Username and email already exist. Please choose a different username and email.", "error")
            elif account['username'] == username:
                flash("Username already exists. Please choose a different username.", "error")
            elif account['email'] == email:
                flash("An account with this email already exists.", "error")
            return redirect(url_for('register'))

        # Validate password strength for all passwords
        invalid_passwords = []
        if not is_password_strong(password):
            invalid_passwords.append("Login Password")
        if not is_password_strong(master_pass):
            invalid_passwords.append("Master Password")
        if not is_password_strong(security_password):
            invalid_passwords.append("Security Password")

        if invalid_passwords:
            flash(f"The following password(s) are not strong enough: {', '.join(invalid_passwords)}. Each must be at least 8 characters long and include uppercase letters, lowercase letters, numbers, and special characters. Spaces are allowed.", "error")
            return redirect(url_for('register'))

        # Hash the passwords
        hashed_password = ph.hash(password)
        hashed_master_pass = ph.hash(master_pass)
        hashed_security_password = ph.hash(security_password)

        # Insert the new user into the database
        cur.execute(
            "INSERT INTO accounts (username, email, password, master_pass, security_pass) VALUES (%s, %s, %s, %s, %s)",
            (username, email, hashed_password, hashed_master_pass, hashed_security_password)
        )
        mysql.connection.commit()
        cur.close()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


#settings
@app.route('/settings')
def settings():
    return render_template('settings.html')

# Login Route with Enhanced Error Handling and Account Lockout Notification
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            # Fetch user from the database
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM accounts WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()

            if user:
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
                    ph.verify(user['password'], password)
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
                    cur.execute("SELECT failed_attempts FROM accounts WHERE Id = %s", (user['Id'],))
                    updated_user = cur.fetchone()
                    failed_attempts = updated_user['failed_attempts']
                    cur.close()

                    if failed_attempts >= 5:
                        lockout_until = datetime.now() + timedelta(minutes=1440)  # Lock account for 1 day
                        cur = mysql.connection.cursor()
                        cur.execute("UPDATE accounts SET lockout_until = %s WHERE Id = %s", (lockout_until, user['Id']))
                        mysql.connection.commit()
                        cur.close()

                        # Send account lockout email notification
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

                        flash("Account locked due to multiple failed login attempts. Please check your email for more information.", "error")
                    else:
                        remaining_attempts = 5 - failed_attempts
                        flash(f"Incorrect password. {remaining_attempts} attempt(s) remaining.", "error")
                    return redirect(url_for('login'))
                except Exception as e:
                    print(f"Error during password verification: {e}")
                    flash("An error occurred during login. Please try again.", "error")
                    return redirect(url_for('login'))
            else:
                # Username not found
                flash("Username not found. Please check and try again.", "error")
                return redirect(url_for('login'))
        except Exception as e:
            print(f"Database error: {e}")
            flash("An error occurred during login. Please try again.", "error")
            return redirect(url_for('login'))

    return render_template('login.html')



# OTP Verification Route
@app.route('/otp_verification', methods=['GET', 'POST'])
def otp_verification():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['temp_user_id']

    # Fetch the user's email address
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT email FROM accounts WHERE Id = %s", (user_id,))
    user_data = cur.fetchone()
    cur.close()

    if not user_data:
        flash("User not found. Please log in again.", "error")
        return redirect(url_for('login'))

    # Mask the email for privacy
    def mask_email(email):
        try:
            local_part, domain_part = email.split('@')
            if len(local_part) > 2:
                local_part = local_part[0] + '***' + local_part[-1]
            else:
                local_part = local_part[0] + '*'
            return f"{local_part}@{domain_part}"
        except Exception:
            return email

    email = mask_email(user_data['email'])

    if request.method == 'POST':
        user_otp = request.form['otp']

        # Fetch OTP and expiry from the database
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT otp, otp_expiry FROM accounts WHERE Id = %s", (user_id,))
        otp_data = cur.fetchone()
        cur.close()

        # Check if OTP is valid and not expired
        if otp_data and str(otp_data['otp']) == user_otp and datetime.now() < otp_data['otp_expiry']:
            # Set user session and clear temporary session
            session['user_id'] = user_id
            session.pop('temp_user_id', None)

            # Clear OTP from database after successful verification
            cur = mysql.connection.cursor()
            cur.execute("UPDATE accounts SET otp = NULL, otp_expiry = NULL WHERE Id = %s", (user_id,))
            mysql.connection.commit()
            cur.close()

            flash("Logged in successfully!", "success")
            return redirect(url_for('home'))  # Redirect to home page
        else:
            flash("Invalid or expired OTP. Please try again.", "error")
            return redirect(url_for('otp_verification'))

    return render_template('otp_verification.html', email=email)



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

# Test Route
@app.route('/test')
def test():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('test.html')



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

# Route to Verify Security Password
@app.route('/verify_security_password', methods=['GET', 'POST'])
def verify_security_password():
    if 'otp_verified' not in session or 'reset_email' not in session:
        flash("Unauthorized access. Please verify OTP first.", "error")
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        security_password_input = request.form['security_password']
        email = session['reset_email']

        # Fetch the stored security password hash from the database
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT security_pass FROM accounts WHERE email = %s", (email,))
        account = cur.fetchone()
        cur.close()

        if account and ph.verify(account['security_pass'], security_password_input):
            # Security password is correct
            session['security_password_verified'] = True
            flash("Security password verified. You can now reset your password.", "success")
            return redirect(url_for('reset_password'))
        else:
            flash("Incorrect security password. Please try again.", "error")
            return redirect(url_for('verify_security_password'))
    return render_template('verify_security_password.html')


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

# Resend OTP Route
@app.route('/resend_otp')
def resend_otp():
    if 'temp_user_id' not in session:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for('login'))

    user_id = session['temp_user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Fetch user email
        cur.execute("SELECT email FROM accounts WHERE Id = %s", (user_id,))
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


#update email route
@app.route('/change_email', methods=['POST'])
def change_email():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401
    new_email = request.form['email']
    user_id = session['user_id']
    cur = mysql.connection.cursor()
    cur.execute("UPDATE accounts SET email = %s WHERE Id = %s", (new_email, user_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Email updated successfully'})

#Update Username Route
@app.route('/change_username', methods=['POST'])
def change_username():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401
    new_username = request.form['username']
    user_id = session['user_id']
    cur = mysql.connection.cursor()
    cur.execute("UPDATE accounts SET username = %s WHERE Id = %s", (new_username, user_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Username updated successfully'})

#update password route
@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401
    new_password = request.form['password']
    hashed_password = ph.hash(new_password)
    user_id = session['user_id']
    cur = mysql.connection.cursor()
    cur.execute("UPDATE accounts SET password = %s WHERE Id = %s", (hashed_password, user_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Password updated successfully'})

# Change Master Password Route
@app.route('/change_master_password', methods=['POST'])
def change_master_password():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    current_master_password = request.form.get('current_master_password')
    new_master_password = request.form.get('new_master_password')

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Fetch the current master password hash from the database
        cur.execute("SELECT master_pass FROM accounts WHERE Id = %s", (user_id,))
        account = cur.fetchone()

        if not account or not ph.verify(account['master_pass'], current_master_password):
            return jsonify({'message': 'Current master password is incorrect'}), 403

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

# Set Idle Logout Time Route
@app.route('/set_idle_logout_time', methods=['POST'])
def set_idle_logout_time():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    idle_time = request.form.get('idle_time')
    user_id = session['user_id']

    try:
        # Store the idle time in the session
        session['idle_logout_time'] = int(idle_time)  # Store as integer (minutes)

        return jsonify({'message': 'Idle logout time updated successfully'})
    except Exception as e:
        print(f"Error setting idle logout time: {e}")
        return jsonify({'message': 'Failed to update idle logout time', 'error': str(e)}), 500
    
# Update Password Generator Settings Route
@app.route('/update_password_generator_settings', methods=['POST'])
def update_password_generator_settings():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    password_length = request.form.get('password_length')
    include_uppercase = request.form.get('include_uppercase') == 'true'
    include_lowercase = request.form.get('include_lowercase') == 'true'
    include_numbers = request.form.get('include_numbers') == 'true'
    include_symbols = request.form.get('include_symbols') == 'true'

    try:
        # Convert boolean values to integers for storage
        include_uppercase = int(include_uppercase)
        include_lowercase = int(include_lowercase)
        include_numbers = int(include_numbers)
        include_symbols = int(include_symbols)

        # Store these settings in the database
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # Check if the user already has settings saved
        cur.execute("SELECT * FROM `password_generator_settings` WHERE `user_id` = %s", (user_id,))
        existing_settings = cur.fetchone()

        if existing_settings:
            # Update existing settings
            cur.execute("""
                UPDATE `password_generator_settings`
                SET `password_length` = %s, `include_uppercase` = %s, `include_lowercase` = %s, `include_numbers` = %s, `include_symbols` = %s
                WHERE `user_id` = %s
            """, (password_length, include_uppercase, include_lowercase, include_numbers, include_symbols, user_id))
        else:
            # Insert new settings
            cur.execute("""
                INSERT INTO `password_generator_settings` (`user_id`, `password_length`, `include_uppercase`, `include_lowercase`, `include_numbers`, `include_symbols`)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, password_length, include_uppercase, include_lowercase, include_numbers, include_symbols))

        mysql.connection.commit()
        cur.close()

        return jsonify({'message': 'Password generator settings updated successfully'})
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error updating password generator settings: {e}")
        return jsonify({'message': 'Failed to update password generator settings', 'error': str(e)}), 500


@app.route('/logout')
def logout():
    session.clear()  # Clear the user session
    return redirect(url_for('login'))  # Redirect to home page or login page

if __name__ == "__main__":
    app.run(debug=True)