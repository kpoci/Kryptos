import os
import MySQLdb
from MySQLdb.cursors import DictCursor
from flask import Flask, jsonify, render_template, session, request, redirect, url_for
from flask_mysqldb import MySQL
from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken


app = Flask(__name__)
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = ""
app.config['MYSQL_DB'] = "users"
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

mysql = MySQL(app)

# PasswordHasher instance with custom parameters
ph = PasswordHasher(memory_cost=102400, time_cost=1, parallelism=8)

@app.route("/test", methods=["POST", "GET"])
def test():
    return render_template("test.html")


@app.route("/home", methods=["POST", "GET"])
def home():

    if 'user_id' in session:
        user_id = session['user_id']
        # Assuming you have a way to get the username using the user_id
        cur = mysql.connection.cursor()
        cur.execute("SELECT username FROM accounts WHERE Id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        if user:
            username = user[0]
        else:
            # Handle case where no user is found
            username = "Unknown"
        return render_template("home.html", username=username)
    else:
        # Handle the case where there is no user_id in session
        return redirect(url_for('login')) 

@app.route("/", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form['username']
        pwd = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT Id, password FROM accounts WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user and ph.verify(user[1], pwd):
            session['user_id'] = user[0]  # Storing the numerical Id from the accounts table
            return redirect(url_for('home'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == 'POST':
        username = request.form['username']
        pwd = request.form['password']
        email = request.form['email']
        master_pass = request.form['master_pass']
        
        hashed_password = ph.hash(pwd)
        hashed_master_pass = ph.hash(master_pass)
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO accounts (username, password, email, master_pass) VALUES (%s, %s, %s, %s)", (username, hashed_password, email, hashed_master_pass))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('login'))
    
    return render_template('register.html')

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
        cur.execute("SELECT password_id, site, login_name, passwords FROM passwords WHERE key_id = %s", (key_id,))
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
                    'login_name': password['login_name'],
                    'passwords': decrypted_password  # Add decrypted password
                })
            except InvalidToken:
                # Log error if decryption fails
                print(f"Decryption failed for password_id {password['password_id']} with key_id {key_id}")
                decrypted_passwords.append({
                    'id': password['password_id'],
                    'site': password['site'],
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
    cur.execute("SELECT * FROM 'keys' WHERE user_id = %s", (user_id,))
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

#NEW UPDATE - DELETE FUNCTION
@app.route('/delete_password/<int:password_id>', methods=['DELETE'])
def delete_password(password_id):
    # Remove the user_id session check for testing
    cur = mysql.connection.cursor()

    try:
        # Attempt to delete the password entry by password_id only
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
        return jsonify({'success': False, 'message': 'Failed to delete password'}), 500
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