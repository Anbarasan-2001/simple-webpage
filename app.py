from flask import Flask, render_template, request, redirect, session, url_for
import db_collection as dbc
from db_config import get_database
from bson.objectid import ObjectId
import bcrypt


app = Flask(__name__)

# Secret key for session management (set to a random value)
app.secret_key = 'your_secret_key'

database = get_database()

collection   = database[dbc.USER_COLLECTION]


@app.route('/')
def home():
    # Check if user is logged in by checking session
    if 'email' in session:
        return f'Logged in as {session["email"]}'
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register():
    # Get form data
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    
    # Check if user already exists
    existing_user = collection.find_one({"email": email})
    if existing_user:
        return 'User with this email already exists!'
    
    # Hash the password before storing it
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert new user data into MongoDB
    collection.insert_one({
        'username': username,
        'email': email,
        'password': hashed_password
    })

    # Store user info in session after registration
    session['email'] = email

    return redirect(url_for('home'))


@app.route('/login', methods=['POST'])
def login():
    # Get form data
    email = request.form['email']
    password = request.form['password']
    
    # Check if user exists in the database
    user = collection.find_one({"email": email})
    if user:
        # Check if the provided password matches the hashed password
        if bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['email'] = user['email']  # Store the user's email in session
            return redirect(url_for('home'))
        else:
            return 'Invalid email/password combination'
    else:
        return 'User not found'
    

@app.route('/logout')
def logout():
    # Clear the session data
    session.pop('email', None)
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)

