from flask import Flask, render_template, request, redirect, session, url_for,flash
import db_collection as dbc
from db_config import get_database
from bson.objectid import ObjectId
import bcrypt


app = Flask(__name__)


app.secret_key = 'your_secret_key'

database       = get_database()

collection     = database[dbc.USER_COLLECTION]


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        
        username = request.form['username']
        email    = request.form['email']
        password = request.form['password']
        
        existing_user = collection.find_one({"email": email})
        
        if existing_user:
            flash('Username already exists. Please choose another one.', 'danger' )
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        users = {
            'username': username,
            'email'   : email,
            'password': hashed_password
        }
        
        try:
            result = collection.insert_one(users)
            if result.inserted_id:
                flash('Registration successful!','success')
            else:
                flash('Registration failed, please try again.', 'danger')
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')    

        return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/', methods=['POST','GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')    
        email    = request.form.get('email')
        password = request.form.get('password')
        
        if 'username' not in request.form or 'email' not in request.form or 'password' not in request.form:
            flash('Username or password field is missing.', 'error')
            return redirect(url_for('login'))
        
        user = collection.find_one({"email": email})
        if user:
            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                session['email']    = user['email']
                session['username'] = username
                return redirect(url_for('dashboard'))
            
        flash('Invalid credentials, please try again.', 'error')
        return redirect(url_for('login'))
    
    return render_template('login.html')

    
@app.route("/dashboard", methods=['GET'])
def dashboard():
    return render_template('dashboard.html')
    

@app.route('/logout', methods=['GET','POST'])
def logout():
    
    session.pop('email', None)
    session.pop('logged_in', None)
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)

