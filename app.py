# app.py
import os
import sqlite3
from flask import Flask, render_template, request, url_for, flash, redirect, session, g
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the Flask application
app = Flask(__name__, instance_relative_config=True) # instance_relative_config=True to load config from instance folder

# Load configuration from config.py in the instance folder
app.config.from_mapping(
    SECRET_KEY='dev', # Default secret key for development, override in instance/config.py
    DATABASE=os.path.join(app.instance_path, 'database.db'),
)

# Ensure the instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# Load the instance config if it exists
app.config.from_pyfile('config.py', silent=True)

# --- Database Helper Functions ---

def get_db():
    """
    Establishes a connection to the database or returns the existing one.
    The 'g' object is used to store the database connection for the current request.
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        # Set row_factory to sqlite3.Row to allow accessing columns by name
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """
    Closes the database connection at the end of the request.
    """
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """
    Initializes the database by executing the schema.sql script.
    This function should be called once when setting up the application.
    """
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
    print("Database initialized.")

# Command-line command to initialize the database
@app.cli.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    print('Initialized the database.')

# --- User Authentication ---

@app.before_request
def load_logged_in_user():
    """
    Loads the logged-in user's ID from the session before each request.
    Stores it in g.user for easy access in views.
    """
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        db = get_db()
        g.user = db.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()

@app.route('/register', methods=('GET', 'POST'))
def register():
    """
    Handles user registration.
    - GET: Displays the registration form.
    - POST: Processes the form submission, creates a new user, and redirects to login.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = f"User {username} is already registered."

        if error is None:
            # Hash the password before storing it for security
            hashed_password = generate_password_hash(password)
            db.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, hashed_password)
            )
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        
        flash(error, 'danger')

    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    """
    Handles user login.
    - GET: Displays the login form.
    - POST: Authenticates the user and sets the session.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            # Store user ID in session to keep user logged in
            session.clear()
            session['user_id'] = user['id']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        
        flash(error, 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """
    Logs out the current user by clearing the session.
    """
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# --- Book Management ---

@app.route('/add_book', methods=('GET', 'POST'))
def add_book():
    """
    Allows logged-in users to add new books to the database.
    - GET: Displays the add book form.
    - POST: Processes the form submission and adds the book.
    """
    # Ensure user is logged in
    if g.user is None:
        flash('You need to be logged in to add a book.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        genre = request.form['genre']
        error = None

        if not title:
            error = 'Title is required.'
        elif not author:
            error = 'Author is required.'

        if error is None:
            db = get_db()
            db.execute(
                'INSERT INTO books (title, author, genre, user_id) VALUES (?, ?, ?, ?)',
                (title, author, genre, g.user['id'])
            )
            db.commit()
            flash('Book added successfully!', 'success')
            return redirect(url_for('books'))
        
        flash(error, 'danger')

    return render_template('add_book.html')

@app.route('/books')
def books():
    """
    Displays a list of books added by the currently logged-in user.
    Redirects to login if no user is logged in.
    """
    if g.user is None:
        flash('You need to be logged in to view your books.', 'warning')
        return redirect(url_for('login'))

    db = get_db()
    # Modify the SQL query to filter by the logged-in user's ID
    books = db.execute(
        'SELECT b.id, b.title, b.author, b.genre, u.username '
        'FROM books b JOIN users u ON b.user_id = u.id '
        'WHERE b.user_id = ? ' # Add this WHERE clause
        'ORDER BY b.title ASC',
        (g.user['id'],) # Pass the user's ID as a parameter
    ).fetchall()
    return render_template('books.html', books=books)

# --- Main Routes ---

@app.route('/')
def index():
    """
    Homepage of the application.
    """
    return render_template('index.html')

if __name__ == '__main__':
    # You can initialize the database using 'flask init-db' command
    # For simple running, you can also uncomment the line below,
    # but it's better to use the Flask CLI command for setup.
    # if not os.path.exists(app.config['DATABASE']):
    #     with app.app_context():
    #         init_db()
    app.run(debug=True) # Run the Flask app in debug mode
