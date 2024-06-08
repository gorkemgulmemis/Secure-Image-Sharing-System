from flask import Flask, request, jsonify, render_template_string, redirect, send_file, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import utils

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Assuming public and private keys for the server are pre-generated and stored in a file
SERVER_KEY_FILE = 'server_key.pem'

if not os.path.exists(SERVER_KEY_FILE):
    _, server_private_key = utils.generate_key_pair(SERVER_KEY_FILE)
else:
    server_private_key = utils.load_key(SERVER_KEY_FILE)

# Directory to store uploaded images and user keys
UPLOAD_FOLDER = 'uploaded_images'
KEYS_FOLDER = 'keys'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(KEYS_FOLDER):
    os.makedirs(KEYS_FOLDER)

users = {}  # To store user data: {username: {'password': ..., 'public_key': ..., 'private_key': ..., 'mac_key': ...}}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            flash('Username already exists')
            return redirect(url_for('register'))
        # Generate key pair and MAC key for user and store them in files
        key_filename = os.path.join(KEYS_FOLDER, f"{username}_key.pem")
        public_key, private_key = utils.generate_key_pair(key_filename)
        mac_key = utils.generate_mac_key()
        users[username] = {'password': password, 'public_key': public_key, 'private_key': private_key, 'mac_key': mac_key}
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template_string('''
        <h1>Register</h1>
        <form method="post" action="/register">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Register">
        </form>
        <a href="{{ url_for('login') }}">Already have an account? Login here.</a>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            user = User(username)
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
        return redirect(url_for('login'))
    return render_template_string('''
        <h1>Login</h1>
        <form method="post" action="/login">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        <a href="{{ url_for('register') }}">Don't have an account? Register here.</a>
    ''')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string('''
        <h1>Welcome {{ current_user.id }}</h1>
        <h2>Upload Image</h2>
        <form method="post" action="/upload" enctype="multipart/form-data">
            Select image: <input type="file" name="image"><br>
            Intended Users: <input type="text" name="intended_users"><br>
            <input type="submit" value="Upload Image">
        </form>
        <h2>Download Image</h2>
        <form method="post" action="/download">
            Image Name: <input type="text" name="image_name"><br>
            <input type="submit" value="Download Image">
        </form>
        <a href="{{ url_for('logout') }}">Logout</a>
    ''')

@app.route('/upload', methods=['POST'])
@login_required
def upload_image():
    username = current_user.id
    image = request.files['image']
    intended_users = request.form['intended_users'].split(',')  # List of intended users
    if image:
        filepath = os.path.join(UPLOAD_FOLDER, image.filename)
        image.save(filepath)
        
        # Encrypt the image
        aes_key = utils.generate_aes_key()
        encrypted_image, iv = utils.encrypt_image(filepath, aes_key)
        digital_signature = utils.sign_data(encrypted_image, users[username]['private_key'])

        # Encrypt AES key with intended users' public keys
        encrypted_aes_keys = {}
        for user in intended_users:
            if user in users:
                encrypted_aes_key = utils.encrypt_with_public_key(aes_key, users[user]['public_key'])
                encrypted_aes_keys[user] = encrypted_aes_key.hex()

        # Save encrypted image to a new file
        encrypted_file_path = filepath + '.enc'
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_image)
        
        # Store metadata (for simplicity, just store locally, ideally in a database)
        if 'images' not in users[username]:
            users[username]['images'] = {}
        
        users[username]['images'][image.filename] = {
            'file_path': encrypted_file_path,
            'digital_signature': digital_signature.hex(),
            'iv': iv.hex(),
            'aes_keys': encrypted_aes_keys  # Encrypted AES keys for intended users
        }

        # Print proof of encryption
        print(f"Image {image.filename} has been encrypted.")
        print(f"AES Key: {aes_key.hex()}")
        print(f"IV: {iv.hex()}")
        print(f"Digital Signature: {digital_signature.hex()}")
        print(f"Encrypted AES keys for intended users: {encrypted_aes_keys}")

        return jsonify({'message': f'Image {image.filename} encrypted and uploaded successfully'})
    return jsonify({'error': 'No image provided'}), 400

@app.route('/download', methods=['POST'])
@login_required
def download_image():
    username = current_user.id
    image_name = request.form['image_name']
    
    if username not in users:
        return jsonify({'error': 'User not registered'}), 400

    found_image = None
    for user in users:
        if 'images' in users[user] and image_name in users[user]['images']:
            found_image = users[user]['images'][image_name]
            break

    if not found_image:
        return jsonify({'error': 'Image not found'}), 404

    encrypted_image_path = found_image['file_path']
    if username not in found_image['aes_keys']:
        return jsonify({'error': 'You do not have permission to access this image'}), 403

    encrypted_aes_key = bytes.fromhex(found_image['aes_keys'][username])
    aes_key = utils.decrypt_with_private_key(encrypted_aes_key, users[username]['private_key'])
    iv = bytes.fromhex(found_image['iv'])
    
    with open(encrypted_image_path, 'rb') as f:
        encrypted_image = f.read()

    decrypted_image = utils.decrypt_image(encrypted_image, aes_key, iv)
    decrypted_image_path = os.path.join(UPLOAD_FOLDER, image_name + '_decrypted.jpg')
    
    with open(decrypted_image_path, 'wb') as f:
        f.write(decrypted_image)

    # Print proof of decryption
    print(f"Image {image_name} has been decrypted.")
    print(f"AES Key: {aes_key.hex()}")
    print(f"IV: {iv.hex()}")

    return send_file(decrypted_image_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
