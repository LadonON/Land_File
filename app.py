from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.utils import secure_filename
from datetime import datetime
from sqlalchemy import and_
from cryptography.fernet import Fernet
import re
import os

UPLOAD_FOLDER = "user_uploads"
ALLOWED_EXTENSIONS = {"zip", "tar", "7z", "rar", "gz", "tar.gz", "tar.bz2", "tar.xz", "tar.lz", "tar.lzo", "tar.lzma", "tar.lzop", "tar.zst"}
#Basic flask app setup
app = Flask(__name__)
app.config["SECRET_KEY"] = "wqdhouqwhdpoqdhwouncoup3297f"
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///users.db'
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
# Setup database
db = SQLAlchemy(app)
bycrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

#encryption setup
if not os.path.exists("secret.key"):
    key = Fernet.generate_key()
    with open("secret.key", "wb") as secret:
            secret.write(key)
else:
    with open("secret.key", "rb") as secret:
        key = secret.read()



#user SQL model
class User(UserMixin, db.Model):
    """Defines the User model for the database."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class File(db.Model): #File SQL model
    """Defines the File model for the database."""
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    owner_user = db.relationship("User", backref="files")
    filename = db.Column(db.String(255))
    filepath = db.Column(db.String(255))
    size = db.Column(db.Integer)
    time_uploaded = db.Column(db.DateTime, default=datetime.utcnow)
    is_encrypted = db.Column(db.Boolean, default=False)
    public = db.Column(db.Boolean, default=True)




@login_manager.user_loader
def load_user(user_id): #loading users 
    """Load user by ID."""
    return User.query.get(int(user_id)) #get users space in the user database


@app.route("/login", methods=["GET", "POST"])
def login():# login page
    """Handle user login."""
    if request.method == "POST":
        username = request.form.get("username") #get the inout and password from the form in login.html
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first() #find the user based off the username
        if user and bycrypt.check_password_hash(user.password, password): #check username and hashed password
            login_user(user)
            return redirect(url_for("home"))
        else:
            flash("Invalid username and password", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required #logout
def logout():
    """Handle user logout."""
    logout_user()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"]) #same thing as login
def register():
    """Handle user registration."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        hash_pw = bycrypt.generate_password_hash(password).decode("utf-8") #generate a hash for the password to be decrypted later
        user_new = User(username=username, password=hash_pw) #make a new user
        db.session.add(user_new) #add the user to the databse
        db.session.commit() #commit the changes
        flash("Accoutn created Please login")
        return redirect(url_for("login"))
    return render_template("register.html")


def allowed_filetypes(filename):
    """Check if the file type is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def user_folders(user_name):
    """Create user folder if it doesn't exist."""
    #create the user's file to store uploads
    folder = os.path.join(app.config["UPLOAD_FOLDER"], str(user_name))
    if not os.path.exists(folder):
        os.makedirs(folder)


def list_files(dir):
    """List all files in a directory."""
    #list all files in the user's directory
    found_files = []
    for root, _, files in os.walk(dir):
        for file in files:
            path = os.path.join(root, file)
            found_files.append(path)
    return found_files


def list_folders(dir):
    """List all folders in a directory."""
    #list all folders in the user's directory
    found_folders = []
    for root, dirs, _ in os.walk(dir):
        for folder in dirs:
            path = os.path.relpath(os.path.join(root, folder), dir)
            found_folders.append(path)
    return found_folders

@app.route("/manage/<int:file_id>")
@login_required
def manage(file_id):
    file_record = File.query.get_or_404(file_id)
    if file_record.owner != current_user.id:
        flash("You do not have permisson to acsess this file", "danger")
        return redirect(url_for("home"))
    full = os.path.join(app.config["UPLOAD_FOLDER"], *file_record.filepath.split("/"))
    return render_template("manage.html", file=file_record, file_id=file_id, path=full)

@app.route("/manage/<int:file_id>/make_public")
def make_public(file_id):
    file_record = File.query.get_or_404(file_id)
    if file_record.owner != current_user.id:
        flash("You do not have acsess to use this file", "danger")
        return redirect(url_for("home"))
    file_record.public = True
    db.session.commit()
    flash("File is now public", "success")
    return redirect(url_for("manage", file_id=file_id))

@app.route("/manage/<int:file_id>/make_private")
def make_private(file_id):
    file_record = File.query.get_or_404(file_id)
    if file_record.owner != current_user.id:
        flash("You do not have acsess to use this file", "danger")
        return redirect(url_for("home"))
    file_record.public = False
    db.session.commit()
    flash("File is now private", "success")
    return redirect(url_for("manage", file_id=file_id))

@app.route("/public")
def public_files():
    public_files = File.query.filter(
    and_(
        File.public == True,
        File.is_encrypted == False
        )
    ).all()
    return render_template("public.html", files=public_files)

@app.route("/")
def lander():
    return render_template("lander.html")
        
@app.route("/manage/<int:file_id>/encrypt")
def encrypt_file(file_id):
    file_record = File.query.get_or_404(file_id)
    if file_record.owner != current_user.id:
        flash("You do not have acsess to use this file", "danger")
        return redirect(url_for("home"))
    input_file = os.path.join(app.config["UPLOAD_FOLDER"], *file_record.filepath.split("/"))
    with open("secret.key", "rb") as f:
        key = f.read()
    fernet = Fernet(key)
    try:
        if not file_record.is_encrypted:
            with open(input_file, "rb") as f:
                data = f.read()
            encrypt = fernet.encrypt(data)
            with open(input_file, "wb") as f:
                f.write(encrypt)
            file_record.is_encrypted = True
            db.session.commit()
            flash("Sucsesfully encrypted", "success")
        else:
            flash("file is already encrypted", "error")
            return redirect(url_for("manage", file_id=file_id))
    except Exception as e:
        flash(f"Encryption failed! {e}", "danger")
    return redirect(url_for("manage", file_id=file_id))


@app.route("/manage/<int:file_id>/decrypt")
def decrypt_file(file_id):
    file_record = File.query.get_or_404(file_id)
    
    if file_record.owner != current_user.id:
        flash("You do not have acsess to use this file", "danger")
        return redirect(url_for("home"))
    input_file = os.path.join(app.config["UPLOAD_FOLDER"], *file_record.filepath.split("/")) 
    with open("secret.key", "rb") as f:
        key = f.read()
    fernet = Fernet(key)
    try:
        if file_record.is_encrypted:
            with open(input_file, "rb") as f:
                data = f.read()
            decrypt = fernet.decrypt(data)
            with open(input_file, "wb") as f:
                f.write(decrypt)
            file_record.is_encrypted = False
            db.session.commit()
            flash("Suscsfully decrpyted", "success")
        else:
            flash("File is not encrypted", "error")
            return redirect(url_for("manage", file_id=file_id))
    except Exception as e:
        flash(f"decryption failed! {e}", "danger")
    return redirect(url_for("manage", file_id=file_id))


@app.route("/download/<int:file_id>") #download files
@login_required
def download(file_id):
    """Handle file download."""
    file_record = File.query.get_or_404(file_id)
    public = file_record.public
    full = os.path.join(app.config["UPLOAD_FOLDER"], *file_record.filepath.split("/"))
    if not public:
        if file_record.owner != current_user.id:
            flash("You do not have permission to access this file", "danger")
            return redirect(url_for("home"))
        if file_record.is_encrypted:
            flash("Cannot download encrypte files", "error")
        else:
            return send_file(full, as_attachment=True)
    else:
        return send_file(full, as_attachment=True)





@app.route("/create_folder", methods=["POST"])
@login_required
def create_folder():
    """Create a new folder for the user."""
    folder_name = request.form.get("folder_name")
    if not folder_name:
        flash("Unnamed folders are not permitted")
        return redirect(url_for("home"))
    folder_name = secure_filename(folder_name)
    user_direcctory = os.path.join(app.config["UPLOAD_FOLDER"], current_user.username)
    new_path = os.path.join(user_direcctory, folder_name)
    try:
        os.makedirs(new_path)
        flash(f"Folder {folder_name} has been created!", "success")
    except FileExistsError:
        flash(f"Folder {folder_name} already exists!", "danger")
    return redirect(url_for("home"))



@app.route("/folder/<path:foldername>/upload", methods=["GET", "POST"])
@login_required
def folder_upload(foldername):
    """Upload a file to a specific folder."""
    user_directory = os.path.join(app.config["UPLOAD_FOLDER"], current_user.username)
    target_folder = os.path.join(user_directory, foldername)
    if not os.path.exists(target_folder):
        flash("Folder does not exist", "danger")
        return redirect(url_for("home"))
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part", "danger")
            return redirect(request.url)
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file", "danger")
            return redirect(request.url)
        if file and allowed_filetypes(file.filename):
            filename = secure_filename(file.filename)
            path = os.path.join(target_folder, filename)
            file.save(path)
            rel_path = os.path.relpath(path, app.config["UPLOAD_FOLDER"]).replace("\\", "/")
            upload_file = File(
                owner=current_user.id,
                filename=filename,
                filepath=rel_path,
                size=os.path.getsize(path)
            )
            db.session.add(upload_file)
            db.session.commit()
            flash("File uploaded successfully", "success")
        else:
            flash("File type not allowed", "danger")
    return redirect(url_for("view_folder", foldername=foldername))




@app.route("/folder/<path:foldername>")
@login_required
def view_folder(foldername):
    """View contents of a specific folder."""
    user_directory = os.path.join(app.config["UPLOAD_FOLDER"], current_user.username)
    target_folder = os.path.join(user_directory, foldername)
    if not os.path.exists(target_folder):
        flash("Folder does not exist", "danger")
        return redirect(url_for("home"))
    rel_t = f"{current_user.username}/{foldername}"
    files_in_folder = File.query.filter(
    File.owner == current_user.id,
    File.filepath.like(f"{rel_t}/%")
    ).all()
    return render_template("folder.html", files=files_in_folder, foldername=foldername)



@app.route("/home")
@login_required
def home():
    """Render the home page with user's files and folders."""
    usr_dir = os.path.join(app.config["UPLOAD_FOLDER"], current_user.username)
    user_folders(current_user.username)
    usr_files = File.query.filter_by(owner=current_user.id).all()
    folders = list_folders(usr_dir)
    return render_template("home.html", files=usr_files, folders=folders)




@app.route("/delete/<int:file_id>", methods=["GET", "POST"])
@login_required
def delete(file_id):
    file_record = File.query.get_or_404(file_id)
    if file_record.owner != current_user.id:
        flash("You do not have acses to this file", "danger")
        return redirect(url_for("home"))
    full_path = os.path.join(app.config["UPLOAD_FOLDER"], *file_record.filepath.split("/"))
    if os.path.exists(full_path):
        os.remove(full_path)

    db.session.delete(file_record)
    db.session.commit()
    flash("file deleted!", "success")
    return redirect(url_for("home"))




@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    """Handle file upload."""
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part", "danger")
            return redirect(request.url)
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file", "danger")
            return redirect(request.url)
        if file and allowed_filetypes(file.filename):
            user_folders(current_user.username)
            filename = secure_filename(file.filename)
            upload_file = File(
                owner=current_user.id,
                filename=filename,
                filepath=f"{app.config['UPLOAD_FOLDER']}/{current_user.username}/{filename}",
                size=os.path.getsize(f"{app.config['UPLOAD_FOLDER']}/{current_user.username}/{filename}")
            )
            db.session.add(upload_file)
            db.session.commit()
            flash("File uploaded successfully", "success")
        else:
            flash("File type not allowed", "danger")
    return render_template("upload.html")


if __name__ == "__main__":
    app.run(debug=True)

