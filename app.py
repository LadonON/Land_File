"""
Landon Stone
12/9/2025

This week while working on my project, I learned a lot about how websites work behind the scenes
It was hard for me to learn how to incorporate a sqlite database
My friend Ricardo helped me this week on styling the html pages
One word that would explain how I am feeling about this project would be "exhausted"
I would add and admin page and ranks
"""
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
app.add_url_rule("/favicon.ico", endpoint="favicon", redirect_to="/static/favicon.ico")
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
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class File(db.Model): #File SQL model
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
    """
    args:
        user_id:
        user's id from the database
    returns:
        User in format <User #>
    """
    return User.query.get(int(user_id)) #get users space in the user database


@app.route("/login", methods=["GET", "POST"])
def login():# login page
    """
       args:
       returns:
           Html page for login visulizaytion
       """
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
    """
       args:
       returns:
           A redirect to the login page
       """
    logout_user()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"]) #same thing as login
def register():
    """
       args:

       returns:
           Html page for register visulization
       """
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

def debug_console():
    index = 0
    folders = []
    print("------DEBUG-------\n")
    while index < len(list_folders("user_uploads")):
        folders.append(list_folders("user_uploads")[index])
        folders.insert(index, list_folders("user_uploads")[index])
        print(list_folders("user_uploads")[index])
        index += 1
    print("------------------\n")



def allowed_filetypes(filename):
    """
          args:
            filename:
                the full filename of an uploaded file

          returns:
              True or False depending on if the extension is allowed
          """
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS #split the filename up and see if it's extension is allowed


def user_folders(user_name):
    """
          args:
          user_name:
            the name of the user in which the folder will be created

          returns:

          """
    #create the user's file to store uploads
    folder = os.path.join(app.config["UPLOAD_FOLDER"], str(user_name))
    if not os.path.exists(folder):
        os.makedirs(folder)


def list_files(dir):
    """
          args:
          dir:
            the directory that contains user files

          returns:
              a list of all files in the directory
          """
    #list all files in the user's directory
    found_files = []
    for root, _, files in os.walk(dir):
        for file in files:
            path = os.path.join(root, file)
            found_files.append(path)
    return found_files


def list_folders(dir):
    """
          args:
          dir:
            the directory that contains user files/folders

          returns:
              Every folder foud in the directory in a list
          """
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
    """
          args:
          file_id:
          the id of the file to manage from the database

          returns:
              Html page for file management with the variables file and file_id sent to jinja
          """
    file_record = File.query.get_or_404(file_id) #get all the data about the file with the sepcific id
    if file_record.owner != current_user.id:
        flash("You do not have permisson to acsess this file", "danger")
        return redirect(url_for("home"))
    full = os.path.join(app.config["UPLOAD_FOLDER"], *file_record.filepath.split("/"))
    return render_template("manage.html", file=file_record, file_id=file_id, path=full)

@app.route("/manage/<int:file_id>/make_public")
def make_public(file_id):
    """
          args:
          file_id:
          the id of the file to manage from the database

          returns:
              the redirect of the manage page with the variable file_id
          """
    file_record = File.query.get_or_404(file_id)
    if file_record.owner != current_user.id:
        flash("You do not have acsess to use this file", "danger")
        return redirect(url_for("home"))
    #Change the public flag to True (defualt false)
    file_record.public = True
    db.session.commit()
    flash("File is now public", "success")
    return redirect(url_for("manage", file_id=file_id))

@app.route("/manage/<int:file_id>/make_private")
def make_private(file_id):
    """
          args:
          file_id:
          the id of the file to manage from the database

          returns:
              redirect to manage after file is made private
          """

    file_record = File.query.get_or_404(file_id)
    #check file owner
    if file_record.owner != current_user.id:
        flash("You do not have acsess to use this file", "danger")
        return redirect(url_for("home"))
    file_record.public = False
    db.session.commit()
    flash("File is now private", "success")
    return redirect(url_for("manage", file_id=file_id))

@app.route("/public")
def public_files():
    """
          args:

          returns:
              Html page that shows all files with the public flag
          """
    public_files = File.query.filter( #get every file that has both public and no is encrypted
    and_(
        File.public == True,
        File.is_encrypted == False
        )
    ).all()
    return render_template("public.html", files=public_files) #show those files

@app.route("/")
def lander():
    """
          args:

          returns:
              Html page for the landing page
          """
    return render_template("lander.html")
        
@app.route("/manage/<int:file_id>/encrypt")
def encrypt_file(file_id):
    """
          args:
          file_id:
          the id of the file to encrypt from the database

          returns:
              Return the redirect url for the manage file after encrypting and changinging the encrypted flag in the databsee
          """
    file_record = File.query.get_or_404(file_id)
    if file_record.owner != current_user.id:
        flash("You do not have acsess to use this file", "danger")
        return redirect(url_for("home"))
    input_file = os.path.join(app.config["UPLOAD_FOLDER"], *file_record.filepath.split("/")) #unpack the filepath so it can be split into an absouluet path
    with open("secret.key", "rb") as f:
        key = f.read()
    fernet = Fernet(key) #open fernet secret key
    try:
        #encrypt if the file is not encrypted
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
    except Exception as e: #check for any exceptions and sprint it
        flash(f"Encryption failed! {e}", "danger")
    return redirect(url_for("manage", file_id=file_id))


@app.route("/manage/<int:file_id>/decrypt")
def decrypt_file(file_id): #same process as above
    """
              args:
              file_id:
              the id of the file to de decrypt from the database

              returns:
                  Return the redirect url for the manage file after decrypting and changinging the encrypted flag in the databsee
              """
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
            file_record.is_encrypted = False #only diffrence from above is that the encrypted is set to True
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
    """
              args:
              file_id:
              the id of the file to download from the database

              returns:
                  Returns the url of a generated downlaod link from send_file
              """
    file_record = File.query.get_or_404(file_id)
    public = file_record.public
    full = os.path.join(app.config["UPLOAD_FOLDER"], *file_record.filepath.split("/"))
    if not public:
        if file_record.owner != current_user.id:
            flash("You do not have permission to access this file", "danger")
            return redirect(url_for("home"))
        if file_record.is_encrypted:
            flash("Cannot download encrypte files", "error") #only allow download of non encrypted files
        else:
            return send_file(full, as_attachment=True) #download public files
    else:
        return send_file(full, as_attachment=True) #download private files





@app.route("/create_folder", methods=["POST"])
@login_required
def create_folder():
    """
              args:


              returns:
                  returns the user home after folder creation
              """
    folder_name = request.form.get("folder_name")
    if not folder_name:
        flash("Unnamed folders are not permitted")
        return redirect(url_for("home"))
    folder_name = secure_filename(folder_name)
    user_direcctory = os.path.join(app.config["UPLOAD_FOLDER"], current_user.username) #get where the new folder will be made
    new_path = os.path.join(user_direcctory, folder_name) #the path that will be used
    try:
        os.makedirs(new_path)
        flash(f"Folder {folder_name} has been created!", "success")
    except FileExistsError: #check for other folders with the same name
        flash(f"Folder {folder_name} already exists!", "danger")
    return redirect(url_for("home"))



@app.route("/folder/<path:foldername>/upload", methods=["GET", "POST"])
@login_required
def folder_upload(foldername):
    """
              args:
              foldername:
              the name of the folder to create

              returns:
                 Return the redirct view_files so the user can see the folder's contents
                 (return redirect(request.url)Refreshes the page the user is on
              """
    user_directory = os.path.join(app.config["UPLOAD_FOLDER"], current_user.username)
    target_folder = os.path.join(user_directory, foldername) #where the file will be uploaded i na specfif folder
    if not os.path.exists(target_folder):
        flash("Folder does not exist", "danger")
        return redirect(url_for("home"))
    if request.method == "POST":
        if "file" not in request.files: #check if the HTMl formactully sent a file
            flash("No file part ", "danger")
            return redirect(request.url)
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file", "danger")
            return redirect(request.url)
        if file and allowed_filetypes(file.filename):
            filename = secure_filename(file.filename)
            path = os.path.join(target_folder, filename)
            file.save(path)
            rel_path = os.path.relpath(path, app.config["UPLOAD_FOLDER"]).replace("\\", "/") #create a relative path based on the absoulte one
            #Create a new enetry in the File table with the new uploaded file in it
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
    """
              args:
              foldername:
              the name of the folder to show the contents of

              returns:
                 Return the redirect url for the folder page
              """
    user_directory = os.path.join(app.config["UPLOAD_FOLDER"], current_user.username)
    target_folder = os.path.join(user_directory, foldername)
    if not os.path.exists(target_folder):
        flash("Folder does not exist", "danger")
        return redirect(url_for("home"))
    rel_t = f"{current_user.username}/{foldername}" #get the relative filepath
    files_in_folder = File.query.filter(
    File.owner == current_user.id,
    File.filepath.like(f"{rel_t}/%") #returns all files in a specific folder
    ).all()
    return render_template("folder.html", files=files_in_folder, foldername=foldername)



@app.route("/home")
@login_required
def home():
    """
              args:


              returns:
                  Returns the main home.html with the files and folders variables for jinja
              """
    #basic home setup like the users folders wr=orking dir and files
    usr_dir = os.path.join(app.config["UPLOAD_FOLDER"], current_user.username)
    user_folders(current_user.username)
    usr_files = File.query.filter_by(owner=current_user.id).all()
    folders = list_folders(usr_dir)
    return render_template("home.html", files=usr_files, folders=folders)




@app.route("/delete/<int:file_id>", methods=["GET", "POST"])
@login_required
def delete(file_id):
    """
              args:
              file_id:
              the id of the file to delete from the database

              returns:
                  Return the redirect url for home page after file deletion
              """
    file_record = File.query.get_or_404(file_id)
    if file_record.owner != current_user.id: #check for ownership
        flash("You do not have acses to this file", "danger")
        return redirect(url_for("home"))
    full_path = os.path.join(app.config["UPLOAD_FOLDER"], *file_record.filepath.split("/"))
    if os.path.exists(full_path):
        os.remove(full_path)
    #remove the deleted file from the database
    db.session.delete(file_record)
    db.session.commit()
    flash("file deleted!", "success")
    return redirect(url_for("home"))




@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    """
              args:


              returns:
                  Return the page upload form.
                  Returns the user back to the page they were just on
              """
    if request.method == "POST":
        if "file" not in request.files:
            #if a file was incorrectly uploaded, refresh the page
            flash("No file part", "danger")
            return redirect(request.url)
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file", "danger")
            return redirect(request.url)
        if file and allowed_filetypes(file.filename):
            user_folders(current_user.username)
            filename = secure_filename(file.filename)
            #upload the fodler to the databse and commit
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
    debug_console()
    app.run(debug=True)

