from flask import Flask, request, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String,Integer
from sqlalchemy.orm import DeclarativeBase,mapped_column, Mapped
from sqlalchemy.sql import func
from flask_jwt_extended import create_access_token,get_jwt_identity,jwt_required,JWTManager
from werkzeug.utils import secure_filename

class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] ="mysql://root:test123@localhost/employees"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
UPLOAD_FOLDER = "./files/"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db.init_app(app)

class Employee(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(20))
    email: Mapped[str] = mapped_column(String(20))
    designation: Mapped[str] = mapped_column(String(40))

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "secret_key12342"  # Change this!
jwt = JWTManager(app)

with app.app_context():
    db.create_all()

# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected_route", methods=["GET"])
@jwt_required()
def protectedRoute():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/register", methods = ["POST"]) #Create
def registerEmployee():
   #username=request.json.get("username", None)
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    email = request.json.get("email", None)
    designation = request.json.get("designation", None)
    if username == None:
        return "Username is required.",404
    employee = Employee(username=username,password=password,email=email,designation=designation)
    db.session.add(employee)
    db.session.commit()
    return "User Registered."

# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    
    query = db.session.query(Employee).filter(Employee.username==username, Employee.password==password)
    result = query.first()
    if result:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token)
    else:
        return "Please enter your correct login information. Register if you are not a user."

@app.route("/employees")
def getEmployee():
    employees = Employee.query.filter().all()
    result = []
    for i in employees:
        result.append({"Employee Name":i.username,"Designation":i.designation,"Email":i.email})
    return jsonify({"Employees":result})

@app.route("/employee", methods = ["POST"]) #Create
@jwt_required()
def createEmployee():
    username = request.json.get("username", None)
    designation = request.json.get("designation", None)
    email = request.json.get("email", None)
    current_user = get_jwt_identity()
    if username == None:
        return "Username is required",404
    employee = Employee(username=current_user,designation=designation,email=email)
    db.session.add(employee)
    db.session.commit()
    return "Hello World!"

@app.route("/employee/<username>", methods = ["GET"]) #Read
@jwt_required()
def getEmployee(designation):
    current_user = get_jwt_identity()
    obj =Employee.query.filter_by(username=current_user,designation=designation).first_or_404()
    result={"Employee Name":obj.username,"Designation":obj.designation,"Email":obj.email}
    return jsonify({"Employees":result})

@app.route("/employee/<username>", methods = ["PUT"]) #Update
@jwt_required()
def updateEmployee(username):
    designation = request.json.get("designation", 0)
    current_user = get_jwt_identity()
    if username == None:
        return "The employee you searching for does not exist.",404
    employee = Employee.query.filter_by(username=current_user).update(dict(designation=designation))
    db.session.commit()
    return "Successfully committed the changes!"

@app.route("/employee/<username>", methods = ["DELETE"]) #Delete
@jwt_required()
def deleteEmployee(username):
    print("Hi")
    if username == None:
        return "The employee you searching for does not exist.",404
    current_user = get_jwt_identity()
    obj =Employee.query.filter_by(username=current_user).first()
    db.session.delete(obj)
    db.session.commit()
    return "Employee deleted successfully."
  
@app.route("/file", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        # check if the post request has the file part
        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)
        file = request.files["file"]
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)
        if file and allowed_file(file.filename):
            return "File uploaded"
    return """
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    """

if __name__ == "__main__":
    app.run()