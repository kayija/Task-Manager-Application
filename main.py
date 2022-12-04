from flask import Flask, render_template, url_for, redirect, flash, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField, DateField, SelectField
from wtforms.validators import DataRequired, Email
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from datetime import datetime
from flask_ckeditor import CKEditorField

# from signal import signal, SIGPIPE, SIG_DFL
# signal(SIGPIPE,SIG_DFL)

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'

# applying Bootstrap to the app instance
Bootstrap(app)

# configuring the app to use Flask_login
login_manager = LoginManager()
login_manager.init_app(app)


# this will load the current user from the database
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///Todo.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# this code fixes RuntimeError: Working outside of application context.
app.app_context().push()


class Users(UserMixin, db.Model):
    __tablename__ = "Users_Table"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    user_email = db.Column(db.String(250), unique=True, nullable=False)
    user_password = db.Column(db.String(250), nullable=False)

    projects = relationship("Projects", back_populates="project_owner")


class Projects(db.Model):
    __tablename__ = "Projects_Table"
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(250), nullable=False)
    project_description = db.Column(db.String(500), nullable=True)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completion_timeline = db.Column(db.DateTime, nullable=False)

    project_owner = relationship("Users", back_populates="projects")
    project_owner_id = db.Column(db.Integer, db.ForeignKey("Users_Table.id"))
    tasks = relationship("To_Do", back_populates="tasks_name")


class To_Do(db.Model):
    __tablename__ = "ToDo_Table"
    id = db.Column(db.Integer, primary_key=True)

    project_id = db.Column(db.Integer, db.ForeignKey("Projects_Table.id"))
    tasks_name = relationship("Projects", back_populates="tasks")
    to_do_name = db.Column(db.String(250), nullable=False)
    to_do_description = db.Column(db.String(250), nullable=True)
    to_do_status = db.Column(db.String(50), nullable=False)
    completion_timeline = db.Column(db.DateTime, nullable=False)


db.create_all()


class Registration(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class User_Login(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")


class CreateProjectForm(FlaskForm):
    Project_Name = StringField("Project Name", validators=[DataRequired()])
    Project_Description = StringField("Project Description", validators=[DataRequired()])
    Complete_By = DateField("Date", validators=[DataRequired()])
    submit = SubmitField("Add Project")


class AddToDo(FlaskForm):
    ToDo_Name = StringField("To Do Name", validators=[DataRequired()])
    ToDo_Description = StringField("ToDO Description", validators=[DataRequired()])
    ToDo_Status = SelectField("Status", choices=["Not Started", "In Progress", "Completed"], validators=[DataRequired()])
    Completion_Timeline = DateField("Date", validators=[DataRequired()])
    submit = SubmitField("Add Task")


@app.route('/', methods=["GET", "POST"])
def home():
    return render_template("index.html", current_user=current_user )


# this works
@app.route('/registration', methods=["GET", "POST"])
def registration():
    form = Registration()
    if form.validate_on_submit():
        if Users.query.filter_by(user_email=form.email.data).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        hashed_password = generate_password_hash(form.password.data, method=("pbkdf2:sha256"), salt_length=8)
        new_user = Users(name=form.name.data, user_email=form.email.data, user_password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("registration.html", form=form)


# this works
@app.route('/login', methods=["GET", "POST"])
def login():
    form = User_Login()
    if form.validate_on_submit():
        user = Users.query.filter_by(user_email=form.email.data).first()
        if user:
            if check_password_hash(user.user_password, form.password.data):
                login_user(user)
                return redirect(url_for("projects"))
    return render_template("login.html", form=form)


# this works
@app.route('/projects', methods=["GET", "POST"])
@login_required
def projects():
    project = Projects.query.filter_by(project_owner_id=current_user.id)
    return render_template("projects.html", projects=project)


# this works
@app.route('/new_project', methods=["GET", "POST"])
@login_required
def add_project():
    form = CreateProjectForm()
    if form.validate_on_submit():
        new_project = Projects(project_name=form.Project_Name.data, project_description=form.Project_Description.data,
                               completion_timeline=form.Complete_By.data, project_owner_id=current_user.id)
        db.session.add(new_project)
        db.session.commit()
        return redirect(url_for('projects'))
    return render_template("new_project.html", form=form, current_user=current_user)


@app.route('/project-todo/<int:projects_id>', methods=["GET", "POST"])
@login_required
def project_todo(projects_id):
    current_project = Projects.query.get(projects_id)
    to_do = To_Do.query.filter_by(project_id=projects_id)
    return render_template("project-todo.html", project_todo=to_do, project=current_project)


@app.route('/add-todo/<int:projects_id>', methods=["GET", "POST"])
@login_required
def add_task(projects_id):
    new_todo_form = AddToDo()
    if new_todo_form.validate_on_submit():
        todo = To_Do(project_id=projects_id, to_do_name=new_todo_form.ToDo_Name.data,
                     to_do_description=new_todo_form.ToDo_Description.data, to_do_status=new_todo_form.ToDo_Status.data,
                     completion_timeline=new_todo_form.Completion_Timeline.data)
        db.session.add(todo)
        db.session.commit()
        return redirect(url_for("project_todo", projects_id=projects_id))
    current_project = Projects.query.filter_by(id=projects_id)
    return render_template("add_todo.html", form=new_todo_form, project=current_project)


@app.route('/change-status/<int:to_do_id>', methods=["GET", "POST"])
@login_required
def change_status(to_do_id):
    change_to_do_status = To_Do.query.get(to_do_id)
    if request.method == "POST":
        change_to_do_status.to_do_status = request.form.get("select-status")
        db.session.commit()
        return redirect(url_for("project_todo", projects_id=change_to_do_status.tasks_name.id))
    return redirect("project-todo.html")


@app.route("/delete/<int:projects_id>", methods=["GET", "POST"])
@login_required
def delete_project(projects_id):
    project_to_delete = Projects.query.get(projects_id)
    db.session.delete(project_to_delete)
    db.session.commit()
    return redirect(url_for('projects'))


@app.route("/delete_to_do/<int:to_do_id>", methods=["GET", "POST"])
@login_required
def delete_todo(to_do_id):
    to_do_delete = To_Do.query.get(to_do_id)
    db.session.delete(to_do_delete)
    db.session.commit()
    return redirect(url_for('projects'))
    # return redirect(url_for("project_todo"))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)