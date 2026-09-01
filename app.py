import os
import sqlite3
from datetime import timedelta

import click
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    session,
    url_for,
)
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import check_password_hash, generate_password_hash


# Carga las variables almacenadas en .env
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "seguridad.db")

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

if not app.config["SECRET_KEY"]:
    raise RuntimeError("No se encontró SECRET_KEY en el archivo .env")


# Formulario de inicio de sesión
class LoginForm(FlaskForm):
    username = StringField(
        "Usuario",
        validators=[
            DataRequired(message="Ingresa tu usuario."),
            Length(min=3, max=30),
        ],
    )

    password = PasswordField(
        "Contraseña",
        validators=[
            DataRequired(message="Ingresa tu contraseña."),
        ],
    )

    submit = SubmitField("Iniciar sesión")


# Formulario vacío utilizado para cerrar sesión de forma segura
class LogoutForm(FlaskForm):
    submit = SubmitField("Cerrar sesión")


def get_db():
    """Abre una conexión con SQLite para la petición actual."""

    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """Cierra la conexión al terminar la petición."""

    database = g.pop("db", None)

    if database is not None:
        database.close()


def init_db():
    """Crea la tabla de usuarios si todavía no existe."""

    database = get_db()

    database.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    database.commit()


@app.cli.command("create-user")
@click.argument("username")
@click.option("--email", prompt="Correo electrónico")
@click.option(
    "--password",
    prompt="Contraseña",
    hide_input=True,
    confirmation_prompt="Repite la contraseña",
)
def create_user(username, email, password):
    """Crea un usuario y almacena el hash de su contraseña."""

    username = username.strip().lower()
    email = email.strip().lower()

    if len(username) < 3:
        click.echo("El usuario debe contener al menos 3 caracteres.")
        return

    if len(password) < 8:
        click.echo("La contraseña debe contener al menos 8 caracteres.")
        return

    password_hash = generate_password_hash(password)
    database = get_db()

    try:
        database.execute(
            """
            INSERT INTO users (username, password_hash, email)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, email),
        )

        database.commit()
        click.echo(f"Usuario '{username}' creado correctamente.")

    except sqlite3.IntegrityError:
        click.echo(f"El usuario '{username}' ya existe.")


@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        password = form.password.data

        database = get_db()

        user = database.execute(
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["security_layer"] = 1

            return redirect(url_for("dashboard"))

        flash("Usuario o contraseña incorrectos.", "error")

    return render_template("login.html", form=form)


@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    if not user_id:
        flash("Debes iniciar sesión para acceder.", "error")
        return redirect(url_for("login"))

    database = get_db()

    user = database.execute(
        """
        SELECT id, username, email, role
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    logout_form = LogoutForm()

    return render_template(
        "dashboard.html",
        user=user,
        logout_form=logout_form,
    )


@app.route("/logout", methods=["POST"])
def logout():
    form = LogoutForm()

    if form.validate_on_submit():
        session.clear()
        flash("La sesión se cerró correctamente.", "success")

    return redirect(url_for("login"))


# Crea la tabla cuando se carga la aplicación
with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True)