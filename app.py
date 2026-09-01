import os
import random
import secrets
import sqlite3
import time
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
from wtforms import IntegerField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, InputRequired, Length, NumberRange
from werkzeug.security import check_password_hash, generate_password_hash


# Carga las variables almacenadas en el .env
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


# Formulario vacío para cerrar sesión
class LogoutForm(FlaskForm):
    submit = SubmitField("Cerrar sesión")

class CaptchaForm(FlaskForm):
    answer = IntegerField(
        "Respuesta",
        validators=[
            InputRequired(message="Debes resolver la operación."),
            NumberRange(
                min=0,
                max=100,
                message="La respuesta debe ser un número válido.",
            ),
        ],
    )

    submit = SubmitField("Verificar CAPTCHA")


class RefreshCaptchaForm(FlaskForm):
    submit = SubmitField("Generar otra operación")

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

    database.execute(
        """
        CREATE TABLE IF NOT EXISTS captcha_challenges (
            challenge_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            question TEXT NOT NULL,
            answer INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )

    database.commit()

def create_captcha(user_id):
    """Crea una operación matemática con una vigencia de cinco minutos."""

    database = get_db()

    # Elimina operaciones anteriores del mismo usuario
    database.execute(
        """
        DELETE FROM captcha_challenges
        WHERE user_id = ?
        """,
        (user_id,),
    )

    first_number = random.randint(1, 10)
    second_number = random.randint(1, 10)

    question = f"{first_number} + {second_number}"
    answer = first_number + second_number

    challenge_id = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + 300

    database.execute(
        """
        INSERT INTO captcha_challenges (
            challenge_id,
            user_id,
            question,
            answer,
            expires_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            challenge_id,
            user_id,
            question,
            answer,
            expires_at,
        ),
    )

    database.commit()

    session["captcha_id"] = challenge_id

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
        if session.get("security_layer", 0) >= 2:
            return redirect(url_for("dashboard"))

        return redirect(url_for("captcha"))

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

            create_captcha(user["id"])

            return redirect(url_for("captcha"))

        flash("Usuario o contraseña incorrectos.", "error")

    return render_template("login.html", form=form)

@app.route("/captcha", methods=["GET", "POST"])
def captcha():
    user_id = session.get("user_id")
    security_layer = session.get("security_layer", 0)

    if not user_id:
        flash("Primero debes iniciar sesión.", "error")
        return redirect(url_for("login"))

    if security_layer >= 2:
        return redirect(url_for("dashboard"))

    if security_layer != 1:
        session.clear()
        return redirect(url_for("login"))

    database = get_db()
    challenge_id = session.get("captcha_id")

    challenge = database.execute(
        """
        SELECT challenge_id, user_id, question, answer, expires_at
        FROM captcha_challenges
        WHERE challenge_id = ? AND user_id = ?
        """,
        (challenge_id, user_id),
    ).fetchone()

    if challenge is None:
        create_captcha(user_id)
        return redirect(url_for("captcha"))

    if challenge["expires_at"] < int(time.time()):
        create_captcha(user_id)
        flash(
            "El CAPTCHA expiró. Se generó una nueva operación.",
            "error",
        )
        return redirect(url_for("captcha"))

    captcha_form = CaptchaForm()
    refresh_form = RefreshCaptchaForm()

    if captcha_form.validate_on_submit():
        if captcha_form.answer.data == challenge["answer"]:
            database.execute(
                """
                DELETE FROM captcha_challenges
                WHERE challenge_id = ?
                """,
                (challenge["challenge_id"],),
            )

            database.commit()

            session.pop("captcha_id", None)
            session["security_layer"] = 2

            flash("CAPTCHA resuelto correctamente.", "success")
            return redirect(url_for("dashboard"))

        create_captcha(user_id)

        flash(
            "La respuesta es incorrecta. Se generó otra operación.",
            "error",
        )

        return redirect(url_for("captcha"))

    return render_template(
        "captcha.html",
        question=challenge["question"],
        captcha_form=captcha_form,
        refresh_form=refresh_form,
    )

@app.route("/captcha/refresh", methods=["POST"])
def refresh_captcha():
    user_id = session.get("user_id")
    security_layer = session.get("security_layer", 0)

    if not user_id or security_layer != 1:
        return redirect(url_for("login"))

    form = RefreshCaptchaForm()

    if form.validate_on_submit():
        create_captcha(user_id)
        flash("Se generó una nueva operación.", "success")

    return redirect(url_for("captcha"))

@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    if not user_id:
        flash("Debes iniciar sesión para acceder.", "error")
        return redirect(url_for("login"))

    if session.get("security_layer", 0) < 2:
        flash("Debes completar el CAPTCHA.", "error")
        return redirect(url_for("captcha"))
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
        challenge_id = session.get("captcha_id")

        if challenge_id:
            database = get_db()

            database.execute(
                """
                DELETE FROM captcha_challenges
                WHERE challenge_id = ?
                """,
                (challenge_id,),
            )

            database.commit()

        session.clear()
        flash("La sesión se cerró correctamente.", "success")

    return redirect(url_for("login"))


# Crea la tabla cuando se carga la aplicación
with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True)