import os
import random
import secrets
import sqlite3
import time
import hashlib
import hmac
import smtplib
import ssl
import base64
import io
import pyotp
import qrcode
from email.message import EmailMessage
from email.headerregistry import Address
from datetime import datetime, timedelta, timezone

import click
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    session,
    url_for,
)
from flask_wtf import FlaskForm
from wtforms import IntegerField, PasswordField, StringField, SubmitField
from wtforms.validators import (
    DataRequired,
    InputRequired,
    Length,
    NumberRange,
    Regexp,
)
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

class EmailCodeForm(FlaskForm):
    code = StringField(
        "Código de verificación",
        validators=[
            DataRequired(message="Ingresa el código recibido."),
            Regexp(
                r"^\d{6}$",
                message="El código debe contener exactamente seis números.",
            ),
        ],
    )

    submit = SubmitField("Verificar código")


class ResendEmailCodeForm(FlaskForm):
    submit = SubmitField("Enviar otro código")

class TotpCodeForm(FlaskForm):
    code = StringField(
        "Código del autenticador",
        validators=[
            DataRequired(message="Ingresa el código del autenticador."),
            Regexp(
                r"^\d{6}$",
                message="El código debe contener exactamente seis números.",
            ),
        ],
    )

    submit = SubmitField("Verificar código")

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

    database.execute(
        """
        CREATE TABLE IF NOT EXISTS email_challenges (
            challenge_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )

    database.execute(
        """
        CREATE TABLE IF NOT EXISTS totp_usage (
            user_id INTEGER PRIMARY KEY,
            last_timecode INTEGER NOT NULL,
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

def hash_email_code(code):
    """Crea un HMAC del código utilizando la clave secreta."""

    secret_key = app.config["SECRET_KEY"].encode("utf-8")
    code_bytes = code.encode("utf-8")

    return hmac.new(
        secret_key,
        code_bytes,
        hashlib.sha256,
    ).hexdigest()


def send_verification_email(recipient, code):
    """Envía el código mediante SMTP."""

    mail_server = os.getenv("MAIL_SERVER")
    mail_port = int(os.getenv("MAIL_PORT", "587"))
    mail_use_tls = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
    mail_username = os.getenv("MAIL_USERNAME")
    mail_password = os.getenv("MAIL_PASSWORD")
    mail_from = os.getenv("MAIL_FROM", mail_username)
    mail_sender_name = os.getenv(
    "MAIL_SENDER_NAME",
    "Sistema de Seguridad",
)
    if not all(
        [
            mail_server,
            mail_username,
            mail_password,
            mail_from,
        ]
    ):
        raise RuntimeError(
            "La configuración SMTP está incompleta en el archivo .env"
        )

    message = EmailMessage()
    message["Subject"] = "Código de verificación"
    message["From"] = Address(
    display_name=mail_sender_name,
    addr_spec=mail_from,
)
    message["To"] = recipient

    message.set_content(
        f"""
Se solicitó un código para acceder al sistema de seguridad.

Tu código de verificación es:

{code}

El código expirará en cinco minutos.

Si no realizaste esta solicitud, puedes ignorar este mensaje.
""".strip()
    )

    ssl_context = ssl.create_default_context()

    with smtplib.SMTP(
        mail_server,
        mail_port,
        timeout=15,
    ) as smtp:
        smtp.ehlo()

        if mail_use_tls:
            smtp.starttls(context=ssl_context)
            smtp.ehlo()

        smtp.login(mail_username, mail_password)
        smtp.send_message(message)


def create_email_challenge(user_id):
    """Genera, envía y almacena un desafío de correo."""

    database = get_db()

    user = database.execute(
        """
        SELECT id, email
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    if user is None:
        raise RuntimeError("El usuario no existe")

    code = f"{secrets.randbelow(1_000_000):06d}"
    challenge_id = secrets.token_urlsafe(32)
    current_time = int(time.time())
    expires_at = current_time + 300

    # Primero intenta enviar el código. Si el envío falla,
    # el código anterior permanece disponible.
    send_verification_email(user["email"], code)

    database.execute(
        """
        DELETE FROM email_challenges
        WHERE user_id = ?
        """,
        (user_id,),
    )

    database.execute(
        """
        INSERT INTO email_challenges (
            challenge_id,
            user_id,
            code_hash,
            expires_at,
            attempts,
            created_at
        )
        VALUES (?, ?, ?, ?, 0, ?)
        """,
        (
            challenge_id,
            user_id,
            hash_email_code(code),
            expires_at,
            current_time,
        ),
    )

    database.commit()

    session["email_challenge_id"] = challenge_id


def mask_email(email):
    """Oculta parcialmente el correo mostrado en pantalla."""

    local_part, separator, domain = email.partition("@")

    if not separator:
        return email

    visible_character = local_part[:1]
    hidden_characters = "*" * max(len(local_part) - 1, 3)

    return f"{visible_character}{hidden_characters}@{domain}"

def find_totp_timecode(secret, code):
    """
    Verifica el código actual y permite una diferencia
    máxima de 30 segundos.
    """

    code = code.strip()

    if not code.isdigit() or len(code) != 6:
        return None

    totp = pyotp.TOTP(secret)
    current_time = datetime.now(timezone.utc)

    for offset in (0, -1, 1):
        candidate_time = current_time + timedelta(
            seconds=offset * totp.interval
        )

        expected_code = totp.at(candidate_time)

        if hmac.compare_digest(expected_code, code):
            return totp.timecode(candidate_time)

    return None


def create_totp_qr(secret, account_name):
    """Genera un QR TOTP y lo devuelve codificado en Base64."""

    totp = pyotp.TOTP(secret)

    provisioning_uri = totp.provisioning_uri(
        name=account_name,
        issuer_name="Seguridad Práctica",
    )

    qr_image = qrcode.make(provisioning_uri)
    image_buffer = io.BytesIO()

    qr_image.save(image_buffer, format="PNG")

    return base64.b64encode(
        image_buffer.getvalue()
    ).decode("ascii")

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
        security_layer = session.get("security_layer", 0)

        if security_layer >= 4:
            return redirect(url_for("dashboard"))

        if security_layer == 3:
            return redirect(url_for("totp_verification"))

        if security_layer == 2:
            return redirect(url_for("email_verification"))

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

    if security_layer >= 4:
        return redirect(url_for("dashboard"))

    if security_layer == 3:
        return redirect(url_for("totp_verification"))

    if security_layer == 2:
        return redirect(url_for("email_verification"))

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

            try:
                create_email_challenge(user_id)

                flash(
                    "Se envió un código de verificación a tu correo.",
                    "success",
                )

            except Exception:
                app.logger.exception(
                    "No fue posible enviar el código por correo"
                )

                flash(
                    "No fue posible enviar el código. "
                    "Revisa la configuración SMTP e intenta nuevamente.",
                    "error",
                )

            return redirect(url_for("email_verification"))

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

@app.route("/email-verification", methods=["GET", "POST"])
def email_verification():
    user_id = session.get("user_id")
    security_layer = session.get("security_layer", 0)

    if not user_id:
        flash("Primero debes iniciar sesión.", "error")
        return redirect(url_for("login"))

    if security_layer >= 4:
        return redirect(url_for("dashboard"))

    if security_layer == 3:
        return redirect(url_for("totp_verification"))

    if security_layer < 2:
        return redirect(url_for("captcha"))

    database = get_db()

    user = database.execute(
        """
        SELECT id, email
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    challenge_id = session.get("email_challenge_id")

    challenge = database.execute(
        """
        SELECT
            challenge_id,
            user_id,
            code_hash,
            expires_at,
            attempts,
            created_at
        FROM email_challenges
        WHERE challenge_id = ? AND user_id = ?
        """,
        (challenge_id, user_id),
    ).fetchone()

    if challenge and challenge["expires_at"] < int(time.time()):
        database.execute(
            """
            DELETE FROM email_challenges
            WHERE challenge_id = ?
            """,
            (challenge["challenge_id"],),
        )

        database.commit()

        session.pop("email_challenge_id", None)
        challenge = None

        flash(
            "El código expiró. Solicita uno nuevo.",
            "error",
        )

    code_form = EmailCodeForm()
    resend_form = ResendEmailCodeForm()

    if code_form.validate_on_submit():
        if challenge is None:
            flash(
                "No hay un código activo. Solicita uno nuevo.",
                "error",
            )
            return redirect(url_for("email_verification"))

        received_hash = hash_email_code(code_form.code.data)

        if hmac.compare_digest(
            received_hash,
            challenge["code_hash"],
        ):
            database.execute(
                """
                DELETE FROM email_challenges
                WHERE challenge_id = ?
                """,
                (challenge["challenge_id"],),
            )

            database.commit()

            session.pop("email_challenge_id", None)
            session["security_layer"] = 3

            flash(
                "Código de correo verificado correctamente.",
                "success",
            )

            return redirect(url_for("totp_verification"))

        new_attempt_count = challenge["attempts"] + 1

        if new_attempt_count >= 5:
            database.execute(
                """
                DELETE FROM email_challenges
                WHERE challenge_id = ?
                """,
                (challenge["challenge_id"],),
            )

            database.commit()
            session.pop("email_challenge_id", None)

            flash(
                "Se alcanzó el máximo de intentos. "
                "Solicita un código nuevo.",
                "error",
            )

        else:
            database.execute(
                """
                UPDATE email_challenges
                SET attempts = ?
                WHERE challenge_id = ?
                """,
                (
                    new_attempt_count,
                    challenge["challenge_id"],
                ),
            )

            database.commit()

            remaining_attempts = 5 - new_attempt_count

            flash(
                f"Código incorrecto. "
                f"Intentos restantes: {remaining_attempts}.",
                "error",
            )

        return redirect(url_for("email_verification"))

    return render_template(
        "email_verification.html",
        masked_email=mask_email(user["email"]),
        has_active_code=challenge is not None,
        code_form=code_form,
        resend_form=resend_form,
    )

@app.route("/email-verification/resend", methods=["POST"])
def resend_email_code():
    user_id = session.get("user_id")
    security_layer = session.get("security_layer", 0)

    if not user_id or security_layer != 2:
        return redirect(url_for("login"))

    form = ResendEmailCodeForm()

    if not form.validate_on_submit():
        return redirect(url_for("email_verification"))

    database = get_db()

    current_challenge = database.execute(
        """
        SELECT created_at
        FROM email_challenges
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()

    if current_challenge:
        elapsed_time = int(time.time()) - current_challenge["created_at"]

        if elapsed_time < 60:
            remaining_time = 60 - elapsed_time

            flash(
                f"Espera {remaining_time} segundos antes de solicitar otro código.",
                "error",
            )

            return redirect(url_for("email_verification"))

    try:
        create_email_challenge(user_id)

        flash(
            "Se envió un nuevo código a tu correo.",
            "success",
        )

    except Exception:
        app.logger.exception(
            "No fue posible reenviar el código"
        )

        flash(
            "No fue posible enviar el código. "
            "Revisa la configuración SMTP.",
            "error",
        )

    return redirect(url_for("email_verification"))

@app.route("/totp-verification", methods=["GET", "POST"])
def totp_verification():
    user_id = session.get("user_id")
    security_layer = session.get("security_layer", 0)

    if not user_id:
        flash("Primero debes iniciar sesión.", "error")
        return redirect(url_for("login"))

    if security_layer >= 4:
        return redirect(url_for("dashboard"))

    if security_layer < 2:
        return redirect(url_for("captcha"))

    if security_layer < 3:
        return redirect(url_for("email_verification"))

    database = get_db()

    user = database.execute(
        """
        SELECT
            id,
            username,
            email,
            totp_secret,
            totp_enabled
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    totp_secret = user["totp_secret"]

    # Primera configuración del autenticador
    if not totp_secret:
        totp_secret = pyotp.random_base32()

        database.execute(
            """
            UPDATE users
            SET totp_secret = ?, totp_enabled = 0
            WHERE id = ?
            """,
            (totp_secret, user_id),
        )

        database.commit()

    setup_mode = not bool(user["totp_enabled"])
    form = TotpCodeForm()

    if form.validate_on_submit():
        matched_timecode = find_totp_timecode(
            totp_secret,
            form.code.data,
        )

        if matched_timecode is None:
            attempts = session.get("totp_attempts", 0) + 1
            session["totp_attempts"] = attempts

            if attempts >= 5:
                session.clear()

                flash(
                    "Se alcanzó el máximo de intentos. "
                    "Inicia el proceso nuevamente.",
                    "error",
                )

                return redirect(url_for("login"))

            remaining_attempts = 5 - attempts

            flash(
                f"Código incorrecto. "
                f"Intentos restantes: {remaining_attempts}.",
                "error",
            )

            return redirect(url_for("totp_verification"))

        previous_usage = database.execute(
            """
            SELECT last_timecode
            FROM totp_usage
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        if (
            previous_usage
            and matched_timecode <= previous_usage["last_timecode"]
        ):
            flash(
                "Este código ya fue utilizado. "
                "Espera a que la aplicación genere uno nuevo.",
                "error",
            )

            return redirect(url_for("totp_verification"))

        database.execute(
            """
            UPDATE users
            SET totp_enabled = 1
            WHERE id = ?
            """,
            (user_id,),
        )

        database.execute(
            """
            INSERT INTO totp_usage (user_id, last_timecode)
            VALUES (?, ?)
            ON CONFLICT(user_id)
            DO UPDATE SET last_timecode = excluded.last_timecode
            """,
            (user_id, matched_timecode),
        )

        database.commit()

        session.pop("totp_attempts", None)
        session["security_layer"] = 4

        if setup_mode:
            flash(
                "El autenticador fue configurado correctamente.",
                "success",
            )
        else:
            flash(
                "Código del autenticador verificado.",
                "success",
            )

        return redirect(url_for("dashboard"))

    qr_image = None

    if setup_mode:
        qr_image = create_totp_qr(
            totp_secret,
            user["email"],
        )

    response = make_response(
        render_template(
            "totp_verification.html",
            form=form,
            setup_mode=setup_mode,
            qr_image=qr_image,
            totp_secret=totp_secret if setup_mode else None,
        )
    )

    # Evita guardar en caché una página que contiene el secreto TOTP
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, private"
    )
    response.headers["Pragma"] = "no-cache"

    return response

@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    if not user_id:
        flash("Debes iniciar sesión para acceder.", "error")
        return redirect(url_for("login"))

    security_layer = session.get("security_layer", 0)

    if security_layer < 2:
        flash("Debes completar el CAPTCHA.", "error")
        return redirect(url_for("captcha"))

    if security_layer < 3:
        flash(
            "Debes verificar el código enviado por correo.",
            "error",
        )
        return redirect(url_for("email_verification"))

    if security_layer < 4:
        flash(
            "Debes verificar el código de tu autenticador.",
            "error",
        )
        return redirect(url_for("totp_verification"))

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
        email_challenge_id = session.get("email_challenge_id")
        if challenge_id:
            database = get_db()

            database.execute(
                """
                DELETE FROM captcha_challenges
                WHERE challenge_id = ?
                """,
                (challenge_id,),
            )

        if email_challenge_id:
            database = get_db()

            database.execute(
                """
                DELETE FROM email_challenges
                WHERE challenge_id = ?
                """,
                (email_challenge_id,),
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