"""
Registro + 2FA (TOTP con pyotp) + login en Streamlit, con PostgreSQL.

Instalar:  pip install streamlit pyotp argon2-cffi cryptography "qrcode[pil]" psycopg2-binary

Variables de entorno (en el servidor, NO en el repo):
    PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD   (psycopg2/libpq las lee solas)
    APP_FERNET_KEY   -> python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Correr:  streamlit run app_auth.py
"""
import csv
import hmac
import io
import os
import re
import time
from contextlib import contextmanager
from datetime import date

import psycopg2
import pyotp
import qrcode
import streamlit as st
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from psycopg2.extras import RealDictCursor

# ---------------------------------------------------------------- config
TABLE = "app_users"       # nombre distinto para no chocar con tablas de la clase
ISSUER = "MiApp"
MAX_ATTEMPTS = 5          # intentos fallidos antes de bloquear
LOCK_SECONDS = 300        # 5 min de bloqueo
TOTP_STEP = 30

_key = os.getenv("APP_FERNET_KEY")
if not _key:
    st.error("Falta la variable de entorno APP_FERNET_KEY.")
    st.stop()
fernet = Fernet(_key.encode())
ph = PasswordHasher()                       # Argon2id
DUMMY_HASH = ph.hash("dummy-password-xyz")  # iguala tiempos si el usuario no existe


# ---------------------------------------------------------------- cifrado
def enc(text: str) -> bytes:
    return fernet.encrypt(text.encode())


def dec(blob) -> str:
    return fernet.decrypt(bytes(blob)).decode()  # bytes(): psycopg2 devuelve memoryview


# ---------------------------------------------------------------- base de datos
@contextmanager
def db():
    """Cursor con commit/rollback automático. Lee PG* del entorno."""
    con = psycopg2.connect(cursor_factory=RealDictCursor)
    try:
        yield con.cursor()
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db():
    with db() as cur:
        cur.execute(
            f"""CREATE TABLE IF NOT EXISTS {TABLE}(
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,          -- Argon2id (sal incluida)
                full_name_enc BYTEA NOT NULL,         -- PII cifrado
                document_id_enc BYTEA NOT NULL,       -- PII cifrado
                birth_date_enc BYTEA NOT NULL,        -- PII cifrado
                health_info_enc BYTEA,                -- PHI cifrado
                monthly_income_enc BYTEA,             -- crediticio cifrado
                credit_score_enc BYTEA,               -- crediticio cifrado
                card_last4_enc BYTEA,                 -- solo últimos 4; NUNCA número completo ni CVV
                totp_secret_enc BYTEA NOT NULL,       -- secreto TOTP cifrado
                totp_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
                last_totp_step BIGINT NOT NULL DEFAULT 0,   -- anti-replay
                failed_attempts INT NOT NULL DEFAULT 0,
                locked_until DOUBLE PRECISION NOT NULL DEFAULT 0,
                created_at DOUBLE PRECISION NOT NULL
            )"""
        )


# ---------------------------------------------------------------- política de contraseña
def validate_password(pw: str, username: str, email: str) -> list[str]:
    errs = []
    if len(pw) < 12:
        errs.append("Mínimo 12 caracteres.")
    if len(pw) > 128:
        errs.append("Máximo 128 caracteres.")
    if not re.search(r"[a-z]", pw):
        errs.append("Debe tener una minúscula.")
    if not re.search(r"[A-Z]", pw):
        errs.append("Debe tener una mayúscula.")
    if not re.search(r"\d", pw):
        errs.append("Debe tener un número.")
    if not re.search(r"[^\w\s]", pw):
        errs.append("Debe tener un símbolo.")
    low = pw.lower()
    if username and username.lower() in low:
        errs.append("No puede contener el usuario.")
    if email and email.split("@")[0].lower() in low:
        errs.append("No puede contener el correo.")
    if re.search(r"(.)\1{2,}", pw):
        errs.append("No repitas el mismo carácter 3+ veces seguidas.")
    return errs


# ---------------------------------------------------------------- TOTP
def new_secret() -> str:
    return pyotp.random_base32()


def qr_png(secret: str, label: str) -> bytes:
    uri = pyotp.TOTP(secret, interval=TOTP_STEP).provisioning_uri(name=label, issuer_name=ISSUER)
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    return buf.getvalue()


def check_otp(secret: str, code: str, last_step: int):
    """Devuelve el step usado si el código es válido y no se reutilizó; si no, None.
    Ventana ±1 paso + anti-replay + comparación en tiempo constante."""
    if not re.fullmatch(r"\d{6}", code or ""):
        return None
    totp = pyotp.TOTP(secret, interval=TOTP_STEP)
    now_step = int(time.time() // TOTP_STEP)
    matched = None
    for step in (now_step - 1, now_step, now_step + 1):
        if hmac.compare_digest(totp.generate_otp(step), code):
            matched = step
    if matched is None or matched <= last_step:
        return None
    return matched


# ---------------------------------------------------------------- registro
def register(f: dict):
    secret = new_secret()
    try:
        with db() as cur:
            cur.execute(
                f"""INSERT INTO {TABLE}(username,email,password_hash,full_name_enc,document_id_enc,
                    birth_date_enc,health_info_enc,monthly_income_enc,credit_score_enc,card_last4_enc,
                    totp_secret_enc,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    f["username"], f["email"], ph.hash(f["password"]),
                    enc(f["full_name"]), enc(f["document_id"]), enc(str(f["birth_date"])),
                    enc(f["health_info"]) if f["health_info"] else None,
                    enc(str(f["income"])), enc(str(f["score"])), enc(f["last4"]),
                    enc(secret), time.time(),
                ),
            )
    except psycopg2.IntegrityError:
        return None  # usuario o correo ya existe
    return secret


def page_register():
    st.subheader("Registro")
    # Paso 2: activar 2FA
    if "pending" in st.session_state:
        p = st.session_state["pending"]
        st.success("Cuenta creada. Ahora activa el 2FA.")
        st.image(qr_png(p["secret"], p["email"]), caption="Escanéalo con Google/Microsoft Authenticator")
        st.caption(f"O ingresa la llave manual: `{p['secret']}`")
        code = st.text_input("Código de 6 dígitos para confirmar", max_chars=6, key="act_code")
        if st.button("Activar 2FA"):
            with db() as cur:
                cur.execute(f"SELECT * FROM {TABLE} WHERE username=%s", (p["username"],))
                row = cur.fetchone()
                step = check_otp(dec(row["totp_secret_enc"]), code, row["last_totp_step"])
                if step:
                    cur.execute(
                        f"UPDATE {TABLE} SET totp_confirmed=TRUE, last_totp_step=%s WHERE id=%s",
                        (step, row["id"]),
                    )
                    del st.session_state["pending"]
                    st.success("2FA activado. Ya puedes iniciar sesión.")
                else:
                    st.error("Código inválido.")
        return

    with st.form("registro"):
        st.markdown("**Cuenta**")
        username = st.text_input("Usuario")
        email = st.text_input("Correo")
        pw = st.text_input("Contraseña", type="password")
        pw2 = st.text_input("Confirmar contraseña", type="password")
        st.markdown("**Datos personales (PII)**")
        full_name = st.text_input("Nombre completo")
        document_id = st.text_input("Documento de identidad")
        birth_date = st.date_input("Fecha de nacimiento", min_value=date(1900, 1, 1),
                                   max_value=date.today(), value=date(2000, 1, 1))
        st.markdown("**Salud (PHI)**")
        health_info = st.text_area("Condiciones / alergias (opcional)")
        st.markdown("**Datos crediticios**")
        income = st.number_input("Ingresos mensuales", min_value=0.0, step=100000.0)
        score = st.number_input("Puntaje crediticio", min_value=150, max_value=950, value=600)
        last4 = st.text_input("Últimos 4 dígitos de la tarjeta", max_chars=4)
        consent = st.checkbox("Acepto el tratamiento de mis datos personales (Ley 1581 de 2012)")
        ok = st.form_submit_button("Registrarme")

    if not ok:
        return
    errs = []
    if not consent:
        errs.append("Debes aceptar el tratamiento de datos.")
    if not re.fullmatch(r"[A-Za-z0-9_]{4,30}", username):
        errs.append("Usuario: 4-30 caracteres (letras, números, _).")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        errs.append("Correo inválido.")
    if not full_name.strip() or not document_id.strip():
        errs.append("Nombre y documento son obligatorios.")
    if not re.fullmatch(r"\d{4}", last4):
        errs.append("Los últimos 4 dígitos deben ser numéricos.")
    if pw != pw2:
        errs.append("Las contraseñas no coinciden.")
    errs += validate_password(pw, username, email)
    if errs:
        for e in errs:
            st.error(e)
        return

    secret = register(dict(
        username=username, email=email.lower(), password=pw, full_name=full_name.strip(),
        document_id=document_id.strip(), birth_date=birth_date, health_info=health_info.strip(),
        income=income, score=score, last4=last4,
    ))
    if secret is None:
        st.error("No se pudo registrar con esos datos. Prueba con otro usuario o correo.")
        return
    st.session_state["pending"] = {"username": username, "email": email.lower(), "secret": secret}
    st.rerun()


# ---------------------------------------------------------------- login
def login(username: str, password: str, otp: str):
    """Devuelve (ok, mensaje). Mensaje genérico: no revela cuál de las 3 variables falló."""
    GENERIC = "Credenciales inválidas."
    with db() as cur:
        cur.execute(f"SELECT * FROM {TABLE} WHERE username=%s", (username,))
        row = cur.fetchone()

        if row is None:
            try:  # mismo costo que un usuario real (anti enumeración por tiempo)
                ph.verify(DUMMY_HASH, password)
            except VerifyMismatchError:
                pass
            return False, GENERIC

        if row["locked_until"] > time.time():
            mins = int((row["locked_until"] - time.time()) // 60) + 1
            return False, f"Cuenta bloqueada temporalmente. Intenta en ~{mins} min."

        # Evaluar SIEMPRE las dos pruebas (sin cortocircuitar)
        try:
            pw_ok = ph.verify(row["password_hash"], password)
        except VerifyMismatchError:
            pw_ok = False
        step = check_otp(dec(row["totp_secret_enc"]), otp, row["last_totp_step"])
        otp_ok = step is not None and row["totp_confirmed"]

        if pw_ok and otp_ok:
            cur.execute(
                f"UPDATE {TABLE} SET failed_attempts=0, locked_until=0, last_totp_step=%s WHERE id=%s",
                (step, row["id"]),
            )
            if ph.check_needs_rehash(row["password_hash"]):
                cur.execute(f"UPDATE {TABLE} SET password_hash=%s WHERE id=%s",
                            (ph.hash(password), row["id"]))
            return True, "ok"

        attempts = row["failed_attempts"] + 1
        locked = time.time() + LOCK_SECONDS if attempts >= MAX_ATTEMPTS else 0
        cur.execute(
            f"UPDATE {TABLE} SET failed_attempts=%s, locked_until=%s WHERE id=%s",
            (0 if locked else attempts, locked, row["id"]),
        )
        return False, GENERIC


def page_login():
    st.subheader("Iniciar sesión")
    if st.session_state.get("user"):
        st.success(f"Sesión iniciada como {st.session_state['user']}")
        if st.button("Cerrar sesión"):
            del st.session_state["user"]
            st.rerun()
        return
    with st.form("login"):
        u = st.text_input("Usuario")
        p = st.text_input("Contraseña", type="password")
        o = st.text_input("Código OTP (6 dígitos)", max_chars=6)
        ok = st.form_submit_button("Entrar")
    if ok:
        if not (u and p and o):
            st.error("Completa usuario, contraseña y OTP.")
            return
        good, msg = login(u, p, o)
        if good:
            st.session_state["user"] = u
            st.rerun()
        else:
            st.error(msg)


# ---------------------------------------------------------------- export CSV
def _safe(v) -> str:
    """Evita CSV/formula injection: celdas que empiezan con = + - @ se prefijan con '."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def users_csv() -> str:
    """CSV con los datos de los usuarios. Descifra PII/PHI/crediticios;
    NO exporta password_hash ni el secreto TOTP."""
    with db() as cur:
        cur.execute(f"SELECT * FROM {TABLE} ORDER BY id")
        rows = cur.fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "usuario", "correo", "nombre_completo", "documento", "fecha_nacimiento",
                "salud", "ingresos_mensuales", "puntaje_crediticio", "tarjeta_ultimos4",
                "2fa_activo", "fecha_registro"])
    for r in rows:
        w.writerow([
            r["id"], _safe(r["username"]), _safe(r["email"]),
            _safe(dec(r["full_name_enc"])), _safe(dec(r["document_id_enc"])),
            _safe(dec(r["birth_date_enc"])),
            _safe(dec(r["health_info_enc"])) if r["health_info_enc"] else "",
            dec(r["monthly_income_enc"]), dec(r["credit_score_enc"]), dec(r["card_last4_enc"]),
            r["totp_confirmed"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["created_at"])),
        ])
    return out.getvalue()


def page_export():
    st.subheader("Exportar usuarios")
    if not st.session_state.get("user"):  # solo con sesión iniciada (login + OTP)
        st.warning("Inicia sesión para descargar los datos.")
        return
    st.download_button(
        "Descargar usuarios (CSV)",
        data=users_csv().encode("utf-8-sig"),  # utf-8-sig: Excel abre bien las tildes
        file_name="usuarios.csv",
        mime="text/csv",
    )


# ---------------------------------------------------------------- main
init_db()
st.title("Autenticación y registro")
tab1, tab2, tab3 = st.tabs(["Registro", "Login", "Usuarios"])
with tab1:
    page_register()
with tab2:
    page_login()
with tab3:
    page_export()
