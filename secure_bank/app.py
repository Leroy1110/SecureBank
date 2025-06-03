from __future__ import annotations

import os
import logging
import logging.handlers
from datetime import datetime
from typing import Optional

from flask import (
    Flask, render_template, redirect, url_for, request, flash,
    abort, current_app, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_migrate import Migrate
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import (
    StringField, PasswordField, SubmitField, FloatField, HiddenField
)
from wtforms.validators import (
    DataRequired, Length, EqualTo, NumberRange, Email, ValidationError
)
from cryptography.fernet import Fernet, InvalidToken
import pyotp
import qrcode
from io import BytesIO
import base64
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_mail import Mail, Message

# ────────────────────────────────────────────────────────────────────────────
# Extension instances (initialized later in create_app)
# ────────────────────────────────────────────────────────────────────────────

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()
migrate = Migrate()
mail = Mail()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])


CSP = {
    'default-src': ['\'self\''],
    'img-src': ['\'self\'', 'data:'],
}

# ---------------------------------------------------------------------------
# Configuration classes
# ---------------------------------------------------------------------------
# --- Helpers for absolute paths ------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
# -------------------------------------------------------------------------


class BaseConfig:
    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(32))
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # נתיב מוחלט למסד-הנתונים
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URI",
        f"sqlite:///{os.path.join(PROJECT_ROOT, 'instance', 'bank.db')}"
    )

    SECURITY_PASSWORD_SALT = os.getenv("SECURITY_PASSWORD_SALT", "change-me")
    MAIL_SERVER = os.getenv("MAIL_SERVER", "localhost")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 8025))
    MAIL_USE_TLS = False
    MAIL_USE_SSL = False
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "no-reply@securebank.local")


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = 'https'
    # Any other production‑level tweaks


CONFIGS = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
}

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def init_logger(app: Flask) -> None:
    """Attach rotating file handler for security audit logs."""
    if not os.path.exists('logs'):
        os.mkdir('logs')
    handler = logging.handlers.RotatingFileHandler(
        'logs/audit.log', maxBytes=256_000, backupCount=5
    )
    handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s'
    ))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)


def generate_fernet_key(path: str = 'instance/encryption_key.key') -> bytes:
    if os.path.exists(path):
        with open(path, 'rb') as fp:
            return fp.read()
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as fp:
        fp.write(key)
    return key


cipher: Optional[Fernet] = None  # Assigned in create_app

# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), unique=True, index=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    balance = db.Column(db.Float, default=0.0, nullable=False)
    _credit_card = db.Column('credit_card', db.LargeBinary, nullable=True)
    otp_secret = db.Column(db.String(16), nullable=False, default=pyotp.random_base32)
    is_active = db.Column(db.Boolean, default=True)  # Soft‑delete flag

    transactions = db.relationship('Transaction', backref='owner', lazy=True)

    # ─── property helpers ────────────────────────────────────────────────
    @property
    def credit_card(self) -> str | None:  # Decrypted representation
        if self._credit_card is None:
            return None
        try:
            return cipher.decrypt(self._credit_card).decode()
        except (InvalidToken, AttributeError):
            return None

    @credit_card.setter
    def credit_card(self, plaintext: str) -> None:
        self._credit_card = cipher.encrypt(plaintext.encode())

    def get_totp_uri(self) -> str:
        return pyotp.totp.TOTP(self.otp_secret).provisioning_uri(name=self.username, issuer_name="SecureBank")


class Transaction(db.Model):
    __tablename__ = 'transactions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # deposit, withdraw, transfer
    description = db.Column(db.String(255))


# ---------------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------------


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    credit_card = StringField('Credit Card', validators=[DataRequired(), Length(min=16, max=16)])
    submit = SubmitField('Sign Up')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken.')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class OTPForm(FlaskForm):
    otp = StringField('One‑Time Password', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')


class DepositForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    submit = SubmitField('Deposit')


class WithdrawForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    submit = SubmitField('Withdraw')


class TransferForm(FlaskForm):
    recipient = StringField('Recipient Username', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    submit = SubmitField('Transfer')


# ---------------------------------------------------------------------------
# App factory & blueprints
# ---------------------------------------------------------------------------

def create_app(config_name: str | None = None) -> Flask:
    """Application factory."""
    global cipher

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(CONFIGS.get(config_name or os.getenv('FLASK_ENV', 'development')))

    # Initialise extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    Talisman(app, content_security_policy=CSP)

    cipher = Fernet(generate_fernet_key(app.instance_path + '/encryption_key.ke'))

    # Logging setup
    init_logger(app)

    # User loader
    @login_manager.user_loader
    def load_user(user_id: str):  # pragma: no cover
        return User.query.get(int(user_id))

    # Register blueprints
    from flask import Blueprint

    auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
    bank_bp = Blueprint('bank', __name__, url_prefix='/bank')
    admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

    # ───── auth routes ───────────────────────────────────────────────────
    @auth_bp.route('/register', methods=['GET', 'POST'])
    @limiter.limit("5/minute")
    def register():
        form = RegistrationForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode()
            user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password,
            )
            user.credit_card = form.credit_card.data
            db.session.add(user)
            db.session.commit()
            qr = generate_qr_code(user)
            return render_template('auth/show_qr.html', qr_code=qr)
        return render_template('auth/register.html', form=form)

    @auth_bp.route('/login', methods=['GET', 'POST'])
    @limiter.limit("10/minute")
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                current_app.logger.info('User logged in', extra={'remote_addr': request.remote_addr})
                return redirect(url_for('auth.verify'))
            flash('Invalid username or password.', 'danger')
        return render_template('auth/login.html', form=form)

    @auth_bp.route('/verify', methods=['GET', 'POST'])
    @login_required
    def verify():
        if current_user.is_admin:
            return redirect(url_for('bank.dashboard'))

        form = OTPForm()
        if form.validate_on_submit():
            if pyotp.TOTP(current_user.otp_secret).verify(form.otp.data):
                flash('Successfully verified.', 'success')
                return redirect(url_for('bank.dashboard'))
            flash('Invalid OTP.', 'danger')
        return render_template('auth/verify.html', form=form)

    @auth_bp.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Logged out successfully.', 'info')
        return redirect(url_for('auth.login'))

    # ───── bank routes ───────────────────────────────────────────────────
    @bank_bp.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('bank/dashboard.html')

    @bank_bp.route('/deposit', methods=['GET', 'POST'])
    @login_required
    def deposit():
        form = DepositForm()
        if form.validate_on_submit():
            amount = form.amount.data
            current_user.balance += amount
            db.session.add(Transaction(user_id=current_user.id, amount=amount, type='deposit'))
            db.session.commit()
            flash(f'Deposited ₪{amount:.2f}', 'success')
            return redirect(url_for('bank.dashboard'))
        return render_template('bank/deposit.html', form=form)

    @bank_bp.route('/withdraw', methods=['GET', 'POST'])
    @login_required
    def withdraw():
        form = WithdrawForm()
        if form.validate_on_submit():
            amount = form.amount.data
            if amount > current_user.balance:
                flash('Insufficient funds.', 'danger')
                return redirect(url_for('bank.withdraw'))
            current_user.balance -= amount
            db.session.add(Transaction(user_id=current_user.id, amount=-amount, type='withdraw'))
            db.session.commit()
            flash(f'Withdrew ₪{amount:.2f}', 'success')
            return redirect(url_for('bank.dashboard'))
        return render_template('bank/withdraw.html', form=form)

    @bank_bp.route('/transfer', methods=['GET', 'POST'])
    @login_required
    def transfer():
        form = TransferForm()
        if form.validate_on_submit():
            recipient = User.query.filter_by(username=form.recipient.data).first()
            amount = form.amount.data
            if not recipient:
                flash('Recipient not found.', 'danger')
            elif amount > current_user.balance:
                flash('Insufficient balance.', 'danger')
            else:
                current_user.balance -= amount
                recipient.balance += amount
                db.session.add(Transaction(user_id=current_user.id, amount=-amount, type='transfer', description=f'Transfer to {recipient.username}'))
                db.session.add(Transaction(user_id=recipient.id, amount=amount, type='transfer', description=f'Transfer from {current_user.username}'))
                db.session.commit()
                flash(f'Transferred ₪{amount:.2f} to {recipient.username}', 'success')
                return redirect(url_for('bank.dashboard'))
        return render_template('bank/transfer.html', form=form)

    @bank_bp.route('/transactions')
    @login_required
    def transactions():
        page = request.args.get('page', 1, type=int)
        paginated = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).paginate(page=page, per_page=10)
        return render_template('bank/transactions.html', transactions=paginated)

    # ───── admin routes ──────────────────────────────────────────────────
    @admin_bp.before_request
    def restrict_to_admin():
        if not (current_user.is_authenticated and current_user.is_admin):
            abort(403)

    @admin_bp.route('/users')
    def list_users():
        users = User.query.all()
        return render_template('admin/users.html', users=users)

    @admin_bp.route('/user_qr/<int:user_id>')
    def user_qr(user_id):
        user = User.query.get_or_404(user_id)
        buf = create_qr_image(user.get_totp_uri())
        return send_file(buf, mimetype='image/png')

    app.register_blueprint(auth_bp)
    app.register_blueprint(bank_bp)
    app.register_blueprint(admin_bp)

    # ───── index (root) ──────────────────────────────────────────────────
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("bank.dashboard"))
        return redirect(url_for("auth.login"))

    # ───── shell context processor — for flask shell ─────────────────────
    @app.shell_context_processor
    def shell_context():  # pragma: no cover
        return {'db': db, 'User': User, 'Transaction': Transaction}

    return app

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def generate_qr_code(user: User) -> str:
    uri = user.get_totp_uri()
    return base64.b64encode(create_qr_image(uri).getvalue()).decode()


def create_qr_image(data: str):
    img = qrcode.make(data)
    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf

# ---------------------------------------------------------------------------
# CLI entry‑point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # `FLASK_ENV` or command‑line argument chooses config
    app_env = os.getenv('FLASK_ENV', 'development')
    app = create_app(app_env)
    with app.app_context():
        db.create_all()
        # Create default admin if not existing
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@securebank.local',
                password=bcrypt.generate_password_hash('adminpassword').decode(),
                is_admin=True,
            )
            admin.credit_card = '0000000000000000'
            db.session.add(admin)
            db.session.commit()
    app.run(host='127.0.0.1', port=5001, ssl_context='adhoc')
