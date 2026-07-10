from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os
import requests
import json
import urllib.parse 
import uuid
# Load Scanner Manager and Mock fallback
from scanner import ScanManager, ScanJob

try:
    from analyzer import analyze_repository
except ImportError:
    # Fallback mock if file missing
    def analyze_repository(url):
        return {
            "projectName": "Demo-Project",
            "healthScore": {"grade": "B", "status": "Good"},
            "issueCounts": {"security": 1, "bugs": 3, "performance": 2, "codeSmells": 4},
            "priorityIssues": [],
            "bugTrend": {"critical": [1,0,0,0,0], "major": [2,1,0,0,0]}
        }

import random
import secrets
import re
from datetime import datetime, timedelta, timezone

# --- App Initialization ---
load_dotenv()
app = Flask(__name__, template_folder='templates', static_folder='static')

# --- Configurations ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'bug-hawk-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bughawk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail Config
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('BugHawk Team', os.environ.get('MAIL_USERNAME'))

# --- Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
oauth = OAuth(app)

# --- Configure GitHub OAuth ---
github = oauth.register(
    name='github',
    client_id=os.environ.get('GITHUB_CLIENT_ID'),
    client_secret=os.environ.get('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.unauthorized_handler
def unauthorized_callback():
    if request.is_json:
        return jsonify({'error': 'You must be logged in to perform this action.'}), 401
    flash('Please log in to access this page.', 'info')
    return redirect(url_for('login'))

# --- Custom Filters ---
@app.template_filter('from_json')
def from_json_filter(value):
    """Parses a JSON string into a Python dictionary."""
    if not value: return {}
    try: return json.loads(value)
    except (TypeError, json.JSONDecodeError): return value if isinstance(value, dict) else {}

@app.template_filter('time_ago')
def time_ago_filter(dt):
    if not dt: return "Never"
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    diff = now - dt
    if diff.days > 365: return f"{diff.days // 365} year(s) ago"
    if diff.days > 30: return f"{diff.days // 30} month(s) ago"
    if diff.days > 0: return f"{diff.days} day(s) ago"
    if diff.seconds > 3600: return f"{diff.seconds // 3600} hour(s) ago"
    if diff.seconds > 60: return f"{diff.seconds // 60} minute(s) ago"
    return "Just now"

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    github_id = db.Column(db.String(100), unique=True, nullable=True)
    full_name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=True)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    otp = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    date_created = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Profile Fields
    username = db.Column(db.String(50), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    timezone = db.Column(db.String(50), default='UTC')
    experience_level = db.Column(db.String(20), default='Intermediate')
    github_link = db.Column(db.String(200), nullable=True)
    linkedin_link = db.Column(db.String(200), nullable=True)
    portfolio_link = db.Column(db.String(200), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    
    analyses = db.relationship('Analysis', backref='owner', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"User('{self.email}')"

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_name = db.Column(db.String(150), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    health_score_grade = db.Column(db.String(2), default='C')
    health_score_status = db.Column(db.String(50), default='Needs Improvement')
    issue_counts = db.Column(db.Text, default='{}')
    priority_issues = db.Column(db.Text, default='[]')
    bug_trend = db.Column(db.Text, default='{}')
    full_report_text = db.Column(db.Text, nullable=True) 

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    date_sent = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- OTP Logic ---
def send_otp_email(user):
    otp = str(random.randint(100000, 999999))
    expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    user.otp = otp
    user.otp_expiry = expiry
    db.session.commit()
    
    # Log to console for testing (or use Mail for prod)
    print(f"\n[OTP SENT] To: {user.email} | Code: {otp}\n")
    
    if app.config['MAIL_USERNAME']: # Only try sending if config exists
        try:
            msg = Message(
                subject="Your BugHawk Verification Code",
                recipients=[user.email],
                body=f"Hello,\n\nYour verification code is: {otp}\nIt expires in 10 minutes.\n\n- BugHawk Team"
            )
            mail.send(msg)
        except Exception as e:
            print(f"Error sending email: {e}")

# --- Core Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch user's history
    all_analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.timestamp.desc()).all()
    
    # Check for new results passed via URL (from analyze route)
    results_str = request.args.get('results')
    current_analysis_data = {}
    
    if results_str:
        try:
            current_analysis_data = json.loads(urllib.parse.unquote(results_str))
        except: pass
    elif all_analyses:
        # Construct data from the latest DB entry
        latest = all_analyses[0]
        current_analysis_data = {
            "projectName": latest.project_name,
            "healthScore": {"grade": latest.health_score_grade, "status": latest.health_score_status},
            "issueCounts": json.loads(latest.issue_counts),
            "priorityIssues": json.loads(latest.priority_issues),
            "bugTrend": json.loads(latest.bug_trend)
        }

    return render_template('dashboard.html', 
                           current_analysis=current_analysis_data, 
                           all_analyses=all_analyses)

@app.route('/analysis/<int:analysis_id>')
@login_required
def view_analysis(analysis_id):
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis or analysis.owner != current_user:
        abort(403)
    
    all_analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.timestamp.desc()).all()
    
    # Reconstruct the data object for the template
    current_analysis_data = {
        "projectName": analysis.project_name,
        "healthScore": {"grade": analysis.health_score_grade, "status": analysis.health_score_status},
        "issueCounts": json.loads(analysis.issue_counts),
        "priorityIssues": json.loads(analysis.priority_issues),
        "bugTrend": json.loads(analysis.bug_trend)
    }
    
    return render_template('dashboard.html', 
                           current_analysis=current_analysis_data, 
                           all_analyses=all_analyses)

@app.route('/analyze', methods=['POST'])
@login_required 
def analyze_route():
    repo_url = request.get_json().get('url')
    if not repo_url: return jsonify({'error': 'URL required'}), 400

    # 1. Run Analysis with ScanManager
    try:
        print(f"Initiating deterministic repository scan for: {repo_url}")
        job = ScanJob(
            job_id=str(uuid.uuid4()),
            repository_url=repo_url,
            status="PENDING",
            created_at=datetime.now(timezone.utc).isoformat()
        )
        manager = ScanManager()
        report = manager.run_analysis(repo_url, job=job)
        analysis_results = report.to_dict()
    except Exception as e:
        print(f"Deterministic scan failed: {e}. Falling back to mock analyzer.")
        analysis_results = analyze_repository(repo_url)
    
    # 2. Save to DB
    try:
        new_analysis = Analysis(
            user_id=current_user.id,
            project_name=analysis_results.get('projectName', 'Unknown'),
            health_score_grade=analysis_results.get('healthScore', {}).get('grade', 'C'),
            health_score_status=analysis_results.get('healthScore', {}).get('status', 'Unknown'),
            # Save individual JSON fields
            issue_counts=json.dumps(analysis_results.get('issueCounts', {})),
            priority_issues=json.dumps(analysis_results.get('priorityIssues', [])),
            bug_trend=json.dumps(analysis_results.get('bugTrend', {})),
            full_report_text=analysis_results.get('full_report_text', '')
        )
        db.session.add(new_analysis)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"DB Save Error: {e}")
        return jsonify({'error': 'Database error'}), 500
    
    # 3. Redirect
    # Pass results in URL so dashboard renders them immediately without fetch delay
    results_str = urllib.parse.quote(json.dumps(analysis_results))
    return jsonify({'redirect_url': url_for('dashboard', results=results_str)})

# --- Auth Routes ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')

        # Password Validation
        if not password or len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('signup.html')
        if not re.search(r"[a-zA-Z]", password):
            flash('Password must contain at least one letter.', 'danger')
            return render_template('signup.html')
        if not re.search(r"\d", password):
            flash('Password must contain at least one number.', 'danger')
            return render_template('signup.html')
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            flash('Password must contain at least one special symbol.', 'danger')
            return render_template('signup.html')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if not existing_user.is_verified:
                send_otp_email(existing_user)
                session['email_for_verification'] = existing_user.email
                flash('Account exists but unverified. New OTP sent.', 'info')
                return redirect(url_for('verify_otp'))
            flash('Email already registered.', 'danger')
            return redirect(url_for('login'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password_hash=hashed_pw, full_name=full_name)
        db.session.add(new_user)
        db.session.commit()
        
        send_otp_email(new_user)
        session['email_for_verification'] = new_user.email
        flash('Account created! Check email for OTP.', 'info')
        return redirect(url_for('verify_otp'))

    return render_template('signup.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('email_for_verification')
    if not email:
        return redirect(url_for('signup'))

    user = User.query.filter_by(email=email).first()
    if not user:
        return redirect(url_for('signup'))
        
    if request.method == 'POST':
        otp_attempt = request.form.get('otp')
        
        # Timezone-aware comparison
        now_utc = datetime.now(timezone.utc)
        expiry_check = user.otp_expiry
        if expiry_check and expiry_check.tzinfo is None:
            expiry_check = expiry_check.replace(tzinfo=timezone.utc)
            
        if (user.otp == otp_attempt and user.otp_expiry and expiry_check > now_utc):
            user.is_verified = True
            user.otp = None
            user.otp_expiry = None
            db.session.commit()
            login_user(user)
            flash('Verified! Logged in.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid or expired OTP.', 'danger')

    return render_template('verify_otp.html', email=email)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.password_hash and bcrypt.check_password_hash(user.password_hash, password):
            if not user.is_verified:
                flash('Account not verified. Sending new OTP...', 'warning')
                send_otp_email(user)
                session['email_for_verification'] = user.email
                return redirect(url_for('verify_otp'))
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(request.args.get('next') or url_for('dashboard'))
        else:
            flash('Login failed. Check credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# --- Other Pages ---
@app.route('/reports')
@login_required
def reports():
    # 1. Fetch existing reports
    all_analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.timestamp.desc()).all()

    # 2. DEMO DATA GENERATOR (If list is empty)
    if not all_analyses:
        demo_text = """
EXECUTIVE SUMMARY:
The BugHawk AI engine performed a full multi-layer scan of the project 'VIT-Student-Portal'.
The analysis combined static AST checks, ML-based vulnerability classification, 
and predictive modeling using commit history.

Overall, the project displays moderate security posture but contains several critical issues 
that require immediate attention.

----------------------------------------------------------------
CRITICAL SECURITY ISSUES (High Severity):
1. SQL Injection vulnerability detected in: controllers/auth.py (line 42)
   - Cause: User input directly concatenated into SQL query.
   - Risk: Full authentication bypass and data exfiltration.
   - Recommendation: Use parameterized queries or ORM bindings.

2. Unsanitized HTML output (XSS) found in: templates/profile.html
   - Cause: User-controlled variables injected into HTML without escaping.
   - Risk: Session hijacking and credential theft.
   - Recommendation: Use Jinja2 autoescape and validation filters.

----------------------------------------------------------------
BUGS & LOGIC ERRORS:
1. Null reference exception possible in utils/email.py (line 16)
   - Cause: Missing check for 'user_email' before calling send().

2. Inefficient O(n^2) loop inside attendance_summary.py
   - Recommendation: Replace nested loops with dictionary-based indexing.

----------------------------------------------------------------
PERFORMANCE ISSUES:
1. Unoptimized DB query detected in student_dashboard.py
   - Multiple repeated SELECT calls inside loop (N+1 problem).
   - Suggestion: Use JOINs or bulk_fetch.

2. Static resources not cached (JS + CSS)
   - Add 'Cache-Control' headers for performance improvement.

----------------------------------------------------------------
CODE SMELLS:
- 5 functions exceed recommended cyclomatic complexity > 12
- Deprecated method 'os.popen()' used in utils/system.py
- 4 files missing docstrings
- Hard-coded constants in multiple locations

----------------------------------------------------------------
FINAL RECOMMENDATION:
The project is functional but at moderate risk ("B-" grade).
Immediate patching of SQLi + XSS vulnerabilities is strongly recommended.
Refactor identified hotspots and enforce secure coding practices.

Generated by BugHawk Prototype AI v1.0
----------------------------------------------------------------
"""

        
        demo_report = Analysis(
            user_id=current_user.id,
            project_name="VIT-Student-Portal",
            health_score_grade="B-",
            health_score_status="Vulnerable",
            issue_counts=json.dumps({"security": 2, "bugs": 1, "performance": 3, "codeSmells": 5}),
            full_report_text=demo_text,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(demo_report)
        db.session.commit()
        all_analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.timestamp.desc()).all()

    return render_template('reports.html', all_analyses=all_analyses)

@app.route('/chat')
@login_required
def chat(): return render_template('main.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name')
        current_user.username = request.form.get('username')
        current_user.phone = request.form.get('phone')
        current_user.timezone = request.form.get('timezone')
        current_user.experience_level = request.form.get('experience')
        current_user.github_link = request.form.get('github')
        current_user.linkedin_link = request.form.get('linkedin')
        current_user.two_factor_enabled = '2fa_toggle' in request.form
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        flash('Settings saved!', 'success')
    return render_template('settings.html')

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old = request.form.get('old_password')
    new = request.form.get('new_password')
    confirm = request.form.get('confirm_password')

    if current_user.password_hash:
        if not old or not bcrypt.check_password_hash(current_user.password_hash, old):
            flash('Old password incorrect.', 'danger')
            return redirect(url_for('settings'))

    if not new or len(new) < 8:
        flash('New password must be 8+ chars.', 'danger')
        return redirect(url_for('settings'))

    if new != confirm:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('settings'))

    current_user.password_hash = bcrypt.generate_password_hash(new).decode('utf-8')
    db.session.commit()
    flash('Password changed.', 'success')
    return redirect(url_for('settings'))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        new_msg = ContactMessage(
            name=request.form.get('full_name'),
            email=request.form.get('email'),
            subject=request.form.get('subject'),
            message=request.form.get('message')
        )
        db.session.add(new_msg)
        db.session.commit()
        flash('Message sent!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route('/users')
def view_users():
    return render_template('users.html', users=User.query.all(), messages=ContactMessage.query.all())

@app.route('/about')
def about(): return render_template('about.html')

# --- API Endpoints ---

@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    user_query = request.get_json().get('prompt')
    if not user_query: return jsonify({'error': 'Prompt required'}), 400

    API_KEY = os.environ.get('GEMINI_API_KEY')
    if not API_KEY:
        # Fallback mock response if no key
        return jsonify({'text': f"**BugHawk AI (Mock):** I received: `{user_query[:20]}...`. Configure API Key for real analysis."})
        
    API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key={API_KEY}"
    payload = { "contents": [{"parts": [{"text": user_query}]}] }
    
    try:
        response = requests.post(API_URL, headers={'Content-Type': 'application/json'}, json=payload)
        response.raise_for_status()
        result = response.json()
        text = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', "No response.")
        return jsonify({'text': text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat/save_report', methods=['POST'])
@login_required
def save_chat_report():
    data = request.json
    full_text = f"CODE:\n{data.get('code')}\n\nANALYSIS:\n{data.get('analysis')}"
    new_report = Analysis(
        user_id=current_user.id,
        project_name=f"Chat Analysis {datetime.now().strftime('%H:%M')}",
        health_score_grade='B',
        issue_counts=json.dumps({"bugs":1, "security":0}),
        full_report_text=full_text
    )
    db.session.add(new_report)
    db.session.commit()
    return jsonify({'status': 'success'})

# --- Settings API ---
@app.route('/api/settings/clear_history', methods=['POST'])
@login_required
def clear_history_api(): return jsonify({'status': 'success'})

@app.route('/api/settings/reset_memory', methods=['POST'])
@login_required
def reset_memory_api(): return jsonify({'status': 'success'})

@app.route('/api/settings/restore_defaults', methods=['POST'])
@login_required
def restore_defaults_api(): return jsonify({'status': 'success'})

@app.route('/api/profile/logout_devices', methods=['POST'])
@login_required
def logout_devices_api(): 
    session.clear()
    return jsonify({'status': 'success'})

# --- GitHub Auth ---
@app.route('/login/github')
def login_github():
    redirect_uri = url_for('authorize_github', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/auth/github/callback')
def authorize_github():
    try:
        token = github.authorize_access_token()
        resp = github.get('user')
        profile = resp.json()
        email_resp = github.get('user/emails')
        emails = email_resp.json()
        primary_email = next((e['email'] for e in emails if e['primary']), None)
        
        if not primary_email:
            flash('No verified email on GitHub.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=primary_email).first()
        if not user:
             # Create new user via GitHub
            user = User(
                email=primary_email,
                full_name=profile.get('name'),
                github_id=str(profile['id']),
                password_hash=bcrypt.generate_password_hash(secrets.token_hex(16)).decode('utf-8'),
                is_verified=True
            )
            db.session.add(user)
            db.session.commit()
        
        if not user.github_id:
            user.github_id = str(profile['id'])
            db.session.commit()

        login_user(user)
        return redirect(url_for('dashboard'))

    except Exception as e:
        print(f"GitHub Auth Error: {e}")
        flash('GitHub auth failed.', 'danger')
        return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)