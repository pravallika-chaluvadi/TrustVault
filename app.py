
import os
import uuid

from flask import (
    Flask, render_template_string, request, redirect,
    url_for, flash, send_from_directory, abort
)

from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from models import db, User, Document, Permission, AuditLog


# --------------------------------
# 1. APPLICATION CONFIGURATION
# --------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "trustvault-development-secret-change-before-deployment"
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///trustvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

UPLOAD_FOLDER = os.path.join(app.root_path, "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {
    "pdf", "txt", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx",
    "png", "jpg", "jpeg"
}

db.init_app(app)


# --------------------------------
# 2. LOGIN CONFIGURATION
# --------------------------------

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --------------------------------
# 3. HELPER FUNCTIONS
# --------------------------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def log_activity(action, document_id=None, details=""):
    log = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        document_id=document_id,
        details=details
    )

    db.session.add(log)
    db.session.commit()


def get_document(document_id):
    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    return document


def can_read_document(document):
    if document.owner_id == current_user.id:
        return True

    permission = Permission.query.filter_by(
        document_id=document.id,
        user_id=current_user.id
    ).first()

    return permission is not None and permission.access_type in [
        "Read", "Edit"
    ]


def can_edit_document(document):
    if document.owner_id == current_user.id:
        return True

    permission = Permission.query.filter_by(
        document_id=document.id,
        user_id=current_user.id
    ).first()

    return permission is not None and permission.access_type == "Edit"


def require_owner(document):
    if document.owner_id != current_user.id:
        abort(403)


# --------------------------------
# 4. COMMON HTML PAGE
# --------------------------------

BASE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }} - TrustVault</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f1f4f9;
            margin: 0;
            padding: 0;
        }

        header {
            background: #172554;
            color: white;
            padding: 20px;
            text-align: center;
        }

        nav {
            background: #1e3a8a;
            padding: 15px;
            text-align: center;
        }

        nav a {
            color: white;
            margin: 10px;
            text-decoration: none;
        }

        .container {
            background: white;
            width: 90%;
            max-width: 1100px;
            margin: 30px auto;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px #ccc;
        }

        input, select, textarea {
            padding: 10px;
            margin: 8px 0;
            width: 95%;
            box-sizing: border-box;
        }

        button {
            background: #2563eb;
            color: white;
            padding: 10px 18px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }

        th {
            background: #dbeafe;
        }

        .message {
            color: #166534;
            margin: 10px 0;
        }

        .danger {
            color: #dc2626;
        }

        a {
            color: #1d4ed8;
        }
    </style>
</head>

<body>

<header>
    <h1>TrustVault</h1>
    <p>Secure Document Management System</p>
</header>

<nav>
    {% if current_user.is_authenticated %}
        <a href="{{ url_for('dashboard') }}">Dashboard</a>
        <a href="{{ url_for('audit_logs') }}">Audit Logs</a>

        {% if current_user.role == "Admin" %}
            <a href="{{ url_for('admin_users') }}">Admin Users</a>
        {% endif %}

        <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
        <a href="{{ url_for('home') }}">Home</a>
        <a href="{{ url_for('login') }}">Login</a>
        <a href="{{ url_for('register') }}">Register</a>
    {% endif %}
</nav>

<div class="container">

    {% with messages = get_flashed_messages() %}
        {% for message in messages %}
            <p class="message">{{ message }}</p>
        {% endfor %}
    {% endwith %}

    {{ content|safe }}

</div>

</body>
</html>
"""


def page(title, content):
    return render_template_string(
        BASE,
        title=title,
        content=content
    )


# --------------------------------
# 5. HOME PAGE
# --------------------------------

@app.route("/")
def home():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    content = """
        <h2>Welcome to TrustVault</h2>

        <p>
            TrustVault is a secure document management system
            that allows users to upload, download, share and
            manage documents.
        </p>

        <p>
            <a href="/register">Create Account</a>
        </p>

        <p>
            <a href="/login">Login to TrustVault</a>
        </p>
    """

    return page("Home", content)


# --------------------------------
# 6. USER REGISTRATION
# --------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter username and password.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:
            flash("Username already exists.")
            return redirect(url_for("register"))

        user = User(
            username=username,
            password=generate_password_hash(password),
            role="Owner"
        )

        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please login.")
        return redirect(url_for("login"))

    content = """
        <h2>Create Account</h2>

        <form method="POST">
            <label>Username</label>
            <input type="text" name="username" required>

            <label>Password</label>
            <input type="password" name="password" required
                   minlength="8">

            <button type="submit">Register</button>
        </form>
    """

    return page("Register", content)


# --------------------------------
# 7. USER LOGIN
# --------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(
            username=username
        ).first()

        if user and check_password_hash(user.password, password):

            login_user(user)

            log_activity("Login", details="User logged in")

            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")

    content = """
        <h2>User Login</h2>

        <form method="POST">
            <label>Username</label>
            <input type="text" name="username" required>

            <label>Password</label>
            <input type="password" name="password" required>

            <button type="submit">Login</button>
        </form>
    """

    return page("Login", content)


# --------------------------------
# 8. USER LOGOUT
# --------------------------------

@app.route("/logout")
@login_required
def logout():

    log_activity("Logout", details="User logged out")

    logout_user()

    flash("You have logged out successfully.")

    return redirect(url_for("login"))


# --------------------------------
# 9. DASHBOARD
# --------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    owned_documents = Document.query.filter_by(
        owner_id=current_user.id
    ).all()

    shared_permissions = Permission.query.filter_by(
        user_id=current_user.id
    ).all()

    shared_documents = []

    for permission in shared_permissions:

        document = db.session.get(
            Document, permission.document_id
        )

        if document:
            shared_documents.append(
                (document, permission.access_type)
            )

    content = """
        <h2>Welcome, {{ username }}</h2>

        <p>Your Role: {{ role }}</p>

        <h3>Upload Document</h3>

        <form method="POST" action="/upload"
              enctype="multipart/form-data">

            <input type="file" name="file" required>

            <button type="submit">Upload Document</button>
        </form>

        <h3>My Documents</h3>

        <table>
            <tr>
                <th>Document Name</th>
                <th>Upload Date</th>
                <th>Actions</th>
            </tr>

            {% for document in owned_documents %}
            <tr>
                <td>{{ document.filename }}</td>

                <td>{{ document.uploaded_at }}</td>

                <td>
                    <a href="{{ url_for(
                        'download_document',
                        document_id=document.id
                    ) }}">Download</a> |

                    <a href="{{ url_for(
                        'permissions',
                        document_id=document.id
                    ) }}">Share</a> |

                    <a href="{{ url_for(
                        'edit_document',
                        document_id=document.id
                    ) }}">Edit</a> |

                    <a href="{{ url_for(
                        'delete_document',
                        document_id=document.id
                    ) }}"
                    onclick="return confirm('Delete this document?')">
                        Delete
                    </a>
                </td>
            </tr>
            {% else %}
            <tr>
                <td colspan="3">No documents uploaded yet.</td>
            </tr>
            {% endfor %}
        </table>

        <h3>Documents Shared With Me</h3>

        <table>
            <tr>
                <th>Document Name</th>
                <th>Permission</th>
                <th>Action</th>
            </tr>

            {% for document, access in shared_documents %}
            <tr>
                <td>{{ document.filename }}</td>
                <td>{{ access }}</td>
                <td>
                    <a href="{{ url_for(
                        'download_document',
                        document_id=document.id
                    ) }}">Download</a>

                    {% if access == "Edit" %}
                        |
                        <a href="{{ url_for(
                            'edit_document',
                            document_id=document.id
                        ) }}">Edit</a>
                    {% endif %}
                </td>
            </tr>
            {% else %}
            <tr>
                <td colspan="3">No shared documents.</td>
            </tr>
            {% endfor %}
        </table>
    """

    rendered = render_template_string(
        content,
        username=current_user.username,
        role=current_user.role,
        owned_documents=owned_documents,
        shared_documents=shared_documents
    )

    return page("Dashboard", rendered)


# --------------------------------
# 10. UPLOAD DOCUMENT
# --------------------------------

@app.route("/upload", methods=["POST"])
@login_required
def upload_document():

    if "file" not in request.files:
        flash("Please select a file.")
        return redirect(url_for("dashboard"))

    file = request.files["file"]

    if file.filename == "":
        flash("No file selected.")
        return redirect(url_for("dashboard"))

    if not allowed_file(file.filename):
        flash("File type not allowed.")
        return redirect(url_for("dashboard"))

    original_filename = secure_filename(file.filename)

    if not original_filename:
        flash("Invalid filename.")
        return redirect(url_for("dashboard"))

    stored_filename = str(uuid.uuid4()) + "_" + original_filename

    file.save(
        os.path.join(UPLOAD_FOLDER, stored_filename)
    )

    document = Document(
        filename=original_filename,
        stored_filename=stored_filename,
        owner_id=current_user.id
    )

    db.session.add(document)
    db.session.commit()

    log_activity(
        "Upload",
        document.id,
        "Uploaded " + original_filename
    )

    flash("Document uploaded successfully.")

    return redirect(url_for("dashboard"))


# --------------------------------
# 11. DOWNLOAD DOCUMENT
# --------------------------------

@app.route("/download/<int:document_id>")
@login_required
def download_document(document_id):

    document = get_document(document_id)

    if not can_read_document(document):
        abort(403)

    log_activity(
        "Download",
        document.id,
        "Downloaded " + document.filename
    )

    return send_from_directory(
        UPLOAD_FOLDER,
        document.stored_filename,
        as_attachment=True,
        download_name=document.filename
    )


# --------------------------------
# 12. EDIT TEXT DOCUMENT
# --------------------------------

@app.route("/edit/<int:document_id>", methods=["GET", "POST"])
@login_required
def edit_document(document_id):

    document = get_document(document_id)

    if not can_edit_document(document):
        abort(403)

    if not document.filename.lower().endswith(".txt"):
        flash("Only TXT files can be edited online.")
        return redirect(url_for("dashboard"))

    filepath = os.path.join(
        UPLOAD_FOLDER,
        document.stored_filename
    )

    if not os.path.isfile(filepath):
        abort(404)

    if request.method == "POST":

        new_content = request.form.get("content", "")

        with open(filepath, "w", encoding="utf-8") as file:
            file.write(new_content)

        log_activity(
            "Edit",
            document.id,
            "Edited " + document.filename
        )

        flash("Document updated successfully.")

        return redirect(url_for("dashboard"))

    with open(filepath, "r", encoding="utf-8") as file:
        file_content = file.read()

    content = """
        <h2>Edit Document: {{ filename }}</h2>

        <form method="POST">

            <textarea name="content" rows="15"
                      required>{{ file_content }}</textarea>

            <button type="submit">Save Changes</button>

        </form>
    """

    rendered = render_template_string(
        content,
        filename=document.filename,
        file_content=file_content
    )

    return page("Edit Document", rendered)


# --------------------------------
# 13. DELETE DOCUMENT
# --------------------------------

@app.route("/delete/<int:document_id>")
@login_required
def delete_document(document_id):

    document = get_document(document_id)

    require_owner(document)

    filepath = os.path.join(
        UPLOAD_FOLDER,
        document.stored_filename
    )

    filename = document.filename

    Permission.query.filter_by(
        document_id=document.id
    ).delete()

    AuditLog.query.filter_by(
        document_id=document.id
    ).update({
        "document_id": None
    })

    if os.path.isfile(filepath):
        os.remove(filepath)

    db.session.delete(document)
    db.session.commit()

    log_activity(
        "Delete",
        details="Deleted " + filename
    )

    flash("Document deleted successfully.")

    return redirect(url_for("dashboard"))


# --------------------------------
# 14. SHARE DOCUMENT
# --------------------------------

@app.route("/permissions/<int:document_id>", methods=["GET", "POST"])
@login_required
def permissions(document_id):

    document = get_document(document_id)

    require_owner(document)

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        access_type = request.form.get("access_type", "")

        if access_type not in ["Read", "Edit"]:
            flash("Invalid permission type.")
            return redirect(url_for(
                "permissions",
                document_id=document.id
            ))

        user = User.query.filter_by(
            username=username
        ).first()

        if not user:
            flash("User not found.")
            return redirect(url_for(
                "permissions",
                document_id=document.id
            ))

        if user.id == current_user.id:
            flash("You cannot share a document with yourself.")
            return redirect(url_for(
                "permissions",
                document_id=document.id
            ))

        permission = Permission.query.filter_by(
            document_id=document.id,
            user_id=user.id
        ).first()

        if permission:
            permission.access_type = access_type
        else:
            permission = Permission(
                document_id=document.id,
                user_id=user.id,
                access_type=access_type
            )

            db.session.add(permission)

        db.session.commit()

        log_activity(
            "Share",
            document.id,
            "Shared with " + username + " (" + access_type + ")"
        )

        flash("Document permission updated.")

        return redirect(url_for(
            "permissions",
            document_id=document.id
        ))

    existing_permissions = Permission.query.filter_by(
        document_id=document.id
    ).all()

    content = """
        <h2>Share Document: {{ filename }}</h2>

        <form method="POST">

            <label>Username</label>
            <input type="text" name="username" required>

            <label>Permission</label>

            <select name="access_type">
                <option value="Read">Read Only</option>
                <option value="Edit">Read and Edit</option>
            </select>

            <button type="submit">Share Document</button>

        </form>

        <h3>Existing Permissions</h3>

        <table>
            <tr>
                <th>User</th>
                <th>Access</th>
                <th>Action</th>
            </tr>

            {% for permission in permissions %}
            <tr>
                <td>{{ permission.username }}</td>
                <td>{{ permission.access_type }}</td>

                <td>
                    <a href="{{ url_for(
                        'revoke_permission',
                        permission_id=permission.id
                    ) }}"
                    onclick="return confirm('Revoke access?')">
                        Revoke
                    </a>
                </td>
            </tr>
            {% else %}
            <tr>
                <td colspan="3">No permissions granted.</td>
            </tr>
            {% endfor %}
        </table>
    """

    permission_details = []

    for permission in existing_permissions:

        user = db.session.get(User, permission.user_id)

        if user:
            permission_details.append({
                "id": permission.id,
                "username": user.username,
                "access_type": permission.access_type
            })

    rendered = render_template_string(
        content,
        filename=document.filename,
        permissions=permission_details
    )

    return page("Share Document", rendered)


# --------------------------------
# 15. REVOKE PERMISSION
# --------------------------------

@app.route("/revoke_permission/<int:permission_id>")
@login_required
def revoke_permission(permission_id):

    permission = db.session.get(Permission, permission_id)

    if permission is None:
        abort(404)

    document = get_document(permission.document_id)

    require_owner(document)

    username = db.session.get(
        User, permission.user_id
    ).username

    document_id = document.id

    db.session.delete(permission)
    db.session.commit()

    log_activity(
        "Revoke Permission",
        document_id,
        "Revoked access for " + username
    )

    flash("Document access revoked successfully.")

    return redirect(url_for(
        "permissions",
        document_id=document_id
    ))


# --------------------------------
# 16. AUDIT LOGS
# --------------------------------

@app.route("/audit_logs")
@login_required
def audit_logs():

    if current_user.role == "Admin":

        logs = AuditLog.query.order_by(
            AuditLog.id.desc()
        ).all()

    else:

        logs = AuditLog.query.filter_by(
            user_id=current_user.id
        ).order_by(AuditLog.id.desc()).all()

    content = """
        <h2>Audit Logs</h2>

        <p>Track activities performed in TrustVault.</p>

        <table>
            <tr>
                <th>User ID</th>
                <th>Action</th>
                <th>Document ID</th>
                <th>Details</th>
                <th>Time</th>
            </tr>

            {% for log in logs %}
            <tr>
                <td>{{ log.user_id }}</td>
                <td>{{ log.action }}</td>
                <td>{{ log.document_id }}</td>
                <td>{{ log.details }}</td>
                <td>{{ log.timestamp }}</td>
            </tr>
            {% else %}
            <tr>
                <td colspan="5">No audit logs available.</td>
            </tr>
            {% endfor %}
        </table>
    """

    rendered = render_template_string(
        content,
        logs=logs
    )

    return page("Audit Logs", rendered)


# --------------------------------
# 17. ADMIN USER MANAGEMENT
# --------------------------------

@app.route("/admin/users")
@login_required
def admin_users():

    if current_user.role != "Admin":
        abort(403)

    users = User.query.order_by(User.id).all()

    content = """
        <h2>Admin - User Management</h2>

        <table>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Role</th>
                <th>Created At</th>
            </tr>

            {% for user in users %}
            <tr>
                <td>{{ user.id }}</td>
                <td>{{ user.username }}</td>
                <td>{{ user.role }}</td>
                <td>{{ user.created_at }}</td>
            </tr>
            {% endfor %}
        </table>
    """

    rendered = render_template_string(
        content,
        users=users
    )

    return page("Admin Users", rendered)


# --------------------------------
# 18. ERROR HANDLING
# --------------------------------

@app.errorhandler(403)
def forbidden(error):

    return page(
        "Access Denied",
        """
        <h2 class="danger">403 - Access Denied</h2>
        <p>You do not have permission to access this resource.</p>
        """
    ), 403


@app.errorhandler(404)
def not_found(error):

    return page(
        "Not Found",
        """
        <h2 class="danger">404 - Page Not Found</h2>
        <p>The requested page or document does not exist.</p>
        """
    ), 404


@app.errorhandler(413)
def file_too_large(error):

    return page(
        "File Too Large",
        """
        <h2 class="danger">File Too Large</h2>
        <p>Maximum upload size is 16 MB.</p>
        """
    ), 413


# --------------------------------
# 19. RUN APPLICATION
# --------------------------------

if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True)
