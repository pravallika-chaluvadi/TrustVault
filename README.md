# TrustVault – Secure Document Management System

## 1. Project Overview

TrustVault is a web-based Secure Document Management System developed using Python and Flask. It allows users to upload, download, edit, share, and manage documents securely through role-based access permissions.

The system also maintains audit logs to track important user activities.

## 2. Features

- User registration and secure login
- Password hashing for account security
- Document upload and download
- Read-only and Edit permissions
- Secure document sharing between users
- Permission revocation
- Online editing of TXT documents
- Audit logs for tracking user activities
- Admin user management
- Unauthorized access protection
- File upload size and extension validation

## 3. Technologies Used

- **Programming Language:** Python
- **Backend Framework:** Flask
- **Database:** SQLite
- **ORM:** Flask-SQLAlchemy
- **Authentication:** Flask-Login
- **Password Security:** Werkzeug
- **Testing:** Pytest
- **Frontend:** HTML and CSS

## 4. Project Structure

```text
TrustVault/
│
├── app.py
├── models.py
├── test_app.py
├── trustvault.db
├── uploads/
├── venv/
└── README.md
```

## 5. Installation and Setup

### Step 1: Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd TrustVault
```

### Step 2: Create a virtual environment

```bash
python -m venv venv
```

### Step 3: Activate the environment

Windows:

```bash
venv\Scripts\activate
```

### Step 4: Install dependencies

```bash
pip install Flask Flask-Login Flask-SQLAlchemy pytest
```

### Step 5: Run the application

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

## 6. Automated Testing

TrustVault includes automated workflow testing using Pytest.

Run:

```bash
pytest -v test_app.py
```

The automated test checks:

- User registration and login
- Document uploading
- Read and Edit permissions
- Shared document downloading
- Document editing
- Permission revocation
- Unauthorized access prevention
- Audit log recording

**Latest test result:** 1 passed.

## 7. Security Features

- Passwords are stored using secure password hashing.
- Document access is checked on the server.
- Unauthorized document access is denied.
- Uploaded filenames are secured.
- File upload size is limited to 16 MB.
- User activities are recorded through audit logs.

## 8. Future Enhancements

- Email-based account verification
- Multi-factor authentication
- Support for more online document editing formats
- Advanced admin dashboard
- Improved deployment security
- Cloud-based document storage

## 9. Conclusion

TrustVault provides a simple and secure platform for document management and sharing. It combines authentication, access control, document operations, and activity tracking to improve document security and collaboration.

**Developed as a project for the Snovasys Fresher Hiring Challenge 2026.**
