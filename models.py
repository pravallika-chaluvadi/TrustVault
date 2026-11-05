
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


# 1. USER TABLE
class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80), unique=True, nullable=False
    )

    password = db.Column(
        db.String(255), nullable=False
    )

    role = db.Column(
        db.String(20), default="Owner", nullable=False
    )

    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )

    documents = db.relationship(
        "Document",
        back_populates="owner",
        cascade="all, delete-orphan"
    )

    permissions = db.relationship(
        "Permission",
        back_populates="user",
        cascade="all, delete-orphan"
    )


# 2. DOCUMENT TABLE
class Document(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    filename = db.Column(
        db.String(255), nullable=False
    )

    stored_filename = db.Column(
        db.String(255), unique=True, nullable=False
    )

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    uploaded_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )

    owner = db.relationship(
        "User",
        back_populates="documents"
    )

    permissions = db.relationship(
        "Permission",
        back_populates="document",
        cascade="all, delete-orphan"
    )


# 3. PERMISSION TABLE
class Permission(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id"),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    access_type = db.Column(
        db.String(20), default="Read", nullable=False
    )

    document = db.relationship(
        "Document",
        back_populates="permissions"
    )

    user = db.relationship(
        "User",
        back_populates="permissions"
    )


# 4. AUDIT LOG TABLE
class AuditLog(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, nullable=True
    )

    action = db.Column(
        db.String(100), nullable=False
    )

    document_id = db.Column(
        db.Integer, nullable=True
    )

    details = db.Column(
        db.String(255)
    )

    timestamp = db.Column(
        db.DateTime, default=datetime.utcnow
    )
