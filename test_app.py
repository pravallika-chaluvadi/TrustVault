
import io
import uuid

import app as app_module
from app import app, db
from models import User, Document, Permission, AuditLog


def test_trustvault_complete_workflow(tmp_path, monkeypatch):

    app.config["TESTING"] = True

    # Create unique test usernames
    suffix = uuid.uuid4().hex[:8]
    owner_name = "tv_owner_" + suffix
    reader_name = "tv_reader_" + suffix

    # Use a temporary folder for test uploads
    test_upload_folder = tmp_path / "uploads"
    test_upload_folder.mkdir()

    monkeypatch.setattr(
        app_module, "UPLOAD_FOLDER", str(test_upload_folder)
    )

    owner_id = None
    reader_id = None
    document_ids = []

    with app.app_context():

        try:
            db.create_all()
            client = app.test_client()

            # TEST 1: Register two test users
            response = client.post("/register", data={
                "username": owner_name,
                "password": "password123"
            })
            assert response.status_code == 302

            response = client.post("/register", data={
                "username": reader_name,
                "password": "password123"
            })
            assert response.status_code == 302

            owner = User.query.filter_by(
                username=owner_name
            ).first()

            reader = User.query.filter_by(
                username=reader_name
            ).first()

            assert owner is not None
            assert reader is not None

            owner_id = owner.id
            reader_id = reader.id

            # TEST 2: Owner login
            response = client.post("/login", data={
                "username": owner_name,
                "password": "password123"
            })
            assert response.status_code == 302

            # TEST 3: Upload PDF
            response = client.post("/upload", data={
                "file": (
                    io.BytesIO(b"PDF test content"),
                    "sample.pdf"
                )
            }, content_type="multipart/form-data")

            assert response.status_code == 302

            # TEST 4: Upload editable TXT
            response = client.post("/upload", data={
                "file": (
                    io.BytesIO(b"Original document"),
                    "sample.txt"
                )
            }, content_type="multipart/form-data")

            assert response.status_code == 302

            # TEST 5: Upload private document
            response = client.post("/upload", data={
                "file": (
                    io.BytesIO(b"Private document"),
                    "private.pdf"
                )
            }, content_type="multipart/form-data")

            assert response.status_code == 302

            pdf = Document.query.filter_by(
                filename="sample.pdf",
                owner_id=owner_id
            ).first()

            txt = Document.query.filter_by(
                filename="sample.txt",
                owner_id=owner_id
            ).first()

            private_pdf = Document.query.filter_by(
                filename="private.pdf",
                owner_id=owner_id
            ).first()

            assert pdf is not None
            assert txt is not None
            assert private_pdf is not None

            document_ids.extend([
                pdf.id, txt.id, private_pdf.id
            ])

            # TEST 6: Share PDF with Read permission
            response = client.post(
                f"/permissions/{pdf.id}",
                data={
                    "username": reader_name,
                    "access_type": "Read"
                }
            )
            assert response.status_code == 302

            # TEST 7: Share TXT with Edit permission
            response = client.post(
                f"/permissions/{txt.id}",
                data={
                    "username": reader_name,
                    "access_type": "Edit"
                }
            )
            assert response.status_code == 302

            # Logout owner
            client.get("/logout")

            # TEST 8: Reader login
            response = client.post("/login", data={
                "username": reader_name,
                "password": "password123"
            })
            assert response.status_code == 302

            # TEST 9: Reader downloads shared PDF
            response = client.get(f"/download/{pdf.id}")
            assert response.status_code == 200

            # TEST 10: Reader edits shared TXT
            response = client.post(
                f"/edit/{txt.id}",
                data={
                    "content": "Edited successfully by reader"
                }
            )
            assert response.status_code == 302

            with open(
                test_upload_folder / txt.stored_filename,
                "r",
                encoding="utf-8"
            ) as file:
                assert file.read() == "Edited successfully by reader"

            # Logout reader
            client.get("/logout")

            # TEST 11: Owner revokes PDF permission
            client.post("/login", data={
                "username": owner_name,
                "password": "password123"
            })

            permission = Permission.query.filter_by(
                document_id=pdf.id,
                user_id=reader_id
            ).first()

            assert permission is not None

            response = client.get(
                f"/revoke_permission/{permission.id}"
            )
            assert response.status_code == 302

            client.get("/logout")

            # TEST 12: Reader tries to access revoked PDF
            client.post("/login", data={
                "username": reader_name,
                "password": "password123"
            })

            response = client.get(f"/download/{pdf.id}")
            assert response.status_code == 403

            # TEST 13: Reader tries to access private PDF
            response = client.get(
                f"/download/{private_pdf.id}"
            )
            assert response.status_code == 403

            # TEST 14: Reader still has Edit access to TXT
            response = client.get(f"/edit/{txt.id}")
            assert response.status_code == 200

            # TEST 15: Verify audit logs
            actions = [
                log.action for log in AuditLog.query.all()
                if log.user_id in [owner_id, reader_id]
            ]

            assert "Login" in actions
            assert "Upload" in actions
            assert "Share" in actions
            assert "Download" in actions
            assert "Edit" in actions
            assert "Revoke Permission" in actions
            assert "Logout" in actions

            print("\nALL TRUSTVAULT TESTS PASSED!")

        finally:

            # Remove only records created by this test
            user_ids = [
                user_id for user_id in [owner_id, reader_id]
                if user_id is not None
            ]

            if user_ids:
                Permission.query.filter(
                    Permission.user_id.in_(user_ids)
                ).delete(synchronize_session=False)

            if document_ids:
                Permission.query.filter(
                    Permission.document_id.in_(document_ids)
                ).delete(synchronize_session=False)

                AuditLog.query.filter(
                    AuditLog.document_id.in_(document_ids)
                ).delete(synchronize_session=False)

                Document.query.filter(
                    Document.id.in_(document_ids)
                ).delete(synchronize_session=False)

            if user_ids:
                AuditLog.query.filter(
                    AuditLog.user_id.in_(user_ids)
                ).delete(synchronize_session=False)

                User.query.filter(
                    User.id.in_(user_ids)
                ).delete(synchronize_session=False)

            db.session.commit()
            db.session.remove()
