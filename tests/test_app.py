import re
import tempfile
import unittest
from pathlib import Path

from werkzeug.security import generate_password_hash

from app import create_app
from models import connect_db


class PlatformTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = str(Path(self.temp_dir.name) / "test.sqlite3")
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "DATABASE": database,
                "ADMIN_USERNAME": "owner",
                "ADMIN_PASSWORD_HASH": generate_password_hash("a-long-test-password"),
            }
        )
        self.client = self.app.test_client()
        self.database = database

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf(self, client=None, path="/login"):
        client = client or self.client
        with client.session_transaction() as current_session:
            token = current_session.get("csrf_token")
        if not token:
            if path.startswith("/admin"):
                token_path = "/admin/login"
            elif path == "/register":
                token_path = "/register"
            else:
                token_path = "/login"
            client.get(token_path)
            with client.session_transaction() as current_session:
                token = current_session.get("csrf_token")
        self.assertTrue(token)
        return token

    def post(self, path, data, client=None):
        client = client or self.client
        data = dict(data)
        data["csrf_token"] = self.csrf(client, path)
        return client.post(path, data=data, follow_redirects=True)

    def register_user(self):
        response = self.post(
            "/register",
            {
                "phone": "01 23 45 67 89",
                "network": "MTN",
                "password": "a-long-user-password",
            },
        )
        self.assertEqual(response.status_code, 200)
        return response

    def admin_login(self):
        client = self.app.test_client()
        response = self.post(
            "/admin/login",
            {"username": "owner", "password": "a-long-test-password"},
            client,
        )
        self.assertEqual(response.status_code, 200)
        return client

    def add_task(self, client, mode="exact", expected="réponse juste"):
        return self.post(
            "/admin/tasks",
            {
                "prompt": "Effectuez la tâche de démonstration.",
                "validation_mode": mode,
                "expected_answer": expected if mode == "exact" else "",
            },
            client,
        )

    def test_exact_task_is_credited_once_and_ticket_limit_is_five(self):
        admin = self.admin_login()
        for number in range(6):
            self.post(
                "/admin/tasks",
                {
                    "prompt": f"Tâche de démonstration {number}",
                    "validation_mode": "exact",
                    "expected_answer": "réponse juste",
                },
                admin,
            )
        self.register_user()
        self.post("/tickets/take", {"count": "5"})
        with self.app.app_context():
            db = connect_db(self.database)
            try:
                assignments = db.execute(
                    "SELECT id FROM assignments ORDER BY id"
                ).fetchall()
                self.assertEqual(len(assignments), 5)
                first_id = assignments[0]["id"]
            finally:
                db.close()
        self.post(
            f"/tickets/{first_id}/submit",
            {"answer": "RÉPONSE JUSTE"},
        )
        self.post("/tickets/take", {"count": "5"})
        with self.app.app_context():
            db = connect_db(self.database)
            try:
                balance = db.execute(
                    "SELECT balance_fcfa FROM users"
                ).fetchone()["balance_fcfa"]
                active = db.execute(
                    """
                    SELECT COUNT(*) AS n FROM assignments
                    WHERE status IN ('assigned', 'pending_review')
                    """
                ).fetchone()["n"]
                self.assertEqual(balance, 90)
                self.assertEqual(active, 5)
                self.assertEqual(
                    db.execute(
                        "SELECT COUNT(*) AS n FROM wallet_ledger WHERE event_type = 'task_reward'"
                    ).fetchone()["n"],
                    1,
                )
            finally:
                db.close()

    def test_manual_review_credits_only_after_admin_approval(self):
        admin = self.admin_login()
        self.add_task(admin, mode="manual")
        with self.app.app_context():
            db = connect_db(self.database)
            try:
                db.execute("PRAGMA ignore_check_constraints = ON")
                db.execute(
                    "UPDATE tasks SET expected_answer = ?",
                    ("une réponse différente",),
                )
            finally:
                db.close()
        self.register_user()
        self.post("/tickets/take", {"count": "1"})
        with self.app.app_context():
            db = connect_db(self.database)
            try:
                assignment_id = db.execute(
                    "SELECT id FROM assignments"
                ).fetchone()["id"]
            finally:
                db.close()
        submitted_answer = "Une réponse de démonstration"
        self.post(
            f"/tickets/{assignment_id}/submit",
            {"answer": submitted_answer},
        )
        with self.app.app_context():
            db = connect_db(self.database)
            try:
                assignment = db.execute(
                    "SELECT status, answer FROM assignments WHERE id = ?",
                    (assignment_id,),
                ).fetchone()
                balance = db.execute(
                    "SELECT balance_fcfa FROM users"
                ).fetchone()["balance_fcfa"]
                self.assertEqual(assignment["status"], "pending_review")
                self.assertEqual(assignment["answer"], submitted_answer)
                self.assertEqual(balance, 0)
            finally:
                db.close()
        admin_page = admin.get("/admin")
        self.assertIn(submitted_answer.encode(), admin_page.data)
        admin_response = self.post(
            f"/admin/reviews/{assignment_id}/approve",
            {},
            admin,
        )
        self.assertEqual(admin_response.status_code, 200)
        with self.app.app_context():
            db = connect_db(self.database)
            try:
                self.assertEqual(
                    db.execute("SELECT balance_fcfa FROM users").fetchone()["balance_fcfa"],
                    90,
                )
            finally:
                db.close()

    def test_withdrawal_debits_then_rejection_refunds_once(self):
        self.register_user()
        with self.app.app_context():
            db = connect_db(self.database)
            try:
                db.execute("UPDATE users SET balance_fcfa = 1200")
            finally:
                db.close()
        self.post("/withdrawals", {"amount": "1000"})
        with self.app.app_context():
            db = connect_db(self.database)
            try:
                self.assertEqual(
                    db.execute("SELECT balance_fcfa FROM users").fetchone()["balance_fcfa"],
                    200,
                )
                withdrawal_id = db.execute(
                    "SELECT id FROM withdrawals"
                ).fetchone()["id"]
            finally:
                db.close()
        admin = self.admin_login()
        self.post(
            f"/admin/withdrawals/{withdrawal_id}/reject",
            {},
            admin,
        )
        self.post(
            f"/admin/withdrawals/{withdrawal_id}/reject",
            {},
            admin,
        )
        with self.app.app_context():
            db = connect_db(self.database)
            try:
                self.assertEqual(
                    db.execute("SELECT balance_fcfa FROM users").fetchone()["balance_fcfa"],
                    1200,
                )
                refunds = db.execute(
                    """
                    SELECT COUNT(*) AS n FROM wallet_ledger
                    WHERE event_type = 'withdrawal_refund' AND reference_id = ?
                    """,
                    (withdrawal_id,),
                ).fetchone()["n"]
                self.assertEqual(refunds, 1)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
