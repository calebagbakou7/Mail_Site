import functools
import hmac
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from models import connect_db, initialize_database


MAX_ACTIVE_TICKETS = 5
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 Mo

# Statuts du flux en 4 étapes (statut -> étape numérique attendue)
STATUS_STEP = {
    "assigned": 1,
    "attente_justificatif": 2,
    "attente_cle": 3,
    "pending_review": 4,
}
# Un ticket occupe un emplacement tant qu'il est dans l'un de ces statuts.
ACTIVE_STATUSES_SQL = "('assigned', 'attente_justificatif', 'attente_cle', 'pending_review')"

CLOSING_KEY_RE = re.compile(r"^[A-Za-z0-9]{4,64}$")
ALLOWED_PROOF_EXTENSIONS = {"png": "png", "jpg": "jpg", "jpeg": "jpg"}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SIGNATURE = b"\xff\xd8\xff"
MAX_VALUE_LENGTH = 500
MAX_URL_LENGTH = 2000


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get(
            "DATABASE_PATH",
            str(Path(app.instance_path) / "crowdtasks.sqlite3"),
        ),
        ADMIN_USERNAME=os.environ.get("ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD_HASH=os.environ.get("ADMIN_PASSWORD_HASH"),
        COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 64 * 1024,
    )
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not app.config["ADMIN_PASSWORD_HASH"] and admin_password:
        app.config["ADMIN_PASSWORD_HASH"] = generate_password_hash(admin_password)
    if test_config:
        app.config.update(test_config)

    app.config.setdefault(
        "PROOF_UPLOAD_DIR",
        str(Path(app.static_folder) / "uploads" / "proofs"),
    )

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["PROOF_UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)
    initialize_database(app.config["DATABASE"])
    ensure_schema(app.config["DATABASE"])

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=app.config["COOKIE_SECURE"],
    )

    @app.before_request
    def protect_post_requests():
        if request.method != "POST":
            return None
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not supplied or not expected or not hmac.compare_digest(supplied, expected):
            abort(400, description="Jeton de sécurité invalide. Rechargez la page.")
        return None

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; form-action 'self'; "
            "base-uri 'self'; frame-ancestors 'none'"
        )
        return response

    @app.teardown_appcontext
    def close_db(_error=None):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.context_processor
    def template_helpers():
        return {
            "csrf_token": get_csrf_token,
            "format_fcfa": lambda amount: f"{int(amount):,}".replace(",", " "),
        }

    @app.errorhandler(400)
    def bad_request(error):
        return render_template(
            "error.html",
            title="Requête invalide",
            message=getattr(error, "description", "La requête ne peut pas être traitée."),
        ), 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_template(
            "error.html",
            title="Page introuvable",
            message="Cette page n’existe pas ou n’est plus disponible.",
        ), 404

    @app.errorhandler(409)
    def conflict(error):
        return render_template(
            "error.html",
            title="Conflit",
            message=getattr(error, "description", "Cette action n’est plus possible."),
        ), 409

    @app.errorhandler(413)
    def too_large(_error):
        return render_template(
            "error.html",
            title="Fichier trop volumineux",
            message="Le justificatif ne doit pas dépasser 5 Mo.",
        ), 413

    @app.errorhandler(503)
    def unavailable(error):
        return render_template(
            "error.html",
            title="Service indisponible",
            message=getattr(error, "description", "Le service est temporairement indisponible."),
        ), 503

    # ------------------------------------------------------------------
    # Pages publiques et comptes
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        if session.get("is_admin"):
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            phone = normalize_phone(request.form.get("phone", ""))
            network = request.form.get("network", "")
            password = request.form.get("password", "")
            if not phone:
                flash("Saisissez un numéro béninois valide (+229 et 8 à 10 chiffres).", "error")
            elif network not in ("MTN", "MOOV"):
                flash("Sélectionnez MTN ou MOOV.", "error")
            elif len(password) < 10:
                flash("Le mot de passe doit contenir au moins 10 caractères.", "error")
            else:
                db = get_db()
                try:
                    with atomic(db):
                        db.execute(
                            """
                            INSERT INTO users(phone, password_hash, network)
                            VALUES (?, ?, ?)
                            """,
                            (phone, generate_password_hash(password), network),
                        )
                    user = db.execute(
                        "SELECT id FROM users WHERE phone = ?", (phone,)
                    ).fetchone()
                    session.clear()
                    session["user_id"] = user["id"]
                    get_csrf_token()
                    flash("Votre compte est prêt.", "success")
                    return redirect(url_for("dashboard"))
                except sqlite3.IntegrityError:
                    flash("Ce numéro est déjà inscrit.", "error")
            return render_template("register.html")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            phone = normalize_phone(request.form.get("phone", ""))
            password = request.form.get("password", "")
            user = None
            if phone:
                user = get_db().execute(
                    "SELECT id, password_hash FROM users WHERE phone = ?",
                    (phone,),
                ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                get_csrf_token()
                return redirect(url_for("dashboard"))
            flash("Numéro ou mot de passe incorrect.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ------------------------------------------------------------------
    # Tableau de bord utilisateur
    # ------------------------------------------------------------------
    @app.route("/dashboard")
    @user_required
    def dashboard():
        db = get_db()
        user = db.execute(
            "SELECT id, phone, network, balance_fcfa FROM users WHERE id = ?",
            (g.user_id,),
        ).fetchone()
        if user is None:
            session.clear()
            return redirect(url_for("login"))
        settings = get_settings(db)
        active_count = db.execute(
            f"""
            SELECT COUNT(*) AS n FROM assignments
            WHERE user_id = ? AND status IN {ACTIVE_STATUSES_SQL}
            """,
            (g.user_id,),
        ).fetchone()["n"]
        available_count = db.execute(
            """
            SELECT COUNT(*) AS n
            FROM tasks t
            WHERE t.active = 1
              AND NOT EXISTS (
                  SELECT 1 FROM assignments a
                  WHERE a.user_id = ? AND a.task_id = t.id
              )
            """,
            (g.user_id,),
        ).fetchone()["n"]
        # Les liens ressources ne sont exposés qu'à l'étape concernée :
        # resource_url_1 à l'étape 3, resource_url_2 à l'étape 4.
        assignments = db.execute(
            """
            SELECT a.id, a.status, a.current_step, a.closing_key, a.proof_path,
                   a.reward_fcfa, a.assigned_at,
                   t.prompt,
                   t.valeur_a AS Valeur_A, t.valeur_b AS Valeur_B,
                   t.valeur_c AS Valeur_C, t.valeur_d AS Valeur_D,
                   CASE WHEN a.current_step = 3 THEN t.resource_url_1 END AS resource_url_1,
                   CASE WHEN a.current_step = 4 THEN t.resource_url_2 END AS resource_url_2
            FROM assignments a JOIN tasks t ON t.id = a.task_id
            WHERE a.user_id = ?
            ORDER BY a.id DESC LIMIT 30
            """,
            (g.user_id,),
        ).fetchall()
        withdrawals = db.execute(
            """
            SELECT id, amount_fcfa, status, requested_at
            FROM withdrawals WHERE user_id = ?
            ORDER BY id DESC LIMIT 5
            """,
            (g.user_id,),
        ).fetchall()
        return render_template(
            "dashboard.html",
            user=user,
            settings=settings,
            active_count=active_count,
            available_count=available_count,
            assignments=assignments,
            withdrawals=withdrawals,
            max_active=MAX_ACTIVE_TICKETS,
        )

    @app.route("/tickets/take", methods=["POST"])
    @user_required
    def take_tickets():
        try:
            requested_count = int(request.form.get("count", "1"))
        except ValueError:
            abort(400, description="Nombre de tickets invalide.")
        if requested_count < 1 or requested_count > MAX_ACTIVE_TICKETS:
            abort(400, description="Vous pouvez piocher de 1 à 5 tickets à la fois.")

        db = get_db()
        with atomic(db):
            active_count = db.execute(
                f"""
                SELECT COUNT(*) AS n FROM assignments
                WHERE user_id = ? AND status IN {ACTIVE_STATUSES_SQL}
                """,
                (g.user_id,),
            ).fetchone()["n"]
            slots = MAX_ACTIVE_TICKETS - active_count
            if slots <= 0:
                flash("Vous avez déjà 5 tickets actifs ou en cours de vérification.", "error")
                return redirect(url_for("dashboard"))
            config = get_settings(db)
            tasks = db.execute(
                """
                SELECT id FROM tasks t
                WHERE t.active = 1
                  AND NOT EXISTS (
                      SELECT 1 FROM assignments a
                      WHERE a.user_id = ? AND a.task_id = t.id
                  )
                ORDER BY t.id
                LIMIT ?
                """,
                (g.user_id, min(requested_count, slots)),
            ).fetchall()
            for task in tasks:
                db.execute(
                    """
                    INSERT INTO assignments(user_id, task_id, reward_fcfa,
                                            status, current_step)
                    VALUES (?, ?, ?, 'assigned', 1)
                    """,
                    (g.user_id, task["id"], config["reward_fcfa"]),
                )
        if tasks:
            flash(f"{len(tasks)} ticket(s) ajouté(s) à votre tableau de bord.", "success")
        else:
            flash("Aucun nouveau ticket n’est disponible pour le moment.", "error")
        return redirect(url_for("dashboard"))

    # ------------------------------------------------------------------
    # Flux en 4 étapes
    # ------------------------------------------------------------------
    @app.route("/next-step/<int:assignment_id>", methods=["POST"])
    @user_required
    def next_step(assignment_id):
        """Étape 1 -> Étape 2 : l'utilisateur confirme avoir lu les consignes."""
        if request.form.get("confirm") != "1":
            flash("Veuillez confirmer avoir pris connaissance des consignes.", "error")
            return redirect(url_for("dashboard"))

        db = get_db()
        with atomic(db):
            assignment = fetch_user_assignment(db, assignment_id, g.user_id)
            if not step_matches(assignment, "assigned"):
                flash("Ce ticket n’est pas à l’étape 1.", "error")
                return redirect(url_for("dashboard"))
            result = db.execute(
                """
                UPDATE assignments
                SET status = 'attente_justificatif', current_step = 2
                WHERE id = ? AND user_id = ?
                  AND status = 'assigned' AND current_step = 1
                """,
                (assignment_id, g.user_id),
            )
            if result.rowcount != 1:
                abort(409, description="Ce ticket vient d’être modifié.")
        flash("Consignes confirmées. Passez à l’envoi du justificatif.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/upload-proof/<int:assignment_id>", methods=["POST"])
    @user_required
    def upload_proof(assignment_id):
        """Étape 2 -> Étape 3 : dépôt du justificatif image anonymisé."""
        db = get_db()
        with atomic(db):
            assignment = fetch_user_assignment(db, assignment_id, g.user_id)
            if not step_matches(assignment, "attente_justificatif"):
                flash("Ce ticket n’est pas à l’étape 2.", "error")
                return redirect(url_for("dashboard"))

            stored_name, error = save_proof_file(
                request.files.get("proof"),
                current_app.config["PROOF_UPLOAD_DIR"],
                assignment_id,
            )
            if error:
                flash(error, "error")
                return redirect(url_for("dashboard"))

            try:
                result = db.execute(
                    """
                    UPDATE assignments
                    SET proof_path = ?, status = 'attente_cle', current_step = 3
                    WHERE id = ? AND user_id = ?
                      AND status = 'attente_justificatif' AND current_step = 2
                    """,
                    (f"uploads/proofs/{stored_name}", assignment_id, g.user_id),
                )
                if result.rowcount != 1:
                    raise RuntimeError("concurrent update")
            except Exception:
                remove_proof_file(current_app.config["PROOF_UPLOAD_DIR"], stored_name)
                raise
        flash("Justificatif enregistré. Passez à la clé de clôture.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/submit-key/<int:assignment_id>", methods=["POST"])
    @user_required
    def submit_key(assignment_id):
        """Étape 3 -> Étape 4 : soumission de la clé de clôture."""
        closing_key = request.form.get("closing_key", "").strip()
        if not CLOSING_KEY_RE.fullmatch(closing_key):
            flash(
                "La clé de clôture doit être alphanumérique (4 à 64 caractères, sans espace).",
                "error",
            )
            return redirect(url_for("dashboard"))

        db = get_db()
        with atomic(db):
            assignment = fetch_user_assignment(db, assignment_id, g.user_id)
            if not step_matches(assignment, "attente_cle"):
                flash("Ce ticket n’est pas à l’étape 3.", "error")
                return redirect(url_for("dashboard"))
            result = db.execute(
                """
                UPDATE assignments
                SET closing_key = ?, status = 'pending_review', current_step = 4,
                    submitted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE id = ? AND user_id = ?
                  AND status = 'attente_cle' AND current_step = 3
                """,
                (closing_key, assignment_id, g.user_id),
            )
            if result.rowcount != 1:
                abort(409, description="Ce ticket vient d’être modifié.")
        flash("Ticket soumis. Il sera vérifié par l’équipe.", "success")
        return redirect(url_for("dashboard"))

    # ------------------------------------------------------------------
    # Retraits
    # ------------------------------------------------------------------
    @app.route("/withdrawals", methods=["POST"])
    @user_required
    def request_withdrawal():
        try:
            amount = int(request.form.get("amount", "0"))
        except ValueError:
            abort(400, description="Montant de retrait invalide.")
        db = get_db()
        with atomic(db):
            config = get_settings(db)
            if amount < config["minimum_withdrawal_fcfa"]:
                flash(
                    f"Le retrait minimum est de {config['minimum_withdrawal_fcfa']} FCFA.",
                    "error",
                )
                return redirect(url_for("dashboard"))
            debit = db.execute(
                """
                UPDATE users SET balance_fcfa = balance_fcfa - ?
                WHERE id = ? AND balance_fcfa >= ?
                """,
                (amount, g.user_id, amount),
            )
            if debit.rowcount != 1:
                flash("Votre solde disponible est insuffisant.", "error")
                return redirect(url_for("dashboard"))
            withdrawal = db.execute(
                "INSERT INTO withdrawals(user_id, amount_fcfa) VALUES (?, ?)",
                (g.user_id, amount),
            )
            db.execute(
                """
                INSERT INTO wallet_ledger(user_id, amount_fcfa, event_type, reference_id)
                VALUES (?, ?, 'withdrawal_debit', ?)
                """,
                (g.user_id, -amount, withdrawal.lastrowid),
            )
        flash("Demande enregistrée. Le montant a été réservé sur votre portefeuille.", "success")
        return redirect(url_for("dashboard"))

    # ------------------------------------------------------------------
    # Administration
    # ------------------------------------------------------------------
    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if not app.config.get("ADMIN_PASSWORD_HASH"):
            abort(
                503,
                description="L’accès administrateur n’est pas configuré. Définissez ADMIN_PASSWORD.",
            )
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            username_ok = hmac.compare_digest(
                username, app.config["ADMIN_USERNAME"]
            )
            password_ok = check_password_hash(
                app.config["ADMIN_PASSWORD_HASH"], password
            )
            if username_ok and password_ok:
                session.clear()
                session["is_admin"] = True
                get_csrf_token()
                return redirect(url_for("admin_dashboard"))
            flash("Identifiant ou mot de passe incorrect.", "error")
        return render_template("admin_login.html")

    @app.route("/admin/logout", methods=["POST"])
    @admin_required
    def admin_logout():
        session.clear()
        return redirect(url_for("admin_login"))

    @app.route("/admin")
    @admin_required
    def admin_dashboard():
        db = get_db()
        stats = {
            "users": db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"],
            "approved": db.execute(
                "SELECT COUNT(*) AS n FROM assignments WHERE status = 'approved'"
            ).fetchone()["n"],
            "paid_out": db.execute(
                """
                SELECT COALESCE(SUM(amount_fcfa), 0) AS n
                FROM wallet_ledger WHERE event_type = 'task_reward'
                """
            ).fetchone()["n"],
            "pending_withdrawals": db.execute(
                "SELECT COUNT(*) AS n FROM withdrawals WHERE status = 'pending'"
            ).fetchone()["n"],
            "pending_reviews": db.execute(
                "SELECT COUNT(*) AS n FROM assignments WHERE status = 'pending_review'"
            ).fetchone()["n"],
        }
        pending_reviews = db.execute(
            """
            SELECT a.id, a.closing_key, a.proof_path, a.reward_fcfa, a.submitted_at,
                   u.phone, t.prompt,
                   t.valeur_a AS Valeur_A, t.valeur_b AS Valeur_B,
                   t.valeur_c AS Valeur_C, t.valeur_d AS Valeur_D
            FROM assignments a
            JOIN users u ON u.id = a.user_id
            JOIN tasks t ON t.id = a.task_id
            WHERE a.status = 'pending_review' AND a.current_step = 4
            ORDER BY a.submitted_at LIMIT 20
            """
        ).fetchall()
        pending_withdrawals = db.execute(
            """
            SELECT w.id, w.amount_fcfa, w.status, w.requested_at,
                   u.phone, u.network
            FROM withdrawals w JOIN users u ON u.id = w.user_id
            WHERE w.status = 'pending'
            ORDER BY w.id
            LIMIT 50
            """
        ).fetchall()
        return render_template(
            "admin_dashboard.html",
            stats=stats,
            pending_reviews=pending_reviews,
            withdrawals=pending_withdrawals,
        )

    @app.route("/admin/reviews/<int:assignment_id>/<decision>", methods=["POST"])
    @admin_required
    def review_submission(assignment_id, decision):
        if decision not in ("approve", "reject"):
            abort(404)
        db = get_db()
        with atomic(db):
            assignment = db.execute(
                """
                SELECT user_id, reward_fcfa FROM assignments
                WHERE id = ? AND status = 'pending_review' AND current_step = 4
                """,
                (assignment_id,),
            ).fetchone()
            if assignment is None:
                flash("Cette soumission n’est pas en attente de revue.", "error")
                return redirect(url_for("admin_dashboard"))
            status = "approved" if decision == "approve" else "rejected"
            result = db.execute(
                """
                UPDATE assignments
                SET status = ?,
                    reviewed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    credited_at = CASE WHEN ? = 'approved'
                        THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now') ELSE NULL END
                WHERE id = ? AND status = 'pending_review' AND current_step = 4
                """,
                (status, status, assignment_id),
            )
            if result.rowcount != 1:
                abort(409, description="Cette soumission vient d’être traitée.")
            if decision == "approve":
                # Récompense figée à l'attribution du ticket (reward_fcfa).
                credit_task_reward(
                    db,
                    assignment["user_id"],
                    assignment_id,
                    assignment["reward_fcfa"],
                )
        flash(
            "Soumission approuvée et créditée."
            if decision == "approve"
            else "Soumission rejetée (aucun crédit).",
            "success",
        )
        return redirect(url_for("admin_dashboard"))

    @app.route("/admin/tasks", methods=["GET", "POST"])
    @admin_required
    def admin_tasks():
        db = get_db()
        if request.method == "POST":
            prompt = request.form.get("prompt", "").strip()
            validation_mode = request.form.get("validation_mode", "manual")
            expected_answer = request.form.get("expected_answer", "").strip()
            valeurs = [
                request.form.get(f"valeur_{letter}", "").strip() for letter in "abcd"
            ]
            url_1 = request.form.get("resource_url_1", "").strip()
            url_2 = request.form.get("resource_url_2", "").strip()

            # Validation
            if not prompt or len(prompt) > 2000:
                flash("Le texte du ticket doit contenir entre 1 et 2 000 caractères.", "error")
            elif validation_mode == "exact" and not expected_answer:
                flash("En mode 'exact', une réponse attendue est requise.", "error")
            elif validation_mode == "manual" and any(
                not v or len(v) > MAX_VALUE_LENGTH for v in valeurs
            ):
                flash(
                    "Valeur_A à Valeur_D sont requises (500 caractères maximum chacune).",
                    "error",
                )
            elif (url_1 and not is_valid_http_url(url_1)) or (url_2 and not is_valid_http_url(url_2)):
                flash("Les liens ressources doivent être des URL http(s) valides.", "error")
            else:
                with atomic(db):
                    db.execute(
                        """
                        INSERT INTO tasks(prompt, validation_mode, expected_answer,
                                          valeur_a, valeur_b, valeur_c, valeur_d,
                                          resource_url_1, resource_url_2)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            prompt,
                            validation_mode,
                            expected_answer if expected_answer else None,
                            *valeurs,
                            url_1 or None,
                            url_2 or None,
                        ),
                    )
                flash("Ticket ajouté au flux.", "success")
                return redirect(url_for("admin_tasks"))
        tasks = db.execute(
            """
            SELECT t.id, t.prompt, t.active, t.created_at,
                   t.valeur_a AS Valeur_A, t.valeur_b AS Valeur_B,
                   t.valeur_c AS Valeur_C, t.valeur_d AS Valeur_D,
                   t.resource_url_1, t.resource_url_2,
                   COUNT(a.id) AS assignment_count
            FROM tasks t LEFT JOIN assignments a ON a.task_id = t.id
            GROUP BY t.id ORDER BY t.id DESC LIMIT 100
            """
        ).fetchall()
        return render_template("admin_tasks.html", tasks=tasks)

    @app.route("/admin/tasks/<int:task_id>/toggle", methods=["POST"])
    @admin_required
    def toggle_task(task_id):
        with atomic(get_db()) as db:
            result = db.execute(
                "UPDATE tasks SET active = 1 - active WHERE id = ?",
                (task_id,),
            )
        if result.rowcount != 1:
            abort(404)
        flash("Disponibilité du ticket mise à jour.", "success")
        return redirect(url_for("admin_tasks"))

    @app.route("/admin/withdrawals")
    @admin_required
    def admin_withdrawals():
        rows = get_db().execute(
            """
            SELECT w.id, w.amount_fcfa, w.status, w.requested_at,
                   u.phone, u.network
            FROM withdrawals w JOIN users u ON u.id = w.user_id
            ORDER BY CASE w.status WHEN 'pending' THEN 0 ELSE 1 END, w.id DESC
            LIMIT 100
            """
        ).fetchall()
        return render_template("admin_withdrawals.html", withdrawals=rows)

    @app.route("/admin/withdrawals/<int:withdrawal_id>/<decision>", methods=["POST"])
    @admin_required
    def process_withdrawal(withdrawal_id, decision):
        if decision not in ("pay", "reject"):
            abort(404)
        db = get_db()
        with atomic(db):
            withdrawal = db.execute(
                """
                SELECT user_id, amount_fcfa FROM withdrawals
                WHERE id = ? AND status = 'pending'
                """,
                (withdrawal_id,),
            ).fetchone()
            if withdrawal is None:
                flash("Cette demande a déjà été traitée.", "error")
                return redirect(url_for("admin_withdrawals"))
            next_status = "paid" if decision == "pay" else "rejected"
            updated = db.execute(
                """
                UPDATE withdrawals
                SET status = ?, processed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE id = ? AND status = 'pending'
                """,
                (next_status, withdrawal_id),
            )
            if updated.rowcount != 1:
                abort(409, description="Cette demande vient d’être traitée.")
            if decision == "reject":
                db.execute(
                    """
                    UPDATE users SET balance_fcfa = balance_fcfa + ?
                    WHERE id = ?
                    """,
                    (withdrawal["amount_fcfa"], withdrawal["user_id"]),
                )
                db.execute(
                    """
                    INSERT INTO wallet_ledger(user_id, amount_fcfa, event_type, reference_id)
                    VALUES (?, ?, 'withdrawal_refund', ?)
                    """,
                    (
                        withdrawal["user_id"],
                        withdrawal["amount_fcfa"],
                        withdrawal_id,
                    ),
                )
        flash(
            "Paiement marqué comme effectué."
            if decision == "pay"
            else "Demande rejetée et montant recrédité.",
            "success",
        )
        return redirect(url_for("admin_withdrawals"))

    @app.route("/admin/settings", methods=["GET", "POST"])
    @admin_required
    def admin_settings():
        db = get_db()
        if request.method == "POST":
            try:
                reward = int(request.form.get("reward_fcfa", "0"))
                minimum = int(request.form.get("minimum_withdrawal_fcfa", "0"))
            except ValueError:
                abort(400, description="Les montants doivent être des nombres entiers.")
            if not (1 <= reward <= 100_000):
                flash("La récompense doit être comprise entre 1 et 100 000 FCFA.", "error")
            elif not (100 <= minimum <= 100_000_000):
                flash("Le minimum de retrait doit être compris entre 100 et 100 000 000 FCFA.", "error")
            else:
                with atomic(db):
                    db.executemany(
                        "UPDATE configuration SET value = ? WHERE key = ?",
                        [
                            (str(reward), "reward_fcfa"),
                            (str(minimum), "minimum_withdrawal_fcfa"),
                        ],
                    )
                flash("Configuration enregistrée.", "success")
                return redirect(url_for("admin_settings"))
        settings = get_settings(db)
        return render_template("admin_settings.html", settings=settings)

    return app


# ----------------------------------------------------------------------
# Utilitaires
# ----------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = connect_db(current_app.config["DATABASE"])
    return g.db


@contextmanager
def atomic(db):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    else:
        db.commit()


def ensure_schema(database_path):
    """Ajoute, si besoin, les colonnes nécessaires au flux en 4 étapes.

    Idempotent : peut être exécuté à chaque démarrage.
    NB : si models.py définit une contrainte CHECK sur assignments.status,
    elle doit aussi accepter 'attente_justificatif' et 'attente_cle'.
    """
    connection = connect_db(database_path)
    try:
        def columns(table):
            return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}

        task_columns = columns("tasks")
        for name in ("valeur_a", "valeur_b", "valeur_c", "valeur_d"):
            if name not in task_columns:
                connection.execute(
                    f"ALTER TABLE tasks ADD COLUMN {name} TEXT NOT NULL DEFAULT ''"
                )
        for name in ("resource_url_1", "resource_url_2"):
            if name not in task_columns:
                connection.execute(f"ALTER TABLE tasks ADD COLUMN {name} TEXT")

        assignment_columns = columns("assignments")
        if "current_step" not in assignment_columns:
            connection.execute(
                "ALTER TABLE assignments ADD COLUMN current_step INTEGER NOT NULL DEFAULT 1"
            )
            # Anciennes lignes : tout ce qui n'est pas 'assigned' est au bout du flux.
            connection.execute(
                "UPDATE assignments SET current_step = 4 WHERE status != 'assigned'"
            )
        if "proof_path" not in assignment_columns:
            connection.execute("ALTER TABLE assignments ADD COLUMN proof_path TEXT")
        if "closing_key" not in assignment_columns:
            connection.execute("ALTER TABLE assignments ADD COLUMN closing_key TEXT")
        if connection.in_transaction:
            connection.commit()
    finally:
        connection.close()


def fetch_user_assignment(db, assignment_id, user_id):
    assignment = db.execute(
        """
        SELECT id, status, current_step FROM assignments
        WHERE id = ? AND user_id = ?
        """,
        (assignment_id, user_id),
    ).fetchone()
    if assignment is None:
        abort(404)
    return assignment


def step_matches(assignment, expected_status):
    """Vérifie que le statut ET l'étape numérique correspondent au flux."""
    return (
        assignment["status"] == expected_status
        and assignment["current_step"] == STATUS_STEP[expected_status]
    )


def detect_image_type(header):
    if header.startswith(PNG_SIGNATURE):
        return "png"
    if header.startswith(JPEG_SIGNATURE):
        return "jpg"
    return None


def save_proof_file(file_storage, upload_dir, assignment_id):
    """Valide et enregistre un justificatif. Retourne (nom_stocké, erreur)."""
    if file_storage is None or not file_storage.filename:
        return None, "Sélectionnez une image (.png, .jpg ou .jpeg)."

    original = secure_filename(file_storage.filename)
    extension = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    expected_type = ALLOWED_PROOF_EXTENSIONS.get(extension)
    if expected_type is None:
        return None, "Format refusé : seuls .png, .jpg et .jpeg sont acceptés."

    stream = file_storage.stream
    header = stream.read(16)
    stream.seek(0)
    if detect_image_type(header) != expected_type:
        return None, "Le contenu du fichier ne correspond pas à une image valide."

    # Nom entièrement généré côté serveur : aucun fragment du nom d'origine.
    stored_name = f"proof_{assignment_id}_{secrets.token_hex(16)}.{expected_type}"
    destination = Path(upload_dir) / stored_name
    file_storage.save(destination)

    if destination.stat().st_size > MAX_UPLOAD_BYTES:
        destination.unlink(missing_ok=True)
        return None, "Le justificatif ne doit pas dépasser 5 Mo."
    return stored_name, None


def remove_proof_file(upload_dir, stored_name):
    try:
        (Path(upload_dir) / stored_name).unlink(missing_ok=True)
    except OSError:
        pass


def is_valid_http_url(value):
    """Une URL vide est acceptée (champ optionnel)."""
    if not value:
        return True
    if len(value) > MAX_URL_LENGTH:
        return False
    parsed = urlparse(value)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def normalize_phone(value):
    digits = re.sub(r"\D", "", value)
    if digits.startswith("229"):
        digits = digits[3:]
    if not 8 <= len(digits) <= 10:
        return None
    return f"+229{digits}"


def get_settings(db):
    values = {
        row["key"]: row["value"]
        for row in db.execute(
            """
            SELECT key, value FROM configuration
            WHERE key IN ('reward_fcfa', 'minimum_withdrawal_fcfa')
            """
        ).fetchall()
    }
    try:
        return {
            "reward_fcfa": int(values["reward_fcfa"]),
            "minimum_withdrawal_fcfa": int(values["minimum_withdrawal_fcfa"]),
        }
    except (KeyError, ValueError) as error:
        raise RuntimeError("Configuration financière absente ou invalide.") from error


def credit_task_reward(db, user_id, assignment_id, amount):
    db.execute(
        "UPDATE users SET balance_fcfa = balance_fcfa + ? WHERE id = ?",
        (amount, user_id),
    )
    db.execute(
        """
        INSERT INTO wallet_ledger(user_id, amount_fcfa, event_type, reference_id)
        VALUES (?, ?, 'task_reward', ?)
        """,
        (user_id, amount, assignment_id),
    )


def user_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        g.user_id = user_id
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )