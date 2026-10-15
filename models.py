import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


SCHEMA_VERSION = 2

# Anciennes lignes 'assigned' (jamais soumises dans l'ancien système) :
#   False -> elles restent à l'étape 1 et suivent le nouveau flux complet ;
#   True  -> elles sont envoyées directement en revue (status 'pending_review',
#            étape 4), sans justificatif ni clé de clôture.
# Les anciennes lignes 'pending_review', 'approved' et 'rejected' passent
# toujours à l'étape 4.
MIGRATE_LEGACY_ASSIGNED_TO_STEP_4 = False

ASSIGNMENT_STATUSES = (
    "assigned",
    "attente_justificatif",
    "attente_cle",
    "pending_review",
    "approved",
    "rejected",
)

_ASSIGNMENTS_BODY = """
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    status TEXT NOT NULL DEFAULT 'assigned'
        CHECK (status IN (
            'assigned', 'attente_justificatif', 'attente_cle',
            'pending_review', 'approved', 'rejected'
        )),
    current_step INTEGER NOT NULL DEFAULT 1
        CHECK (current_step BETWEEN 1 AND 4),
    answer TEXT,
    proof_path TEXT,
    closing_key TEXT,
    reward_fcfa INTEGER NOT NULL CHECK (reward_fcfa > 0),
    assigned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    submitted_at TEXT,
    reviewed_at TEXT,
    credited_at TEXT,
    UNIQUE (user_id, task_id),
    CHECK (
        (status = 'assigned' AND current_step = 1)
        OR (status = 'attente_justificatif' AND current_step = 2)
        OR (status = 'attente_cle' AND current_step = 3)
        OR (status IN ('pending_review', 'approved', 'rejected') AND current_step = 4)
    )
"""

_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_assignments_user_status ON assignments(user_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_assignments_status ON assignments(status)",
)

SCHEMA = f"""
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    network TEXT NOT NULL CHECK (network IN ('MTN', 'MOOV')),
    balance_fcfa INTEGER NOT NULL DEFAULT 0 CHECK (balance_fcfa >= 0),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prompt TEXT NOT NULL CHECK (length(prompt) BETWEEN 1 AND 2000),
    validation_mode TEXT NOT NULL CHECK (validation_mode IN ('exact', 'manual')),
    expected_answer TEXT,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    valeur_a TEXT NOT NULL DEFAULT '',
    valeur_b TEXT NOT NULL DEFAULT '',
    valeur_c TEXT NOT NULL DEFAULT '',
    valeur_d TEXT NOT NULL DEFAULT '',
    resource_url_1 TEXT,
    resource_url_2 TEXT,
    CHECK (
        (validation_mode = 'exact' AND expected_answer IS NOT NULL AND length(expected_answer) > 0)
        OR (validation_mode = 'manual' AND expected_answer IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS assignments ({_ASSIGNMENTS_BODY});

CREATE TABLE IF NOT EXISTS withdrawals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount_fcfa INTEGER NOT NULL CHECK (amount_fcfa > 0),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'paid', 'rejected')),
    requested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    processed_at TEXT
);

CREATE TABLE IF NOT EXISTS configuration (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS wallet_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount_fcfa INTEGER NOT NULL CHECK (amount_fcfa != 0),
    event_type TEXT NOT NULL
        CHECK (event_type IN ('task_reward', 'withdrawal_debit', 'withdrawal_refund')),
    reference_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (event_type, reference_id)
);

{";".join(_INDEXES)};
CREATE INDEX IF NOT EXISTS idx_tasks_active
    ON tasks(active);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status
    ON withdrawals(status);

INSERT OR IGNORE INTO configuration(key, value) VALUES
    ('reward_fcfa', '90'),
    ('minimum_withdrawal_fcfa', '1000');

PRAGMA user_version = {SCHEMA_VERSION};
"""

_TASK_TEXT_COLUMNS = (
    ("valeur_a", "TEXT NOT NULL DEFAULT ''"),
    ("valeur_b", "TEXT NOT NULL DEFAULT ''"),
    ("valeur_c", "TEXT NOT NULL DEFAULT ''"),
    ("valeur_d", "TEXT NOT NULL DEFAULT ''"),
    ("resource_url_1", "TEXT"),
    ("resource_url_2", "TEXT"),
)

_ASSIGNMENT_REQUIRED_COLUMNS = {"current_step", "proof_path", "closing_key"}

# Colonnes de l'ancienne table recopiées telles quelles si elles existent.
_ASSIGNMENT_CARRIED_COLUMNS = (
    "id",
    "user_id",
    "task_id",
    "answer",
    "proof_path",
    "closing_key",
    "reward_fcfa",
    "assigned_at",
    "submitted_at",
    "reviewed_at",
    "credited_at",
)


def connect_db(database_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(
        database_path,
        timeout=10,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def initialize_database(database_path: str) -> None:
    """Migre une base existante si nécessaire, puis crée ce qui manque."""
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    ensure_schema(database_path)
    connection = connect_db(database_path)
    try:
        connection.executescript(SCHEMA)
    finally:
        connection.close()


def ensure_schema(database_path: str) -> None:
    """Migration idempotente vers le schéma v2 (flux de tickets en 4 étapes).

    - ajoute à `tasks` les colonnes valeur_a..d et resource_url_1/2 ;
    - recrée `assignments` pour élargir le CHECK sur `status` et ajouter
      current_step, proof_path et closing_key, sans perte de données ;
    - recalcule current_step à partir du statut (cf. constantes en tête de
      fichier pour les anciennes lignes 'assigned') ;
    - réalise une sauvegarde de la base avant toute modification.

    Sans effet sur une base vide ou déjà migrée.
    """
    if not Path(database_path).exists():
        return

    connection = connect_db(database_path)
    try:
        has_tasks = _table_exists(connection, "tasks")
        has_assignments = _table_exists(connection, "assignments")
        if not has_tasks and not has_assignments:
            return

        version = connection.execute("PRAGMA user_version").fetchone()[0]
        missing_task_columns = []
        if has_tasks:
            existing = _columns(connection, "tasks")
            missing_task_columns = [
                (name, ddl) for name, ddl in _TASK_TEXT_COLUMNS if name not in existing
            ]
        rebuild_assignments = has_assignments and (
            version < SCHEMA_VERSION
            or not _ASSIGNMENT_REQUIRED_COLUMNS <= _columns(connection, "assignments")
        )

        if not missing_task_columns and not rebuild_assignments:
            return

        _backup_database(connection, database_path)

        if missing_task_columns:
            _add_task_columns(connection, missing_task_columns)
        if rebuild_assignments:
            _rebuild_assignments(connection)
        if has_assignments:
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    finally:
        connection.close()


# ----------------------------------------------------------------------
# Fonctions internes de migration
# ----------------------------------------------------------------------
def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        is not None
    )


def _columns(connection: sqlite3.Connection, table: str) -> set:
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}


def _backup_database(connection: sqlite3.Connection, database_path: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = f"{database_path}.bak-{stamp}"
    with closing(sqlite3.connect(backup_path)) as destination:
        connection.backup(destination)


def _add_task_columns(connection: sqlite3.Connection, columns) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        for name, ddl in columns:
            connection.execute(f"ALTER TABLE tasks ADD COLUMN {name} {ddl}")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    connection.execute("COMMIT")


def _rebuild_assignments(connection: sqlite3.Connection) -> None:
    old_columns = _columns(connection, "assignments")
    is_legacy = "current_step" not in old_columns
    carried = [c for c in _ASSIGNMENT_CARRIED_COLUMNS if c in old_columns]

    if is_legacy and MIGRATE_LEGACY_ASSIGNED_TO_STEP_4:
        status_expr = "CASE WHEN status = 'assigned' THEN 'pending_review' ELSE status END"
    else:
        status_expr = "status"
    step_expr = (
        f"CASE {status_expr} "
        "WHEN 'assigned' THEN 1 "
        "WHEN 'attente_justificatif' THEN 2 "
        "WHEN 'attente_cle' THEN 3 "
        "ELSE 4 END"
    )
    insert_columns = ", ".join(carried + ["status", "current_step"])
    select_columns = ", ".join(carried + [status_expr, step_expr])

    # PRAGMA foreign_keys est sans effet à l'intérieur d'une transaction.
    connection.execute("PRAGMA foreign_keys = OFF")
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            old_count = connection.execute("SELECT COUNT(*) FROM assignments").fetchone()[0]
            old_seq = None
            if _table_exists(connection, "sqlite_sequence"):
                row = connection.execute(
                    "SELECT seq FROM sqlite_sequence WHERE name = 'assignments'"
                ).fetchone()
                old_seq = row["seq"] if row else None

            connection.execute("DROP TABLE IF EXISTS assignments_new")
            connection.execute(f"CREATE TABLE assignments_new ({_ASSIGNMENTS_BODY})")
            connection.execute(
                f"""
                INSERT INTO assignments_new ({insert_columns})
                SELECT {select_columns} FROM assignments ORDER BY id
                """
            )
            new_count = connection.execute("SELECT COUNT(*) FROM assignments_new").fetchone()[0]
            if new_count != old_count:
                raise RuntimeError(
                    f"Migration annulée : {old_count} lignes avant, {new_count} après."
                )

            connection.execute("DROP TABLE assignments")
            connection.execute("ALTER TABLE assignments_new RENAME TO assignments")

            # Conserve le compteur AUTOINCREMENT (pas de réutilisation d'identifiants).
            if old_seq is not None:
                updated = connection.execute(
                    "UPDATE sqlite_sequence SET seq = MAX(seq, ?) WHERE name = 'assignments'",
                    (old_seq,),
                ).rowcount
                if not updated:
                    connection.execute(
                        "INSERT INTO sqlite_sequence(name, seq) VALUES ('assignments', ?)",
                        (old_seq,),
                    )

            for statement in _INDEXES:
                connection.execute(statement)

            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise RuntimeError("Migration annulée : violations de clés étrangères.")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        connection.execute("COMMIT")
    finally:
        connection.execute("PRAGMA foreign_keys = ON")