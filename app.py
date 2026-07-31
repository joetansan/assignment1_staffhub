import sqlite3
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from config import DATABASE_PATH, SECRET_KEY


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["DATABASE"] = DATABASE_PATH

    @app.before_request
    def load_current_user() -> None:
        g.current_user = get_current_user()

    @app.teardown_appcontext
    def close_db(exception: Exception | None = None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.route("/")
    def index():
        if g.current_user is None:
            return redirect(url_for("login"))
        return redirect(url_for("dashboard"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            user = query_one(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            )

            if user is None or not check_password_hash(user["password_hash"], password):
                flash("Invalid username or password.", "error")
                return render_template("login.html"), 401

            session.clear()
            session["user_id"] = user["id"]
            flash(f"Welcome, {user['full_name']}.", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        total_records = query_one("SELECT COUNT(*) AS count FROM records")["count"]
        open_records = query_one("SELECT COUNT(*) AS count FROM records WHERE status != ?", ("Closed",))["count"]
        my_records = query_one(
            "SELECT COUNT(*) AS count FROM records WHERE owner_id = ?",
            (g.current_user["id"],),
        )["count"]

        return render_template(
            "dashboard.html",
            total_records=total_records,
            open_records=open_records,
            my_records=my_records,
        )

    @app.route("/records")
    @login_required
    def records():
        # Starter behaviour: this list is deliberately broad.
        # Students should review whether the final application enforces appropriate role, ownership,
        # department, and scope rules for their assignment.
        rows = query_all(
            """
            SELECT records.*, users.full_name AS owner_name, users.department AS owner_department
            FROM records
            JOIN users ON records.owner_id = users.id
            ORDER BY records.created_at DESC
            """
        )
        return render_template("records.html", records=rows)

    @app.route("/records/new", methods=["GET", "POST"])
    @login_required
    def new_record():
        if request.method == "POST":
            # Starter behaviour: minimal processing only.
            # Students should apply appropriate validation and secure control flow before submission.
            title = request.form.get("title", "")
            category = request.form.get("category", "")
            description = request.form.get("description", "")
            priority = request.form.get("priority", "Medium")

            now = current_timestamp()
            db = get_db()
            db.execute(
                """
                INSERT INTO records (owner_id, title, category, description, priority, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (g.current_user["id"], title, category, description, priority, "Open", now, now),
            )
            db.commit()
            flash("Record submitted.", "success")
            return redirect(url_for("records"))

        return render_template("record_form.html")

    @app.route("/records/<int:record_id>")
    @login_required
    def record_detail(record_id: int):
        # Starter behaviour: record lookup is intentionally simple.
        # Students should review the required access rules for the final application.
        record = query_one(
            """
            SELECT records.*, users.full_name AS owner_name, users.department AS owner_department
            FROM records
            JOIN users ON records.owner_id = users.id
            WHERE records.id = ?
            """,
            (record_id,),
        )

        if record is None:
            abort(404)

        return render_template("record_detail.html", record=record)

    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html")

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("error.html", code=403, message="You are not allowed to access this page."), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("error.html", code=404, message="The requested item was not found."), 404

    @app.errorhandler(500)
    def server_error(error):
        return render_template("error.html", code=500, message="An unexpected error occurred."), 500

    return app


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        db_path = Path(DATABASE_PATH)
        if not db_path.exists():
            raise RuntimeError("Database not found. Run: python init_db.py")
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
    return g.db


def query_one(sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    return get_db().execute(sql, params).fetchone()


def query_all(sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    return get_db().execute(sql, params).fetchall()


def current_timestamp() -> str:
    from datetime import datetime

    return datetime.now().replace(microsecond=0).isoformat(sep=" ")


def get_current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if user_id is None:
        return None

    db = g.get("db")
    if db is None:
        db = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row
        g.db = db

    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.current_user is None:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def is_admin(user: sqlite3.Row | None) -> bool:
    return user is not None and user["role"] == "Admin"


def is_manager(user: sqlite3.Row | None) -> bool:
    return user is not None and user["role"] == "Manager"


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
