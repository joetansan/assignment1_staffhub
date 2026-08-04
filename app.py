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

ALLOWED_PRIORITIES = ("Low", "Medium", "High", "Urgent")

def create_app() -> Flask:
    app = Flask(__name__)
    # added session cookie flags
    app.config["SESSION_COOKIE_HTTPONLY"] = True        # against xss, block client side scripts accessing session cookie
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"       # control when cookies are sent w/ cross-site requests, lax = block on cross-site subrequests
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
                log_audit_event("LOGIN_FAILED", "Warning", f"Failed login attempt for username '{username}'.")
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
        user = g.current_user
        # scope dashboard counts so it only counts records able to be seen
        if user["role"] == "Admin":
            total_records = query_one("SELECT COUNT(*) AS count FROM records")["count"]
            open_records = query_one("SELECT COUNT(*) AS count FROM records WHERE status != ?", ("Closed",))["count"]
        elif user["role"] == "Manager":
            total_records = query_one(
                "SELECT COUNT(*) AS count FROM records JOIN users ON records.owner_id = users.id WHERE users.department = ?",
                (user["department"],),
            )["count"]
            open_records = query_one(
                "SELECT COUNT(*) AS count FROM records JOIN users ON records.owner_id = users.id WHERE users.department = ? AND records.status != ?",
                (user["department"], "Closed"),
            )["count"]
        else:
            total_records = query_one("SELECT COUNT(*) AS count FROM records WHERE owner_id = ?", (user["id"],))["count"]
            open_records = query_one(
                "SELECT COUNT(*) AS count FROM records WHERE owner_id = ? AND status != ?",
                (user["id"], "Closed"),
            )["count"]

        my_records = query_one(
            "SELECT COUNT(*) AS count FROM records WHERE owner_id = ?",
            (user["id"],),
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
        user = g.current_user
        if user["role"] == "Admin": # all records
            rows = query_all(
                """
                SELECT records.*, users.full_name AS owner_name, users.department AS owner_department,
                        categories.name AS category_name
                FROM records
                JOIN users ON records.owner_id = users.id
                JOIN categories ON records.category_id = categories.id
                ORDER BY records.created_at DESC
                """
            )
        elif user["role"] == "Manager": # records from manager's own department only
            rows = query_all(
                """
                SELECT records.*, users.full_name AS owner_name, users.department AS owner_department,
                        categories.name AS category_name
                FROM records
                JOIN users ON records.owner_id = users.id
                JOIN categories ON records.category_id = categories.id
                WHERE users.department = ?
                ORDER BY records.created_at DESC
                """,
                (user["department"],),
            )
        else: # employee, only own records
            rows = query_all( 
                """
                SELECT records.*, users.full_name AS owner_name, users.department AS owner_department,
                        categories.name AS category_name
                FROM records
                JOIN users ON records.owner_id = users.id
                JOIN categories ON records.category_id = categories.id
                WHERE records.owner_id = ?
                ORDER BY records.created_at DESC
                """,
                (user["id"],),
            )
        return render_template("records.html", records=rows)

    @app.route("/records/new", methods=["GET", "POST"])
    @login_required
    def new_record():

        active_categories = query_all(
            """
            SELECT id, name FROM categories
            WHERE status = 'Active'
            ORDER BY name
            """
        )

        user = g.current_user
        if request.method == "POST":
            # Starter behaviour: minimal processing only.
            # Students should apply appropriate validation and secure control flow before submission.
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            priority = request.form.get("priority", "Medium")

            try:
                category_id = int(request.form.get("category_id", ""))
            except ValueError:
                category_id = None

            errors = []
            if not title:
                errors.append("Title is required.")
            elif len(title) > 120:
                errors.append("Title must be 120 characters or fewer.")
            if category_id is None:
                errors.append("Please select a category.")
            else:
                category = query_one(
                    "SELECT id, name, status FROM categories WHERE id = ?",
                    (category_id,),
                )
                if category is None or category["status"] != "Active":
                    errors.append("Please select a valid active category.")
            if not description:
                errors.append("Description is required.")
            elif len(description) > 2000:
                errors.append("Description must be 2000 characters or fewer.")
            if priority not in ALLOWED_PRIORITIES:
                errors.append("Priority must be either Low, Medium, High, or Urgent.")

            if errors:
                log_audit_event("INVALID_INPUT", "Warning", "Record submission rejected due to invalid input")
                for message in errors:
                    flash(message, "error")
                return render_template(
                    "record_form.html",
                    categories=active_categories,
                    title=title,
                    category_id=category_id,
                    description=description,
                    priority=priority,
                ), 400

            now = current_timestamp()
            db = get_db()
            db.execute(
                """
                INSERT INTO records (owner_id, title, category_id, description, priority, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (user["id"], title, category_id, description, priority, "Open", now, now),
            )
            db.commit()
            flash("Record submitted.", "success")
            return redirect(url_for("records"))

        return render_template(
            "record_form.html",
            categories=active_categories,
            title="",
            category_id=None,
            description="",
            priority="Medium",
        ), 400

    @app.route("/records/<int:record_id>")
    @login_required
    def record_detail(record_id: int):
        # Starter behaviour: record lookup is intentionally simple.
        # Students should review the required access rules for the final application.
        user = g.current_user
        record = query_one(
            """
            SELECT records.*, users.full_name AS owner_name, users.department AS owner_department,
                    categories.name AS category_name
            FROM records
            JOIN users ON records.owner_id = users.id
            JOIN categories ON records.category_id = categories.id
            WHERE records.id = ?
            """,
            (record_id,),
        )

        if record is None:
            abort(404)

        if user["role"] == "Employee" and record["owner_id"] != user["id"]:
            abort(403)

        if user["role"] == "Manager" and record["owner_department"] != user["department"]:
            abort(403)

        return render_template("record_detail.html", record=record)

    @app.route("/categories")
    @login_required
    def categories():
        user = g.current_user
        if not is_admin(user):
            abort(403)
        rows = query_all(
            """
            SELECT * FROM categories
            ORDER BY status ASC, name ASC
            """
        )
        return render_template("categories.html", categories=rows)

    @app.route("/categories/new", methods=["GET", "POST"])
    @login_required
    def new_category():
        user = g.current_user
        if not is_admin(user):
            abort(403)
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()

            errors = []
            if not name:
                errors.append("Category name is required.")
            elif len(name) > 50:
                errors.append("Category name must be 50 characters or fewer.")
            if len(description) > 200:
                errors.append("Description must be 200 characters or fewer.")

            if not errors:
                existing = query_one("SELECT id FROM categories WHERE name = ?", (name,))
                if existing is not None:
                    errors.append("A category with this name already exists.")

            if errors:
                for message in errors:
                    flash(message, "error")
                return render_template("category_form.html", category=None, name=name, description=description), 400

            now = current_timestamp()
            db = get_db()
            db.execute(
                """
                INSERT INTO categories (name, description, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, description, "Active", now, now)
            )
            db.commit()
            log_audit_event("ADMIN_ACTION", "Info", f"Category '{name}' created.")
            flash("Category created.", "success")
            return redirect(url_for("categories"))

        return render_template("category_form.html", category=None, name="", description="")

    @app.route("/categories/<int:category_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_category(category_id: int):
        user = g.current_user
        if not is_admin(user):
            abort(403)
        category = query_one("SELECT * FROM categories WHERE id = ?", (category_id,))
        if category is None:
            abort(404)

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()

            errors = []
            if not name:
                errors.append("Category name is required.")
            elif len(name) > 50:
                errors.append("Category name must be 50 characters or fewer.")
            if len(description) > 200:
                errors.append("Description must be 200 characters or fewer.")

            if not errors:
                existing = query_one(
                    "SELECT id FROM categories WHERE name = ? AND id != ?",
                    (name, category_id),
                )
                if existing is not None:
                    errors.append("A category with this name already exists.")

            if errors:
                for message in errors:
                    flash(message, "error")
                return render_template("category_form.html", category=category, name=name, description=description), 400

            db = get_db()
            db.execute(
                """
                UPDATE categories SET name = ?, description = ?, updated_at = ?
                where id = ?
                """,
                (name, description, current_timestamp(), category_id),
            )
            db.commit()
            log_audit_event("ADMIN_ACTION", "Info", f"Category '{name}' updated.")
            flash("Category updated", "success")
            return redirect(url_for("categories"))

        return render_template(
            "category_form.html",
            category=category,
            name=category["name"],
            description=category["description"],
        )

    @app.route("/categories/<int:category_id>/status", methods=["POST"])
    @login_required
    def category_status(category_id: int):
        user = g.current_user
        if not is_admin(user):
            abort(403)
        category = query_one("SELECT * FROM categories WHERE id = ?", (category_id,))
        if category is None:
            abort(404)

        action = request.form.get("action", "")
        if action == "retire" and category["status"] == "Active":
            new_status = "Retired"
        elif action == "activate" and category["status"] == "Retired":
            new_status = "Active"
        else:
            flash("Invalid category status action.", "error")
            return redirect(url_for("categories"))

        db = get_db()
        db.execute(
            """
            UPDATE categories SET status = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_status, current_timestamp(), category_id),
        )
        db.commit()
        log_audit_event("ADMIN_ACTION", "Info", f"Category '{category['name']}' was set to {new_status}.")
        flash(f"Category '{category['name']}' is now {new_status}.", "success")
        return redirect(url_for("categories"))

    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html")

    # error handler for 400
    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message="The request was invalid or missing required security data.")

    @app.errorhandler(403)
    def forbidden(error):
        log_audit_event("ACCESS_DENIED", "Warning", "Access to a protected area was denied.")
        return render_template("error.html", code=403, message="You are not allowed to access this page."), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("error.html", code=404, message="The requested item was not found."), 404

    @app.errorhandler(500)
    def server_error(error):
        app.logger.exception("Unhandled exception while processing a request.")
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

def log_audit_event(event_type: str, severity: str, message: str) -> None:
    user = g.get("current_user")
    actor_username = user["username"] if user else "Anonymous"
    department = user["department"] if user else "Unknown"
    db = get_db()
    db.execute(
        """
        INSERT INTO audit_events (event_type, severity, department, actor_username, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (event_type, severity, department, actor_username, message, current_timestamp()),
    )
    db.commit()
    app.logger.warning(
        "event=%s severity=%s actor=%s department=%s message=%s",
        event_type, severity, actor_username, department, message,
    )

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
