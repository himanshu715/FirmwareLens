import os
import secrets
from datetime import timedelta
from functools import wraps

from flask import Flask, Response, abort, g, redirect, render_template, request, send_file, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from api.pdf_report import generate_pdf
from config import (
    ADS_TXT_CONTENT,
    MAX_UPLOAD_SIZE,
    PREFERRED_URL_SCHEME,
    build_content_security_policy,
    ensure_runtime_dirs,
    public_origin,
)
from engine.analyzer import analyze_firmware
from engine.bot_support import build_chat_reply, build_field_issue_solution
from services.app_db import (
    authenticate_user,
    create_user,
    get_recent_bot_messages,
    get_recent_field_reports,
    get_scan_record,
    get_user_by_id,
    get_user_by_username,
    init_db,
    save_scan_record,
    save_bot_message,
    save_feedback,
    save_field_report,
)
from services.scan_store import (
    ScanStorageError,
    build_report_path,
    build_upload_path,
    create_scan_id,
    load_result,
    normalize_scan_id,
    persist_result,
    validate_upload,
)


ensure_runtime_dirs()
init_db()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["SESSION_COOKIE_NAME"] = "firmwarelens_session"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PREFERRED_URL_SCHEME"] = PREFERRED_URL_SCHEME
app.config["SESSION_COOKIE_SECURE"] = os.getenv(
    "COOKIE_SECURE",
    "1" if PREFERRED_URL_SCHEME == "https" else "0",
) == "1"
app.secret_key = os.getenv("FLASK_SECRET_KEY", "firmwarelens-dev-secret")
GA_MEASUREMENT_ID = os.getenv("GA_MEASUREMENT_ID", "").strip()
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


def is_guest_user(user=None):
    active_user = user or current_user()
    return bool(active_user and active_user.get("guest"))


def current_user():
    if hasattr(g, "_current_user"):
        return g._current_user

    raw_user = session.get("user")
    if not raw_user:
        g._current_user = None
        return None

    if isinstance(raw_user, dict):
        if raw_user.get("guest"):
            guest_token = str(raw_user.get("guest_token", "")).strip()
            if not guest_token:
                guest_token = secrets.token_urlsafe(16)
            guest_user = {"guest": True, "username": "Guest", "guest_token": guest_token}
            session["user"] = guest_user
            g._current_user = guest_user
            return guest_user

        user_id = raw_user.get("id")
        username = str(raw_user.get("username", "")).strip()
    elif isinstance(raw_user, str):
        user_id = None
        username = raw_user.strip()
    else:
        session.clear()
        g._current_user = None
        return None

    resolved = None
    if user_id is not None:
        resolved = get_user_by_id(user_id)
        if resolved:
            session["user"] = resolved
            g._current_user = resolved
            return resolved

    if username:
        resolved = get_user_by_username(username)
        if resolved:
            session["user"] = resolved
            g._current_user = resolved
            return resolved

    session.clear()
    g._current_user = None
    return None


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not current_user():
            return redirect(url_for("index", auth="login"))
        return view(*args, **kwargs)

    return wrapped_view


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def queue_analytics_event(name, params=None):
    events = session.get("_analytics_events", [])
    events.append({"name": name, "params": params or {}})
    session["_analytics_events"] = events[-10:]


def collect_analytics_events(extra_name=None, extra_params=None):
    events = session.pop("_analytics_events", [])
    if extra_name:
        events.append({"name": extra_name, "params": extra_params or {}})
    return events


def remember_guest_scan(scan_id):
    guest_scans = session.get("guest_scans", [])
    if scan_id not in guest_scans:
        guest_scans = (guest_scans + [scan_id])[-20:]
        session["guest_scans"] = guest_scans


def load_scan_for_user(scan_id, user):
    normalized_scan_id = normalize_scan_id(scan_id)

    if is_guest_user(user):
        if normalized_scan_id not in session.get("guest_scans", []):
            return None, "This guest session cannot access that scan."

        result = load_result(normalized_scan_id)
        if not result:
            return None, "This scan report is no longer available."

        return result, None

    scan_record = get_scan_record(normalized_scan_id)
    if not scan_record:
        return None, "This scan is not linked to your account or is no longer available."

    if scan_record.get("user_id") != user["id"]:
        abort(403, description="This scan is not available under your account.")

    result = load_result(normalized_scan_id)
    if not result:
        return None, "This scan report is no longer available."

    return result, None


def render_support(**context):
    user = current_user()
    analytics_events = collect_analytics_events(
        context.pop("analytics_event", None),
        context.pop("analytics_params", None),
    )
    return render_template(
        "support.html",
        user=user,
        bot_messages=get_recent_bot_messages(user["id"]) if user and not is_guest_user(user) else [],
        field_reports=get_recent_field_reports(user["id"]) if user and not is_guest_user(user) else [],
        guest_mode=is_guest_user(user),
        analytics_events=analytics_events,
        **context,
    )


def render_home(**context):
    user = context.pop("user", None) or current_user()
    auth_mode = context.pop("auth_mode", request.args.get("auth", "login"))
    analytics_events = collect_analytics_events(
        context.pop("analytics_event", None),
        context.pop("analytics_params", None),
    )
    return render_template(
        "index.html",
        user=user,
        auth_mode=auth_mode if auth_mode in {"login", "register"} else "login",
        analytics_events=analytics_events,
        **context,
    )


@app.context_processor
def inject_template_globals():
    return {
        "csrf_token": get_csrf_token(),
        "ga_measurement_id": GA_MEASUREMENT_ID,
        "site_origin": public_origin(request),
    }


@app.before_request
def protect_post_routes():
    if request.method != "POST":
        return None

    session_token = session.get("_csrf_token")
    form_token = request.form.get("csrf_token", "")

    if not session_token or not form_token or not secrets.compare_digest(session_token, form_token):
        abort(400, description="Your session expired or the form token is invalid. Refresh the page and try again.")

    return None


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return redirect(url_for("index", auth="register"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if password != confirm_password:
            return render_home(
                auth_mode="register",
                auth_error="Passwords do not match.",
                auth_values={"register_username": username},
            ), 400

        try:
            user = create_user(username, password)
        except ValueError as error:
            return render_home(
                auth_mode="register",
                auth_error=str(error),
                auth_values={"register_username": username},
            ), 400

        session.permanent = True
        session["user"] = user
        queue_analytics_event("sign_up", {"method": "password"})
        return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return redirect(url_for("index", auth="login"))

    if current_user():
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = authenticate_user(username, password)
        if not user:
            return render_home(
                auth_mode="login",
                auth_error="Invalid username or password.",
                auth_values={"login_username": username},
            ), 400

        session.permanent = True
        session["user"] = user
        queue_analytics_event("login", {"method": "password"})
        return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index", auth="login"))


@app.route("/guest-login", methods=["POST"])
def guest_login():
    session.clear()
    session.permanent = True
    session["user"] = {"guest": True, "username": "Guest", "guest_token": secrets.token_urlsafe(16)}
    session["guest_scans"] = []
    queue_analytics_event("guest_login", {"mode": "guest"})
    return redirect(url_for("index"))


@app.route("/")
def index():
    return render_home()


@app.route("/support")
@login_required
def support():
    scan_id = request.args.get("scan_id", "").strip()
    scan_result = None
    scan_error = None
    if scan_id:
        try:
            scan_result, scan_error = load_scan_for_user(scan_id, current_user())
        except ScanStorageError:
            scan_error = "Invalid scan identifier."

    return render_support(scan_id=scan_id, scan_result=scan_result, error=scan_error)


@app.route("/bot-chat", methods=["POST"])
@login_required
def bot_chat():
    user_message = request.form.get("message", "").strip()
    scan_id = request.form.get("scan_id", "").strip() or None
    scan_result = None

    if not user_message:
        return render_support(
            scan_id=scan_id or "",
            error="Please enter a question for Sentinel Bot.",
        ), 400

    if scan_id:
        try:
            scan_result, scan_error = load_scan_for_user(scan_id, current_user())
            if scan_error:
                return render_support(scan_id=scan_id, error=scan_error), 404
        except ScanStorageError:
            return render_support(scan_id=scan_id, error="Invalid scan identifier."), 400

    user = current_user()
    bot_response = build_chat_reply(user_message, scan_result)

    success_message = "Sentinel Bot replied to your question."
    if is_guest_user(user):
        success_message = "Sentinel Bot replied in guest mode. Create an account if you want chat history to be saved."
    else:
        save_bot_message(user["id"], scan_id, user_message, bot_response)

    return render_support(
        scan_id=scan_id or "",
        scan_result=scan_result,
        bot_reply=bot_response,
        last_user_message=user_message,
        success=success_message,
        analytics_event="bot_chat_used",
        analytics_params={"guest": is_guest_user(user), "has_scan_context": bool(scan_result)},
    )


@app.route("/feedback", methods=["POST"])
@login_required
def feedback():
    if is_guest_user():
        return render_support(error="Create an account to save feedback."), 403

    category = request.form.get("category", "general").strip()
    message = request.form.get("message", "").strip()
    rating = request.form.get("rating", "").strip()

    if not message:
        return render_support(error="Feedback message is required."), 400

    rating_value = int(rating) if rating.isdigit() else None
    try:
        save_feedback(current_user()["id"], rating_value, category, message)
    except ValueError as error:
        return render_support(error=str(error)), 400

    return render_support(
        success="Feedback saved. Thank you for helping improve Sentinel Bot.",
        analytics_event="feedback_submitted",
        analytics_params={"category": category},
    )


@app.route("/field-report", methods=["POST"])
@login_required
def field_report():
    title = request.form.get("title", "").strip()
    device_model = request.form.get("device_model", "").strip()
    firmware_version = request.form.get("firmware_version", "").strip()
    symptoms = request.form.get("symptoms", "").strip()
    environment = request.form.get("environment", "").strip()

    if not title or not symptoms:
        return render_support(error="Issue title and symptoms are required."), 400

    bot_solution = build_field_issue_solution(title, device_model, firmware_version, symptoms, environment)
    if is_guest_user():
        return render_support(
            generated_solution=bot_solution,
            success="Field guidance generated in guest mode. Create an account to save issue reports.",
            analytics_event="field_guidance_generated",
            analytics_params={"guest": True},
        )

    try:
        report_id = save_field_report(
            current_user()["id"],
            title,
            device_model,
            firmware_version,
            symptoms,
            environment,
            bot_solution,
        )
    except ValueError as error:
        return render_support(error=str(error)), 400

    return render_support(
        generated_solution=bot_solution,
        generated_report_id=report_id,
        success="Field issue report saved with bot-generated guidance.",
        analytics_event="field_issue_reported",
        analytics_params={"guest": False},
    )


@app.route("/health")
def health():
    return {"status": "ok", "app": "firmwarelens"}


@app.route("/robots.txt")
def robots_txt():
    origin = public_origin(request)
    lines = [
        "User-agent: *",
        "Allow: /",
    ]
    if origin:
        lines.append(f"Sitemap: {origin}/sitemap.xml")
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    origin = public_origin(request)
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        "  <url>\n"
        f"    <loc>{origin}/</loc>\n"
        "    <changefreq>weekly</changefreq>\n"
        "    <priority>1.0</priority>\n"
        "  </url>\n"
        "</urlset>\n"
    )
    return Response(body, mimetype="application/xml")


@app.route("/ads.txt")
def ads_txt():
    if not ADS_TXT_CONTENT:
        abort(404, description="ads.txt is not configured.")
    return Response(f"{ADS_TXT_CONTENT}\n", mimetype="text/plain")


@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    file = request.files.get("firmware")
    user = current_user()

    if file is None:
        return render_home(user=user, error="Please choose a firmware file."), 400

    payload = file.read()

    try:
        validate_upload(file.filename, len(payload))
    except ScanStorageError as error:
        return render_home(user=user, error=str(error)), 400

    scan_id = create_scan_id()
    file_path = build_upload_path(scan_id, file.filename)
    file_path.write_bytes(payload)
    if is_guest_user(user):
        remember_guest_scan(scan_id)
        save_scan_record(scan_id, None, file.filename, file_path.name)
    else:
        save_scan_record(scan_id, user["id"], file.filename, file_path.name)

    result = analyze_firmware(str(file_path))
    result["scan_id"] = scan_id
    persist_result(scan_id, result)

    return render_template(
        "result.html",
        result=result,
        user=user,
        app_mode="ui",
        analytics_events=collect_analytics_events(
            "scan_completed",
            {
                "guest": is_guest_user(user),
                "findings_count": result["all_findings_count"],
                "firmware_type": result["firmware_type"],
            },
        ),
    )


@app.route("/download-report")
@login_required
def download_report():
    scan_id = request.args.get("scan_id", "").strip()
    try:
        result, error = load_scan_for_user(scan_id, current_user())
    except ScanStorageError:
        abort(400, description="Invalid scan identifier.")

    if error:
        abort(404, description=error)

    file_path = build_report_path(scan_id)
    generate_pdf(result, str(file_path))
    return send_file(file_path, as_attachment=True, download_name=f"firmware_report_{scan_id}.pdf")


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = build_content_security_policy(
        enable_analytics=bool(GA_MEASUREMENT_ID)
    )
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=604800, immutable"
    elif request.path in {"/robots.txt", "/sitemap.xml", "/ads.txt"}:
        response.headers["Cache-Control"] = "public, max-age=3600"
    else:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(400)
def bad_request(error):
    description = getattr(error, "description", None) or "Invalid request."
    user = current_user()
    if user:
        if request.path.startswith("/support") or request.path in {"/bot-chat", "/feedback", "/field-report"}:
            return render_support(error=description), 400
        return render_home(user=user, error=description), 400
    auth_mode = "register" if request.path.startswith("/register") else "login"
    return render_home(auth_mode=auth_mode, auth_error=description), 400


@app.errorhandler(403)
def forbidden(error):
    description = getattr(error, "description", None) or "You do not have access to that resource."
    user = current_user()
    if user:
        return render_support(error=description), 403
    return render_home(auth_mode="login", auth_error=description), 403


@app.errorhandler(413)
def file_too_large(_error):
    user = current_user()
    if user:
        return render_home(user=user, error="File too large."), 413
    return render_home(auth_mode="login", auth_error="File too large."), 413


@app.errorhandler(500)
def internal_error(_error):
    session_user = current_user()
    if session_user:
        return render_support(
            error="Something went wrong internally. Please retry, and if the issue continues, submit a field issue report below.",
        ), 500
    return render_home(auth_mode="login", auth_error="Something went wrong internally. Please sign in again."), 500


if __name__ == "__main__":
    app.run(
        debug=os.getenv("FLASK_DEBUG") == "1",
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", os.getenv("FLASK_PORT", "5000"))),
    )
