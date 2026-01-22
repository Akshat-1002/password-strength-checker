from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# -------------------------------
# Password strength check (backend)
# -------------------------------
def is_strong_password(password: str) -> bool:
    if len(password) < 8:
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in "!@#$%^&*()-_+=<>?/{}[]|" for c in password):
        return False
    return True


@app.route("/", methods=["GET"])
def login_page():
    return render_template("signup.html")


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")

    # Backend enforcement
    if not is_strong_password(password):
        return render_template(
            "signup.html",
            error="Password is too weak. Use uppercase, lowercase, number and symbol."
        )

    # ✅ Any email allowed
    # ✅ Password strength enforced
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
