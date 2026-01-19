from flask import Flask
from datetime import timedelta

app = Flask(__name__)

app.secret_key = "super-secret-key"
app.permanent_session_lifetime = timedelta(minutes=30)

app.config.update(
    SESSION_COOKIE_NAME="cpl_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # True in production
    SESSION_COOKIE_SAMESITE="Lax"
)

# ---- Blueprint imports ----
from student import student_bp
from admin import admin_bp
from teacher import teacher_bp

# ---- Register blueprints ----
app.register_blueprint(student_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(teacher_bp)

DB_PATH = "database/db.sqlite3"

import sqlite3
# ---------------- DATABASE ----------------
DB_PATH = "database/db.sqlite3"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/student/analytics")
def student_analytics():
    if session.get("role") != "student":
        return redirect("/")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT game_type, score
        FROM progress
        WHERE user_id=?
    """, (session["user_id"],))

    data = cursor.fetchall()
    conn.close()

    return render_template("analytics.html", data=data)

@app.route("/admin/disable-user/<int:user_id>", methods=["POST"])
def disable_user(user_id):
    if session.get("role") != "admin":
        return redirect("/")

    if user_id == session.get("user_id"):
        flash("You cannot disable your own account.", "error")
        return redirect("/admin/users")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET is_active = 0
        WHERE user_id=? AND school_id=?
    """, (user_id, session["school_id"]))

    conn.commit()
    conn.close()

    flash("User access disabled.", "success")
    return redirect("/admin/users")


# ---------------- LOGIN ----------------
from flask import render_template, request, redirect, session, flash

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        school_code = request.form.get("school_code")
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
    """
    SELECT users.user_id, users.role, users.school_id
    FROM users
    JOIN schools ON users.school_id = schools.school_id
    WHERE schools.school_code = ?
      AND users.email = ?
      AND users.password = ?
    """,
    (school_code, email, password)
)


        user = cursor.fetchone()
        conn.close()

        if user:
            session.permanent = True  # 🔥 IMPORTANT
            session["user_id"] = user["user_id"]
            session["role"] = user["role"].lower()
            session["school_id"] = user["school_id"]
            flash("Login successful", "success")
            return redirect("/dashboard")
        else:
            flash("Invalid credentials", "error")
    return render_template("login.html")

@app.before_request
def check_session_expiry():
    allowed_routes = ["/", "/static"]

    if request.path.startswith("/static"):
        return

    if "user_id" not in session and request.path not in allowed_routes:
        flash("Session expired. Please login again.", "error")
        return redirect("/")


def student_only():
    if session.get("role") != "student":
        return False
    return True


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect("/")


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    role = session.get("role")
    print("ROLE IN SESSION:", role)

    if role == "admin":
        return render_template("dashboard_admin.html")
    elif role == "teacher":
        return render_template("dashboard_teacher.html")
    elif role == "student":
        return render_template("dashboard_student.html")
    else:
        return redirect("/")



# ==================================================
# ================= ADMIN ROUTES ===================
# ==================================================

@app.route("/admin/add-student", methods=["GET", "POST"])
def add_student():
    if session.get("role") != "admin":
        return redirect("/")

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users (school_id, name, email, password, role)
            VALUES (?, ?, ?, ?, 'student')
            """,
            (session["school_id"], name, email, password)
        )

        conn.commit()
        conn.close()

        flash("Student added successfully", "success")
        return redirect("/admin/add-student")

    return render_template("add_student.html")




@app.route("/admin/add-teacher", methods=["GET", "POST"])
def add_teacher():
    if session.get("role") != "admin":
        return redirect("/")

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users (school_id, name, email, password, role)
            VALUES (?, ?, ?, ?, 'teacher')
            """,
            (session["school_id"], name, email, password)
        )

        conn.commit()
        conn.close()

        flash("Teacher added successfully", "success")
        return redirect("/admin/add-teacher")

    return render_template("add_teacher.html")

@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    # 🔐 Only admin allowed
    if session.get("role") != "admin":
        return redirect("/")

    # ❌ Prevent admin from deleting themselves
    if user_id == session.get("user_id"):
        flash("You cannot delete your own account.", "error")
        return redirect("/admin/users")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Optional: prevent deleting last admin
    cursor.execute("""
        SELECT COUNT(*) FROM users
        WHERE role='admin' AND school_id=?
    """, (session["school_id"],))
    admin_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT role FROM users WHERE user_id=?
    """, (user_id,))
    row = cursor.fetchone()

    if row and row["role"] == "admin" and admin_count <= 1:
        conn.close()
        flash("Cannot delete the last admin.", "error")
        return redirect("/admin/users")

    # ✅ Delete user
    cursor.execute("""
        DELETE FROM users
        WHERE user_id=? AND school_id=?
    """, (user_id, session["school_id"]))

    conn.commit()
    conn.close()

    flash("User removed successfully.", "success")
    return redirect("/admin/users")


@app.route("/admin/users")
def admin_users():
    if session.get("role") != "admin":
        return redirect("/")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT name, email, role
        FROM users
        WHERE school_id = ?
    """, (session["school_id"],))
    users = cursor.fetchall()
    conn.close()

    return render_template("view_users.html", users=users)
#TEACHER ROUTES

@app.route("/teacher/students")
def teacher_students():
    if session.get("role") != "teacher":
        return redirect("/")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT name, email
        FROM users
        WHERE role = 'student' AND school_id = ?
    """, (session["school_id"],))
    students = cursor.fetchall()
    conn.close()

    return render_template("teacher_students.html", students=students)


@app.route("/teacher/accounts")
def teacher_accounts():
    if session.get("role") != "teacher":
        return redirect("/")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT name, email, role
        FROM users
        WHERE school_id = ?
    """, (session["school_id"],))
    users = cursor.fetchall()
    conn.close()

    return render_template("teacher_accounts.html", users=users)


@app.route("/teacher/progress")
def teacher_progress():
    if session.get("role") != "teacher":
        return redirect("/")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT users.name, progress.game_type, progress.score, progress.played_at
        FROM progress
        JOIN users ON users.user_id = progress.user_id
        WHERE users.school_id = ?
        ORDER BY progress.played_at DESC
    """, (session["school_id"],))
    progress = cursor.fetchall()
    conn.close()

    return render_template("teacher_progress.html", progress=progress)





# STUDENT GAME ROUTES

@app.route("/student/true-false", methods=["GET", "POST"])
def true_false_game():
    # 🔐 Student only
    if session.get("role") != "student":
        return redirect("/")

    user_id = session.get("user_id")

    # Initialize game session
    if "tf_index" not in session:
        session["tf_index"] = 0
        session["tf_score"] = 0

    # Sample questions (can move to DB later)
    questions = [
        {"question": "Sharing your password with friends is safe.", "answer": "false"},
        {"question": "Using strong passwords helps protect accounts.", "answer": "true"},
        {"question": "Clicking unknown links is safe.", "answer": "false"},
        {"question": "Updating software improves security.", "answer": "true"},
        {"question": "Using the same password for multiple accounts is secure.", "answer": "false"},
        {"question": "Two-factor authentication adds an extra layer of security.", "answer": "true"},
        {"question": "Public Wi-Fi networks are always safe to use.", "answer": "false"},
        {"question": "Antivirus software can help detect malicious programs.", "answer": "true"},
        {"question": "Phishing emails often pretend to be from trusted sources.", "answer": "true"},
        {"question": "It is safe to download files from unknown websites.", "answer": "false"},
        {"question": "Logging out of accounts on shared computers is important.", "answer": "true"},
        {"question": "Cyber attacks only target large companies, not individuals.", "answer": "false"}
    ]

    # Handle answer submission
    if request.method == "POST":
        user_answer = request.form.get("answer")
        correct_answer = questions[session["tf_index"]]["answer"]

        if user_answer == correct_answer:
            session["tf_score"] += 10

        session["tf_index"] += 1

        # Game over
        if session["tf_index"] >= len(questions):
            final_score = session["tf_score"]

            # Save progress
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO progress (user_id, game_type, score)
                VALUES (?, ?, ?)
            """, (user_id, "True/False", final_score))
            conn.commit()
            conn.close()

            # Clear session
            session.pop("tf_index")
            session.pop("tf_score")

            return render_template("game_over.html", score=final_score)

        return redirect("/student/true-false")

    # GET → show current question
    current_question = questions[session["tf_index"]]

    return render_template(
        "true_false_game.html",
        question=current_question["question"],
        index=session["tf_index"] + 1,
        total=len(questions),
        score=session["tf_score"]
    )




@app.route("/student/scenario", methods=["GET", "POST"])
def scenario_game():
    # 🔐 Student-only
    if session.get("role") != "student":
        return redirect("/")

    user_id = session.get("user_id")

    # Initialize session
    if "sc_index" not in session:
        session["sc_index"] = 0
        session["sc_score"] = 0

    # Scenario questions
    scenarios = [
    {
        "question": "While checking your email, you receive a message that appears to be from your bank. It warns that your account will be suspended unless you immediately verify your login details.",
        "options": {
            "A": "Reply with your username and password",
            "B": "Click the link in the email and log in",
            "C": "Report the email as phishing",
            "D": "Forward the email to friends"
        },
        "correct": "C"
    },
    {
        "question": "You get a friend request on social media from someone claiming to be a mutual friend. Their profile has very few posts and no clear personal information.",
        "options": {
            "A": "Accept the request immediately",
            "B": "Start chatting to know more about them",
            "C": "Ignore or block the request",
            "D": "Share your phone number"
        },
        "correct": "C"
    },
    {
        "question": "A close friend messages you saying they are unable to access their account and urgently asks you to share the OTP that just arrived on your phone.",
        "options": {
            "A": "Share the OTP to help them",
            "B": "Ignore the message",
            "C": "Verify and then share the OTP",
            "D": "Refuse to share the OTP"
        },
        "correct": "D"
    },
    {
        "question": "You come across a free app online that promises premium features. During installation, it asks for access to your contacts, photos, and files.",
        "options": {
            "A": "Install it and allow all permissions",
            "B": "Ignore the permission requests",
            "C": "Check reviews and permissions before installing",
            "D": "Share the app link with friends"
        },
        "correct": "C"
    },
    {
        "question": "You receive a message saying you have won a prize and must click a link and enter personal details to claim it within a short time.",
        "options": {
            "A": "Click the link immediately",
            "B": "Share the message with others",
            "C": "Ignore the message",
            "D": "Enter your personal information"
        },
        "correct": "C"
    },
    {
        "question": "You use a public computer at a café or library to check your email and social media accounts.",
        "options": {
            "A": "Save your password for next time",
            "B": "Log out after finishing your work",
            "C": "Leave the account logged in",
            "D": "Turn off security alerts"
        },
        "correct": "B"
    }
]


    # Handle answer submission
    if request.method == "POST":
        user_answer = request.form.get("option")
        correct_answer = scenarios[session["sc_index"]]["correct"]

        if user_answer == correct_answer:
            session["sc_score"] += 10

        session["sc_index"] += 1

        # End game
        if session["sc_index"] >= len(scenarios):
            final_score = session["sc_score"]

            # Save progress
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO progress (user_id, game_type, score) VALUES (?, ?, ?)",
                (user_id, "Scenario Based", final_score)
            )
            conn.commit()
            conn.close()

            # Clear session
            session.pop("sc_index")
            session.pop("sc_score")

            return render_template("game_over.html", score=final_score)

        return redirect("/student/scenario")

    # GET → show current scenario
    current = scenarios[session["sc_index"]]

    return render_template(
        "scenario_game.html",
        question=current["question"],
        options=current["options"],
        index=session["sc_index"] + 1,
        total=len(scenarios),
        score=session["sc_score"]
    )



@app.route("/student/memory", methods=["GET", "POST"])
def memory_game():
    # 🔐 Student only
    if session.get("role") != "student":
        return redirect("/")

    user_id = session.get("user_id")

    # 🎚️ Level (easy / medium / hard)
    level = request.args.get("level", "easy")

    # When game finishes
    if request.method == "POST":
        final_score = int(request.form.get("score", 0))
        level = request.form.get("level", "easy")

        # Save progress
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""INSERT INTO progress (user_id, game_type, score)
        VALUES (?, ?, ?)
        """, (user_id, "Memory Game", final_score))

        conn.commit()
        conn.close()

        return render_template("game_over.html", score=final_score)

    # 🧠 Memory pairs (can be moved to DB later)
    all_pairs = {
        "easy": [
            {"term": "Password", "match_text": "Keeps your account secure"},
            {"term": "OTP", "match_text": "One-time password"},
            {"term": "Antivirus", "match_text": "Protects from malware"},
            {"term": "Firewall", "match_text": "Blocks unauthorized access"}
        ],
        "medium": [
            {"term": "Phishing", "match_text": "Fake email scam"},
            {"term": "Encryption", "match_text": "Secures data"},
            {"term": "VPN", "match_text": "Private internet connection"},
            {"term": "Malware", "match_text": "Harmful software"}
        ],
        "hard": [
            {"term": "SQL Injection", "match_text": "Database attack"},
            {"term": "DDoS", "match_text": "Traffic flood attack"},
            {"term": "Brute Force", "match_text": "Password guessing"},
            {"term": "Zero Day", "match_text": "Unknown vulnerability"}
        ]
    }

    pairs = all_pairs.get(level, all_pairs["easy"])

    return render_template(
        "memory_game.html",
        pairs=pairs,
        level=level
    )


@app.route("/student/drag-safety", methods=["GET", "POST"])
def drag_safety_game():
    # 🔐 Student-only access
    if session.get("role") != "student":
        return redirect("/")

    user_id = session.get("user_id")

    # Difficulty level
    level = request.args.get("level", "easy")

    # Actions per level
    all_actions = {
        "easy": [
            ("Using strong passwords", True),
            ("Sharing OTP with others", False),
            ("Installing antivirus software", True),
            ("Clicking unknown links", False),
        ],
        "medium": [
            ("Logging out of public computers", True),
            ("Saving passwords in browser", False),
            ("Using firewall", True),
            ("Downloading cracked software", False),
        ],
        "hard": [
            ("Enabling 2FA", True),
            ("Using public Wi-Fi for banking", False),
            ("Updating software regularly", True),
            ("Granting all app permissions", False),
        ]
    }

    actions = all_actions.get(level, all_actions["easy"])

    # Handle game finish
    if request.method == "POST":
        score = int(request.form.get("score", 0))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO progress (user_id, game_type, score)
            VALUES (?, ?, ?)
        """, (user_id, "Drag & Safety", score))
        conn.commit()
        conn.close()

        return render_template("game_over.html", score=score)

    return render_template(
        "drag_safety_game.html",
        actions=actions,
        level=level
    )


@app.route("/student/progress")
def student_progress():
    if session.get("role") != "student":
        return redirect("/")

    user_id = session.get("user_id")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT game_type, score
        FROM progress
        WHERE user_id = ?
        ORDER BY rowid DESC
    """, (user_id,))

    progress_data = cursor.fetchall()
    conn.close()

    return render_template(
        "my_progress.html",
        progress=progress_data
    )

@app.route("/student/quiz", methods=["GET", "POST"])
def quiz_game():
    if session.get("role") != "student":
        return redirect("/")

    user_id = session.get("user_id")

    # Initialize quiz session
    if "quiz_index" not in session:
        session["quiz_index"] = 0
        session["quiz_score"] = 0

    quiz_questions = [
        {
            "question": "What is phishing?",
            "options": [
                "A hacking technique",
                "A fake message to steal data",
                "A type of antivirus",
                "A secure login method"
            ],
            "correct": 1
        },
        {
            "question": "Which password is strongest?",
            "options": [
                "password123",
                "abcd1234",
                "P@ssw0rd!",
                "123456"
            ],
            "correct": 2
        },
        {
            "question": "What should you do if you receive an unknown link?",
            "options": [
                "Click immediately",
                "Ignore or report it",
                "Forward to friends",
                "Enter your details"
            ],
            "correct": 1
        },
        {
            "question": "What does OTP stand for?",
            "options": [
                "Online Transfer Password",
                "One Time Password",
                "Open Token Protocol",
                "Only Trusted Person"
            ],
            "correct": 1
        },
        {
            "question": "Which is safe on public Wi-Fi?",
            "options": [
                "Online banking",
                "Logging into email",
                "Using VPN",
                "Saving passwords"
            ],
            "correct": 2
        }
    ]

    # Handle answer
    if request.method == "POST":
        selected = int(request.form.get("option"))
        correct = quiz_questions[session["quiz_index"]]["correct"]

        if selected == correct:
            session["quiz_score"] += 10

        session["quiz_index"] += 1

        # End quiz
        if session["quiz_index"] >= len(quiz_questions):
            final_score = session["quiz_score"]

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO progress (user_id, game_type, score) VALUES (?, ?, ?)",
                (user_id, "Quiz Challenge", final_score)
            )
            conn.commit()
            conn.close()

            session.pop("quiz_index")
            session.pop("quiz_score")

            return render_template("game_over.html", score=final_score)

        return redirect("/student/quiz")

    # GET → current question
    current = quiz_questions[session["quiz_index"]]

    return render_template(
        "quiz_game.html",
        question=current["question"],
        options=current["options"],
        index=session["quiz_index"] + 1,
        total=len(quiz_questions),
        score=session["quiz_score"]
    )

@app.route("/student/phish", methods=["GET", "POST"])
def phish_game():
    if session.get("role") != "student":
        return redirect("/")

    user_id = session.get("user_id")

    # Initialize session
    if "phish_index" not in session:
        session["phish_index"] = 0
        session["phish_score"] = 0

    phish_scenarios = [
        {
            "text": "Your bank account is blocked. Click the link below to verify immediately.",
            "is_phish": True
        },
        {
            "text": "Your OTP is 456789. Do not share it with anyone.",
            "is_phish": False
        },
        {
            "text": "Congratulations! You won a prize. Enter your details to claim.",
            "is_phish": True
        },
        {
            "text": "Your password was changed successfully.",
            "is_phish": False
        },
        {
            "text": "Urgent: Login required to avoid account suspension.",
            "is_phish": True
        }
    ]

    # Handle answer
    if request.method == "POST":
        user_choice = request.form.get("choice")  # "phish" or "safe"
        correct = phish_scenarios[session["phish_index"]]["is_phish"]

        if (user_choice == "phish" and correct) or (user_choice == "safe" and not correct):
            session["phish_score"] += 10

        session["phish_index"] += 1

        # End game
        if session["phish_index"] >= len(phish_scenarios):
            final_score = session["phish_score"]

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO progress (user_id, game_type, score) VALUES (?, ?, ?)",
                (user_id, "Spot the Phish", final_score)
            )
            conn.commit()
            conn.close()

            session.pop("phish_index")
            session.pop("phish_score")

            return render_template("game_over.html", score=final_score)

        return redirect("/student/phish")

    # GET → current scenario
    current = phish_scenarios[session["phish_index"]]

    return render_template(
        "phish_game.html",
        text=current["text"],
        index=session["phish_index"] + 1,
        total=len(phish_scenarios),
        score=session["phish_score"]
    )

@app.route("/student/password-game", methods=["GET", "POST"])
def password_game():
    if session.get("role") != "student":
        return redirect("/")

    user_id = session.get("user_id")

    if request.method == "POST":
        score = int(request.form.get("score", 0))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO progress (user_id, game_type, score) VALUES (?, ?, ?)",
            (user_id, "Password Strength", score)
        )
        conn.commit()
        conn.close()

        return render_template("game_over.html", score=score)

    return render_template("password_game.html")


@app.route("/game/over")
def game_over():
    return render_template("game_over.html")


# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)
