import os
import re


from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, ordinal

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///diary.db")


# connection = psycopg2.connect(database="d290ae7p5vcp2v", user="awywxapixuwmgj", password="69d423becb0ed39ecf4493a9beaf3589c02784505c7937dd61129f206139be46", host="ec2-54-236-169-55.compute-1.amazonaws.com", port=5432)

# db = connection.cursor()

@app.route("/")
@login_required
def index():
    """Show welcome and recent entries, status etc."""

    amount = db.execute("SELECT COUNT(entry) FROM entries WHERE id = :i", i=session["user_id"])[0]["COUNT(entry)"]
    return render_template("index.html", username=session["user_id"], amount=amount)


@app.route("/new", methods=["GET", "POST"])
@login_required
def new():
    """New Entries"""
    amount = db.execute("SELECT COUNT(entry) FROM entries WHERE id = :i", i=session["user_id"])[0]["COUNT(entry)"]
    if request.method == "POST":
        title = request.form.get("title")
        entry = request.form.get("entry")
        # numcheck
        if not entry:
            return apology("Whoa...is your day that empty?", 403)

        u = session["user_id"]
        # insert
        db.execute("INSERT INTO entries (id, entry, title, entryid) VALUES (:i, :e, :t, :a)", i=u, e=entry, t=title, a=amount)
        return redirect("/entries")
    return render_template("new.html", amount=ordinal(amount + 1))


@app.route("/entries", methods=["GET", "POST"])
@login_required
def entries():
    """Show existing entries"""
    # sorted according to time
    if request.method == "POST":
        if "CLEAR" == request.form.get("sort"):
            db.execute("DELETE FROM history WHERE id = :u", u=session["user_id"])
        else:
            db.execute("UPDATE users SET hsort = :s WHERE id = :u", s=request.form.get("sort"), u=session["user_id"])

    # if GET
    # if db.execute("SELECT hsort FROM users WHERE id = :u", u=session["user_id"])[0]["hsort"] == "DESC":
    table = db.execute("SELECT title, date FROM entries WHERE id = :u ORDER BY date DESC", u=session["user_id"])
    return render_template("entries.html", entries=table)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/friends", methods=["GET", "POST"])
@login_required
def friends():
    """Add and view friends"""
    if request.method == "POST":
        return
    return render_template("friends.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        pw = request.form.get("password")
        un = request.form.get("username")
        # Ensure username was submitted
        if not un:
            return apology("must provide username", 403)
        # if username taken
        elif db.execute("SELECT username FROM users WHERE username = :username", username=un):
            return apology("username is already taken", 403)
        elif re.search(" ", un):
            return apology("username must not contain spaces")
        # Ensure password was submitted
        elif not pw:
            return apology("must provide password", 403)
        elif len(un) > 15 :
            return apology("username is limited to 15 characters")
        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 403)
        # compare passwords:
        elif pw != request.form.get("confirmation"):
            return apology("password don't match", 403)
        # database
        db.execute("INSERT INTO users ('username', 'hash', 'length') VALUES (:u, :p, :l)",
                   u=un, p=generate_password_hash(pw), l=len(pw))
        # Remember which user has logged in
        session["user_id"] = db.execute("SELECT id FROM users WHERE username = :username",
                                        username=un)[0]["id"]
        session["username"] = un
        # Redirect user to home page
        return redirect("/")
    return render_template("register.html")


@app.route("/advice", methods=["GET", "POST"])
@login_required
def advice():
    """Ask for advice"""
    if request.method == "POST":
        # is it a post or comment
        return
    return render_template("advice.html")


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        un = request.form.get("changeun")
        pw = request.form.get("changepw")
        if not request.form.get("add") and not un and not pw:
            return apology("you filled in nothing")
        if request.form.get("add"):
            ca = int(request.form.get("add"))
            if ca <= 0 or ca > 100000:
                return apology(f"what, add ${ca}??")
            db.execute("UPDATE users SET  =  + :amount", amount=ca)
        elif pw:
            db.execute("UPDATE users SET hash = :h, length = :l", h=generate_password_hash(pw), l=len(pw))
        else:
            if len(un) > 15 :
                return apology("username is limited to 15 characters")
            if re.search(" ", un) or re.search("^0|1|2|3|4|5|6|7|8|9", un):
                return apology("username must not contain spaces or start with a number")
            if db.execute("SELECT username FROM users WHERE username = :u", u=un):
                return apology("username is taken")
            db.execute("UPDATE users SET username = :un WHERE id = :i", un=un, i=session["user_id"])
    length = db.execute("SELECT length FROM users WHERE id = :u", u=session["user_id"])[0]["length"]
    return render_template("account.html", u=session["user_id"], stars="*" * length)

@app.route("/notifications", methods=["GET", "POST"])
@login_required
def notifs():
    """Show messages"""
    if request.method == "POST":
        return
    return render_template("advice.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
