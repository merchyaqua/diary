import os
import re

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# export API_KEY=pk_5e7c41f93dd44c5486a30f99daadfbd3
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
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("postgres://awywxapixuwmgj:69d423becb0ed39ecf4493a9beaf3589c02784505c7937dd61129f206139be46@ec2-54-236-169-55.compute-1.amazonaws.com:5432/d290ae7p5vcp2v")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    li = db.execute("SELECT * FROM stocks WHERE shares > 0 AND id = :n", n=session["user_id"])
    total = 0
    for i in range(len(li)):
        li[i].update({"price": usd(lookup(li[i]["symbol"])["price"]), "total": usd(
            int(li[i]["shares"]) * lookup(li[i]["symbol"])["price"])})
        total += int(li[i]["shares"]) * lookup(li[i]["symbol"])["price"]
    cash = db.execute("SELECT cash FROM users WHERE id = :i", i=session["user_id"])[0]['cash']
    return render_template("index.html", table=li, cash=usd(cash), total=usd(total+cash), username=session["user_id"])


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        shares = request.form.get("shares")
        results = lookup(request.form.get("symbol"))
        # numcheck
        if not shares.isdigit():
            return apology("shares must be a positive number", 403)
        # stockcheck
        elif float(shares) < 1:
            return apology("shares must be stupoid")
        elif not results:
            return apology("stock not found", 404)
        total = results["price"] * float(shares)
        cash = db.execute(f"SELECT cash FROM users WHERE username = :d", d=session["username"])[0]["cash"]
        # cashcheckd
        if cash < total:
            return apology("you don't have enough cash")
        u = session["user_id"]
        # pay
        db.execute("UPDATE users SET cash = :v WHERE id = :u", v=cash-total, u=u)
        # update status, add the stock if not exist
        symbol = results["symbol"]
        # check if it exists
        if len(db.execute("SELECT * FROM stocks WHERE symbol = :s AND id = :u", u=u, s=symbol)) != 1:
            db.execute("INSERT INTO stocks (id, symbol, name, shares) VALUES (:u, :s, :n, :sh)", u=u, s=symbol, n=results["name"], sh=shares)
        else:
            db.execute("UPDATE stocks SET shares = shares + :sh WHERE symbol = :s AND id = :u", u=u, s=symbol, sh=shares)
        # record time and stuff
        db.execute("INSERT INTO history (symbol, shares, price, id, bs) VALUES (:s, :sh, :p, :i, 'Bought')",
                   s=symbol, sh=shares, p=results["price"], i=u)
        return redirect("/")
    return render_template("buy.html")


@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    """Show history of transactions"""
    # sorted according to time
    if request.method == "POST":
        if "CLEAR" == request.form.get("sort"):
            db.execute("DELETE FROM history WHERE id = :u", u=session["user_id"])
        else:
            db.execute("UPDATE users SET hsort = :s WHERE id = :u", s=request.form.get("sort"), u=session["user_id"])

    # if GET
    if db.execute("SELECT hsort FROM users WHERE id = :u", u=session["user_id"])[0]["hsort"] == "DESC":
        table = db.execute(
            "SELECT symbol, shares, price, transacted, bs FROM history WHERE id = :u ORDER BY transacted DESC", u=session["user_id"])
    else:
        table = db.execute(
            "SELECT symbol, shares, price, transacted, bs FROM history WHERE id = :u ORDER BY transacted ASC", u=session["user_id"])

    return render_template("history.html", table=table)


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if request.form.get("clear"):
            db.execute("DELETE FROM qhist WHERE username = :u", u=session["username"])
            return redirect("/quote")
        s = request.form.get("symbol")
        if not s:
            return apology("must provide stock symbol", 403)
        res = lookup(s)
        if not res:
            return apology("stock not found")
        if not db.execute("SELECT symbol FROM qhist WHERE username = :u", u=session["username"]):
            db.execute("INSERT INTO qhist (symbol, name, username) VALUES (:s, :n, :u)",
                       s=res["symbol"], n=res["name"], u=session["username"])
        elif not db.execute("SELECT * FROM qhist WHERE username = :u AND symbol = :s", u=session["username"], s=res["symbol"]):
            db.execute("INSERT INTO qhist (symbol, name, username) VALUES (:s, :n, :u)",
                       s=res["symbol"], n=res["name"], u=session["username"])
        else:
            db.execute("UPDATE qhist SET time = CURRENT_TIMESTAMP WHERE symbol = :s", s=res["symbol"])

        # table
        li = db.execute("SELECT symbol, name FROM qhist WHERE username = :u ORDER BY time DESC LIMIT 5;", u=session["username"])
        for i in range(len(li)):
            li[i].update({"price": usd(lookup(li[i]["symbol"])["price"])})

        return render_template("quote.html", quoted=True,
                               name=lookup(request.form.get("symbol"))["name"],
                               price=lookup(request.form.get("symbol"))["price"],
                               symbol=res["symbol"],
                               cash=db.execute("SELECT cash FROM users WHERE id=:i", i=session["user_id"])[0]["cash"],
                               recent=li
                               )

    # table
    li = db.execute("SELECT symbol, name FROM qhist WHERE username = :u ORDER BY time DESC LIMIT 5;", u=session["username"])
    for i in range(len(li)):
        li[i].update({"price": usd(lookup(li[i]["symbol"])["price"])})

    return render_template("quote.html", quoted=False, recent=li)


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
        elif re.search(" ", un) or re.search("^0|1|2|3|4|5|6|7|8|9", un):
            return apology("username must not contain spaces or start with a number")
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
        db.execute("INSERT INTO 'users' ('username', 'hash', 'length') VALUES (:u, :p, :l)",
                   u=un, p=generate_password_hash(pw), l=len(pw))
        # Remember which user has logged in
        session["user_id"] = db.execute("SELECT id FROM users WHERE username = :username",
                                        username=un)[0]["id"]
        session["username"] = un
        # Redirect user to home page
        return redirect("/")
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # money

        s = request.form.get("symbol")
        shares = request.form.get("shares")
        if not s or not shares:
            return apology("must provide all information")
        sh = db.execute("SELECT shares FROM stocks WHERE symbol = :s AND id = :u", u=session["user_id"], s=s)[0]["shares"]
        if int(shares) > int(sh):
            return apology(f"you don't have that many shares{shares}{sh}")
        # subtract the amount of shares
        db.execute("UPDATE stocks SET shares = shares - :sh WHERE symbol = :s AND id = :u", u=session["user_id"], sh=shares, s=s)
        # add money
        db.execute("UPDATE users SET cash = cash + :stp WHERE id = :i", stp=int(shares) * lookup(s)["price"], i=session["user_id"])
        # record time and stuff
        db.execute("INSERT INTO history (symbol, shares, price, id, bs) VALUES (:s, :sh, :p, :i, 'Sold')",
                   s=s, sh=shares, p=lookup(s)["price"], i=session["user_id"])

        return redirect("/")
    li = db.execute("SELECT symbol, shares FROM stocks WHERE shares > 0 AND id = :u", u=session["user_id"])
    return render_template("sell.html", li=li)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        un = request.form.get("changeun")
        pw = request.form.get("changepw")
        if not request.form.get("addcash") and not un and not pw:
            return apology("you filled in nothing")
        if request.form.get("addcash"):
            ca = int(request.form.get("addcash"))
            if ca <= 0 or ca > 100000:
                return apology(f"what, add ${ca}??")
            db.execute("UPDATE users SET cash = cash + :amount", amount=ca)
        elif pw:
            db.execute("UPDATE users SET hash = :h, length = :l", h=generate_password_hash(pw), l=len(pw))
        else:
            if len(un) > 15 :
                return apology("username is limited to 15 characters")
            if re.search(" ", un) or re.search("^0|1|2|3|4|5|6|7|8|9", un):
                return apology("username must not contain spaces or start with a number")
            if db.execute("SELECT * FROM users WHERE username = :un", un=un):
                return apology("username is taken")
            db.execute("UPDATE users SET username = :un WHERE id = :i", un=un, i=session["user_id"])
    length = db.execute("SELECT length FROM users WHERE id = :u", u=session["user_id"])[0]["length"]
    return render_template("account.html", cash=usd(db.execute("SELECT cash FROM users WHERE id = :u", u=session["user_id"])[0]["cash"]), stars="*" * length)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
