import os

import sqlite3
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session, g
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# --- NEW DATABASE HELPER FUNCTION ---
def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    if 'db' not in g:
        g.db = sqlite3.connect("finance.db")
        # lets you access columns by name (row['symbol'])
        g.db.row_factory = sqlite3.Row 
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    """
    A custom wrapper to mimic db.execute.
    query: The SQL string
    args: A tuple of arguments to fill the ? placeholders
    one: If True, returns only the first result.
    """
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    # Automatically commit changes if it's an INSERT/UPDATE/DELETE
    get_db().commit() 
    return (rv[0] if rv else None) if one else rv
# ----------------------------------------


@app.route('/init-db')
def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
    return "Database Initialized!"


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""

    # get all the transactions made
    transactions = query_db("SELECT * FROM transactions WHERE user_id = ?", (session["user_id"], ))

    # get sum total of money spent on stocks
    total = 0
    for transaction in transactions:
        sum = transaction["shares"] * transaction["price"]
        total += sum

    # get user balance
    balance = query_db("SELECT cash FROM users WHERE id = ?", (session["user_id"],))

    # get total balance: user_balance + stock total
    total_balance = balance[0]["cash"] + total

    return render_template("index.html", transactions=transactions, balance=balance[0]["cash"], total_balance=total_balance)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # get symbol data
        data = lookup(symbol)

        # validate symbol and shares have an input
        if not data or not shares:
            return apology("Invalid symbol or shares.")

        # validate shares is integer
        try:
            shares = int(shares)
        except ValueError:
            return apology("Shares should be an integer.")

        # validate shares is a positive integer
        if shares < 1 or type(shares) != int:
            return apology("Shares should be positive integer.")

        # get symbol price
        price = data["price"]

        # get how much is in the user's account
        user_balance = query_db("SELECT cash FROM users WHERE id = ?", (session["user_id"],))

        # get current time
        time = datetime.now()

        # ensure user can afford number of shares
        total_amount = shares * price
        if user_balance[0]["cash"] < total_amount:
            return apology("Insufficient balance")

        # get data from transactions table
        transactions = query_db(
            "SELECT * FROM transactions WHERE user_id = ?", (session["user_id"],))

        # update the amount of shares i have for that symbol
        for transaction in transactions:
            if transaction["symbol"] == data["symbol"]:
                query_db(
                    "UPDATE transactions SET shares = ? WHERE symbol = ? AND user_id = ?",
                    shares + transaction["shares"],
                    (data["symbol"], session["user_id"])
                )
                query_db(
                    "UPDATE users SET cash = ? WHERE id = ?",
                    user_balance[0]["cash"] - total_amount,
                    (session["user_id"],)
                )
                query_db(
                    "INSERT INTO history (user_id, symbol, shares, price, time) VALUES(?, ?, ?, ?, ?)",
                    (session["user_id"], data["symbol"], shares, price, time)
                )
                return redirect("/")

        query_db(
            "INSERT INTO transactions (user_id, symbol, shares, price, time) VALUES(?, ?, ?, ?, ?)",
            (session["user_id"], data["symbol"], shares, price, time)
        )
        query_db(
            "INSERT INTO history (user_id, symbol, shares, price, time) VALUES(?, ?, ?, ?, ?)",
            (session["user_id"], data["symbol"], shares, price, time)
        )

        # reduce user balance
        query_db("UPDATE users SET cash = ? WHERE id = ?",
                   (user_balance[0]["cash"] - total_amount, session["user_id"]))

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # get all the transactions made
    history = query_db("SELECT * FROM history WHERE user_id = ?", (session["user_id"],))

    return render_template("history.html", history=history)


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
        rows = query_db(
            "SELECT * FROM users WHERE username = ?", (request.form.get("username"),)
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
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

    # check method
    if request.method == "POST":
        # check search value
        search = request.form.get("symbol")

        # get search value price and symbol
        data = lookup(search)

        # check for valid search
        if not data:
            return apology("Invalid search.")

        price = data["price"]
        symbol = data["symbol"]

        # render another template that displays the price and symbol
        return render_template("quoted.html", price=price, symbol=symbol)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # check the method
    if request.method == "POST":

        # get all form parameters
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # check if passwords match
        if password != confirmation:
            return apology("Passwords do not match.")
        elif not password or not confirmation or not username:
            return apology("You have to provide a username and password and confirm it.")

        # generate password hash
        hash = generate_password_hash(password, method="scrypt", salt_length=16)

        # check if username exists already
        try:
            query_db("INSERT INTO users (username, hash) VALUES(?, ?)", (username, hash))
        except ValueError:
            return apology("Username already exists")

        # success: redirect back to login page
        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # get method
    if request.method == "POST":

        # get owned stocks
        transactions = query_db(
            "SELECT * FROM transactions WHERE user_id = ?", (session["user_id"],))

        stocks = [transaction["symbol"] for transaction in transactions]

        symbol = request.form.get("symbol")

        data = lookup(symbol)

        if not symbol:
            return apology("Invalid symbol")

        if symbol not in stocks:
            return apology("You do not have any shares of that symbol")

        # validate shares is integer
        shares = request.form.get("shares")
        try:
            shares = int(shares)
        except ValueError:
            return apology("Shares should be an integer.")

        # validate shares is a positive integer
        if shares < 1 or type(shares) != int:
            return apology("Shares should be positive integer.")

        # check if users has that amount of shares or less
        user_shares = db.execute(
            "SELECT shares FROM transactions WHERE symbol = ? AND user_id = ?", symbol, session["user_id"])[0]["shares"]
        if user_shares < shares:
            return apology("You don't have enough shares of that Symbol")

        # sell the shares
        shares_available = user_shares - shares

        # update transactions table to reflect the sale
        user_balance = query_db("SELECT cash FROM users WHERE id = ?",
                                  (session["user_id"],))[0]["cash"]

        if shares_available > 0:
            query_db("UPDATE transactions SET shares = ? WHERE symbol = ? AND user_id = ?",
                       (shares_available, symbol, session["user_id"]))
            query_db("UPDATE users SET cash = ? WHERE id = ?", user_balance +
                       ((shares * data["price"]), session["user_id"]))

            query_db("INSERT INTO history (user_id, symbol, shares, price, time) VALUES(?, ?, ?, ?, ?)",
                       (session["user_id"], data["symbol"], shares * -1, data["price"], datetime.now()))
            return redirect("/")
        else:
            query_db("DELETE FROM transactions WHERE symbol = ? AND user_id = ?",
                       (symbol, session["user_id"]))
            query_db("UPDATE users SET cash = ? WHERE id = ?", user_balance +
                       ((shares * data["price"]), session["user_id"]))

            query_db("INSERT INTO history (user_id, symbol, shares, price, time) VALUES(?, ?, ?, ?, ?)",
                       (session["user_id"], data["symbol"], shares * -1, data["price"], datetime.now()))
            return redirect("/")
    else:
        # get transactions data
        transactions = query_db(
            "SELECT * FROM transactions WHERE user_id = ?", (session["user_id"],))
        return render_template("sell.html", transactions=transactions)


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        username = request.form.get("username")
        new = request.form.get("new")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Invalid username.")

        name = query_db("SELECT username FROM users WHERE username = ?", (username,))
        if not name:
            return apology("Username does not exist")
        if username != name[0]["username"]:
            return apology("Username does not exist")

        if not new or not confirmation:
            return apology("You did not provide a password")

        new_password_hash = generate_password_hash(new, method="scrypt", salt_length=16)
        query_db("UPDATE users SET hash = ? WHERE username = ?", (new_password_hash, username))
        return redirect("/login")

    else:
        return render_template("change_password.html")
