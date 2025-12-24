import csv
import datetime
import pytz
import requests
import urllib
import uuid

from flask import redirect, render_template, request, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


import yfinance as yf  # <--- Import the new library

def lookup(symbol):
    """Look up quote for symbol using yfinance."""
    try:
        # Create a Ticker object
        ticker = yf.Ticker(symbol)
        
        # Get the latest day's history
        # period="1d" fetches the most recent available data
        data = ticker.history(period="1d")

        # Check if data exists (if symbol is invalid, dataframe will be empty)
        if data.empty:
            return None

        # Extract the closing price from the last row
        # We use .iloc[-1] to get the last entry (most recent)
        price = data["Close"].iloc[-1]

        return {
            "price": price,
            "symbol": symbol.upper()
        }
    except Exception as e:
        # Print error to console for debugging, but return None to app
        print(f"Error looking up {symbol}: {e}")
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"
