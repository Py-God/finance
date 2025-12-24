# 📈 Flask Stock Trading Engine

A web-based stock trading simulation platform that allows users to "buy" and "sell" stocks in real-time using virtual currency. The application interfaces with the Yahoo Finance API to fetch live market data and manages user portfolios via a relational database.

## ⚙️ Key Features
* **Real-time Market Data:** Integrates with Yahoo Finance API to fetch live stock prices (Adjusted Close).
* **Portfolio Management:** Tracks user holdings, calculating total asset value dynamically based on current market rates.
* **Transaction Processing:** atomic handling of "Buy" and "Sell" orders, ensuring user balance and stock inventory are updated synchronously.
* **Audit Logging:** Maintains a separate history table to record every transaction for accounting and transparency.
* **Security:** Implements session-based authentication and password hashing (Scrypt) to secure user accounts.

## 🛠 Tech Stack
* **Backend:** Python, Flask
* **Database:** SQLite (Relational Design)
* **API:** Yahoo Finance
* **Frontend:** Jinja2 Templating, HTML/CSS, Bootstrap

## 🚀 How to Run Locally

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Py-God/finance-stock-app.git](https://github.com/Py-God/finance-stock-app.git)
    ```

2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Initialize the Database:**
    * Create a file named `finance.db`.
    * Run the SQL commands in `schema.sql` to set up your tables.

4.  **Configure API Key (Optional):**
    * *Note: This app uses a public Yahoo Finance endpoint, so no key is strictly required for basic functionality.*

5.  **Run the Application:**
    ```bash
    flask run
    ```

## 🧠 Database Schema Design
* **`Users`**: Stores authentication data and current cash balance.
* **`Transactions`**: Represents the current *state* of the user's portfolio (holdings per symbol).
* **`History`**: An append-only log of every action taken for audit purposes.