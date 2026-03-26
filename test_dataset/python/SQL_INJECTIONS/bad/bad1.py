# https://brightsec.com/blog/sql-injection-python/

# The following example shows a SQL injection vulnerability in a Flask application. It is based on code provided by SecureFlag.
# The application defines a route for the URL /login and requests credentials from the user:


@app.route("/login")
def login():
    username = request.values.get("username")
    password = request.values.get("password")


# Next, the application connects to a database running on the localhost:
db = pymysql.connect("localhost")
cursor = db.cursor()

# This part of the application is vulnerable to SQL injection. The app runs a SQL query in which it insecurely concatenates the username and password fields:
cursor.execute(
    "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
    % (username, password)
)

# If the query returns a matching record, the application logs the user in:
record = cursor.fetchone()

if record:
    session["logged_user"] = username
    db.close()

# Because the application accepts user inputs and processes them with no validation as part of the SQL query, it is possible for the attacker to switch context and override the authentication mechanism.
