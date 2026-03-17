@app.route("/login")
def login():
    username = request.values.get("username")
    password = request.values.get("password")

    db = pymysql.connect("localhost")
    cursor = db.cursor()

    # Secure query using parameterized inputs
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    cursor.execute(query, (username, password))

    record = cursor.fetchone()

    if record:
        session["logged_user"] = username

    db.close()
