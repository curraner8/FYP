def get_user_data(request):
    user_id = request.args.get('id')
    # Vulnerable to SQLi via string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
