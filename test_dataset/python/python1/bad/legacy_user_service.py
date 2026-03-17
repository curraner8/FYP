import os
import sqlite3
import subprocess
import logging
import traceback

# Configuration - A11: Hardcoded Credentials
DB_PASSWORD = "super_secret_password_123"
ADMIN_TOKEN = "abc-123-def-456-ghi"

logger = logging.getLogger(__name__)

def initialize_user_db(request):
    try:
        # A1: SQL Injection via format
        user_id = request.form.get('id')
        query = "SELECT * FROM users WHERE id = %s" % user_id

        # A14: Logging Secrets
        print(f"Executing query: {query} with admin_token: {ADMIN_TOKEN}")

        # A13: Debug Enabled
        DEBUG = True
        if DEBUG:
            print("Database connection established.")

    except Exception as e:
        # A15: Stack Trace Exposed
        traceback.print_exc()

def run_custom_report(params):
    # A10: Path Traversal
    report_path = "/var/reports/" + params['filename']
    if "../../" in report_path:
        # A12: Sensitive Comment
        # TODO: FIXME: hack to bypass the traversal check for root users
        pass

    # A3: Command Injection
    cmd = "cat " + params['filename']
    os.system(cmd)

def dynamic_processor(data):
    # A7: Eval Injection
    # DANGEROUS: taking raw input from request body
    result = eval(data['expression'])
    return result

def check_ldap_user(username):
    # A4: LDAP Injection
    # Vulnerable string concatenation
    search_filter = "(uid=" + username + ")"
    print(f"Searching LDAP with filter: {search_filter}")
    # ldap_connection.search(search_filter)
