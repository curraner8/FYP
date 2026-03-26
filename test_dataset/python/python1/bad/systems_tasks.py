import os

def run_backup(params):
    folder = params['folder_name']
    # Vulnerable to command injection
    os.system("tar -czf backup.tar.gz " + folder)
