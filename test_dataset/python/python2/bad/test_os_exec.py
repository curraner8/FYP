import os
import subprocess


def cleanup_logs(user_input_path):
    # B2: Direct OS System call
    os.system("rm -rf /var/log/app/" + user_input_path)

    # B6: Subprocess with shell=True (Critical risk)
    subprocess.call("ls " + user_input_path, shell=True)


cleanup_logs("temp_dir; cat /etc/passwd")
