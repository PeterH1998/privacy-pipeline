import subprocess

user_input = input("Enter a command: ")

# Vulnerable: command injection
subprocess.call(user_input, shell=True)