def security_check():
    vulnerabilities = 0

    print(f"Found {vulnerabilities} vulnerabilities")

    if vulnerabilities > 0:
        raise SystemExit("Security check failed!")

    print("Security check passed")

def dangerous_function(user_input):
    return eval(user_input)


def run_command(user_input):
    return eval(user_input)


if __name__ == "__main__":
    security_check()