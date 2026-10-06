def security_check():
    vulnerabilities = 1
    assert vulnerabilities == 0

    print(f"Found {vulnerabilities} vulnerabilities")

    if vulnerabilities > 0:
        raise SystemExit("Security check failed!")

    print("Security check passed")


if __name__ == "__main__":
    security_check()