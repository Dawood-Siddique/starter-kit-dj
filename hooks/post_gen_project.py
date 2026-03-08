import os
import secrets
import string


def generate_secret_key():
    """Generates a secure 50-character Django secret key."""
    # Django keys usually contain alphanumeric characters and symbols
    chars = string.ascii_letters + string.digits + "!@#$%^&*(-_=+)"
    return ''.join(secrets.choice(chars) for _ in range(50))


def create_env_file():
    """Creates a .env file with a generated SECRET_KEY."""
    secret_key = generate_secret_key()

    # Define the content for the new .env file
    env_content = [
        f"SECRET_KEY='{secret_key}'",
        "DEBUG=True",
        "DJANGO_LOG_LEVEL='INFO'",
        "# Postgres Database Config (uncomment if using postgres)",
        "# POSTGRES_DB={{ cookiecutter.postgres_db_name }}",
        "# POSTGRES_USER={{ cookiecutter.postgres_user }}",
        "# POSTGRES_PASSWORD={{ cookiecutter.postgres_password }}",
        "# POSTGRES_HOST={{ cookiecutter.postgres_host }}",
        "# POSTGRES_PORT={{ cookiecutter.postgres_port }}",
    ]

    with open(".env", "w") as f:
        f.write("\n".join(env_content) + "\n")

    print("\nSUCCESS: .env file created with a cryptographically secure SECRET_KEY.")


if __name__ == "__main__":
    create_env_file()
