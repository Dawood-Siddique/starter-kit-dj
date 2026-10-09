# Django REST API Template

A Cookiecutter template for creating Django REST API projects with modern best practices.

## Features

- Django REST Framework
- Authentication with django-allauth (headless, API-only): email/password signup, email verification
  and password reset by code, TOTP MFA, Google sign-in, JWT access/refresh tokens with rotation
- Custom email-based User Model
- API Documentation with drf-spectacular (Swagger/ReDoc)
- CORS support
- Modern Python dependency management with uv
- Well-structured app organization
- Database flexibility (SQLite or PostgreSQL)

## Usage

1. Install cookiecutter:
```bash
pip install cookiecutter
```

2. Generate a new project:
```bash
cookiecutter https://github.com/Dawood-Siddique/starter-kit-dj
```

3. Follow the prompts to customize your project

4. Navigate to your new project and start developing!

## What you'll be prompted for

- **project_name**: The human-readable name of your project
- **project_slug**: The technical name (used for directories and package names)
- **author_name**: Your name
- **author_email**: Your email address
- **description**: A brief description of your project
- **database**: Choose between SQLite (default) or PostgreSQL


## Template Structure

The generated project includes:

- **apps/**: Organized Django apps
- **core/**: Django project settings and configuration
- **Custom User Model**: Email-based, no username
- **Auth API**: django-allauth endpoints under `/_allauth/app/v1/`, documented at `/_allauth/openapi.html`
- **Tests**: Basic test structure
- **Modern tooling**: uv for dependency management

## Getting Started with Generated Project

After generating your project:

1. Install dependencies: `uv sync`
2. Set up your database:
   - **SQLite**: No setup required (database file is created automatically)
   - **PostgreSQL**: Create the database and ensure PostgreSQL is running
3. Run migrations: `uv run python manage.py migrate`
4. Create superuser: `uv run python manage.py createsuperuser`
5. Start server: `uv run python manage.py runserver`
6. Visit API docs: http://localhost:8000/api/docs/ (your API) and http://localhost:8000/_allauth/openapi.html (auth)

## License

This template is open source and available under the MIT License.
