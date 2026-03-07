# {{cookiecutter.project_name}}

{{cookiecutter.description}}

## Features

- Django REST Framework
- JWT Authentication
- Custom User Model with OTP functionality
- API Documentation with Swagger
- CORS support
- Modern Python dependency management with uv
{% if cookiecutter.database == "postgresql" %}
- PostgreSQL database support
{% else %}
- SQLite database (development-ready)
{% endif %}

## Database Configuration

{% if cookiecutter.database == "postgresql" %}
This project is configured to use PostgreSQL with the following settings:
- Database: {{cookiecutter.postgres_db_name}}
- Host: {{cookiecutter.postgres_host}}
- Port: {{cookiecutter.postgres_port}}
- User: {{cookiecutter.postgres_user}}

Make sure PostgreSQL is installed and running before starting the application.
{% else %}
This project uses SQLite as the database, which requires no additional setup for development.
The database file will be created automatically when you run migrations.
{% endif %}

## Installation

1. Install dependencies:
```bash
uv sync
```

{% if cookiecutter.database == "postgresql" %}
2. Set up PostgreSQL database:
   - Ensure PostgreSQL is installed and running
   - Create the database:
   ```bash
   createdb {{cookiecutter.postgres_db_name}}
   ```
   - Or using psql:
   ```sql
   CREATE DATABASE {{cookiecutter.postgres_db_name}};
   ```
   - Update database credentials in settings.py if needed

3. Run migrations:
{% else %}
2. Run migrations:
{% endif %}
```bash
uv run python manage.py migrate
```

{% if cookiecutter.database == "postgresql" %}
4. Create a superuser:
{% else %}
3. Create a superuser:
{% endif %}
```bash
uv run python manage.py createsuperuser
```

{% if cookiecutter.database == "postgresql" %}
5. Start the development server:
{% else %}
4. Start the development server:
{% endif %}
```bash
uv run python manage.py runserver
```

## API Documentation

Once the server is running, visit:
- Swagger UI: http://localhost:8000/api/docs/
- ReDoc: http://localhost:8000/api/redoc/

## Author

{{cookiecutter.author_name}} ({{cookiecutter.author_email}})
