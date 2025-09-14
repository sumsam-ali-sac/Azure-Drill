# FastAPI Authentication App

This project is a FastAPI application that provides user authentication functionalities, including registration, login, logout, and password management. It is structured to separate concerns, making it easy to maintain and extend.

## Project Structure

```
fastapi-auth-app
├── app
│   ├── __init__.py
│   ├── main.py
│   ├── core
│   │   ├── __init__.py
│   │   ├── auth
│   │   │   ├── __init__.py
│   │   │   ├── core.py
│   │   │   ├── session_management.py
│   │   │   └── common
│   │   │       ├── __init__.py
│   │   │       ├── constants.py
│   │   │       ├── exceptions.py
│   │   │       ├── middleware.py
│   │   │       └── schemas.py
│   │   └── database.py
│   ├── models
│   │   ├── __init__.py
│   │   └── user.py
│   ├── routes
│   │   ├── __init__.py
│   │   └── auth.py
│   └── utils
│       ├── __init__.py
│       └── security.py
├── alembic
│   └── (migration files)
├── alembic.ini
├── requirements.txt
└── README.md
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd fastapi-auth-app
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```
   uvicorn app.main:app --reload
   ```

2. Access the API documentation at `http://127.0.0.1:8000/docs`.

## Features

- User registration with email and password
- User login and logout
- Password reset functionality
- Role-based access control for admin routes
- OAuth integration for social logins
- Health check endpoint

## Database Migrations

This project uses Alembic for database migrations. To create a new migration, run:
```
alembic revision --autogenerate -m "migration message"
```

To apply migrations, run:
```
alembic upgrade head
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.