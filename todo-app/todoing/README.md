# Todoing - Todo List App

Todoing is a simple todo list app built with Flask that allows you to manage and organize your tasks efficiently.

## Usage

To use the Todoing app, follow these steps:

1. Set up a virtual environment:

   ```bash
   python -m venv .venv
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Initialize the database:

   ```bash
   flask --app todoing init-db
   ```

   This command will create the necessary database tables to store your todo items.

4. Run the Todoing app:

   ```bash
   flask --app todoing run --debug
   ```

   The app will start running, and you can access it by navigating to `http://localhost:5000` in your web browser.

## Features

- Add new tasks with a title and description.
- Mark tasks as completed or not completed.
- Edit existing tasks to update their details.
- Delete tasks you no longer need.

## Technologies Used

- Flask: A lightweight web framework for Python.
- SQLite: A simple, serverless, and self-contained SQL database engine.
- HTML and CSS: Used for the frontend layout and styling.
