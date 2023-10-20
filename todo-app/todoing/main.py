from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from todoing.auth import login_required
from todoing.db import get_db

# Create a blueprint named 'todoing'
bp = Blueprint('todoing', __name__)

# Route for the main index page
@bp.route('/')
def index():
    db = get_db()
    if g is None:
        return render_template('main/index.html', todos=[])
    if g.user is not None:
        # Retrieve todos for the logged-in user
        todos = db.execute(
            "SELECT p.id, title, checked, created, author_id, email "
            "FROM todo p "
            "JOIN user u ON p.author_id = u.id "
            "WHERE p.author_id = ? "
            "ORDER BY created DESC;",
            (g.user['id'],)
        ).fetchall()

        # Handle todo creation through POST request
        if request.method == 'POST':
            title = request.form['title']
            checked = 0
            error = None

            if not title:
                error = 'Title is required.'

            if error is not None:
                flash(error)
            else:
                db = get_db()
                db.execute(
                    'INSERT INTO todo (title, checked, author_id)'
                    ' VALUES (?, ?, ?)',
                    (title, checked, g.user['id'])
                )
                db.commit()
                return redirect(url_for('todoing.index'))

        return render_template('main/index.html', todos=todos)
    else:
        return render_template('main/index.html', todos=[])

# Route for creating a new todo
@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        checked = 0
        error = None

        if not title:
            error = 'Title is required.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO todo (title, checked, author_id)'
                ' VALUES (?, ?, ?)',
                (title, checked, g.user['id'])
            )
            db.commit()
            return redirect(url_for('todoing.index'))

    return render_template('main/create.html')

# Function to retrieve a specific todo
def get_todo(id, check_author=True):
    todo = get_db().execute(
        'SELECT p.id, title, checked, created, author_id, email'
        ' FROM todo p JOIN user u ON p.author_id = u.id'
        ' WHERE p.id = ?',
        (id,)    
    ).fetchone()

    if todo is None:
        abort(404, f"Todo id {id} doesn't exist.")

    if check_author and todo['author_id'] != g.user['id']:
        abort(403)

    return todo

# Function to check if a todo is marked as checked
def is_checked(id):
    todo = get_todo(id)
    if todo['checked'] == 0:
        return False
    else:
        return True

# Route for checking/unchecking a todo
@bp.route("/check/<int:id>", methods=('GET', 'POST'))
def check(id):
    todo = get_todo(id)
    db = get_db()
    db.execute(
        'UPDATE todo SET checked = ?'
        ' WHERE id = ?',
        (not todo['checked'], id)
    )
    db.commit()
    return redirect(url_for('todoing.index'))

# Route for updating a todo
@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    todo = get_todo(id)

    if request.method == 'POST':
        title = request.form['title']
        checked = 0
        error = None

        if not title:
            error = 'Title is required.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE todo SET title = ?, checked = ?'
                ' WHERE id = ?',
                (title, checked, id)
            )
            db.commit()
            return redirect(url_for('todoing.index'))

    return render_template('main/update.html', todo=todo)

# Route for deleting a todo
@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    get_todo(id)
    db = get_db()
    db.execute('DELETE FROM todo WHERE id = ?', (id,))
    db.commit()
    return redirect(url_for('todoing.index'))
