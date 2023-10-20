import sqlite3

import pytest
from todoing.db import get_db


#Checks the functionality of the get db function
#it compares consitency of getdb 
def test_get_close_db(app):
    with app.app_context():
        db = get_db()
        assert db is get_db()
#executes a query and expects eroor 
    with pytest.raises(sqlite3.ProgrammingError) as e:
        db.execute('SELECT 1')
#if sucessfully closed test is passed 
    assert 'closed' in str(e.value)

#checks CLI commands 
def test_init_db_command(runner, monkeypatch):
    class Recorder(object):
        called = False

    def fake_init_db():
        Recorder.called = True
        
    #replace the actual init_db function with the fake one.
    monkeypatch.setattr('todoing.db.init_db', fake_init_db)
    result = runner.invoke(args=['init-db'])
    assert 'Initialized' in result.output
    assert Recorder.called