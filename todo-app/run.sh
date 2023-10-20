#!/bin/bash

python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
pip3 install -U Flask Authlib requests

# Ask the user if they want to run init-db
read -p "Do you want to run init-db? (yes/no): " run_init_db

if [ "$run_init_db" == "yes" ]; then
    flask --app todoing init-db
fi

flask --app todoing run --debug --port 8080