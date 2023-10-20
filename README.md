# CS 344 Himalia Project: ENT4 - Oh, Authenticate Me Please

## Contact

Keegan Norton: keegan@entersekt.com  
Christoff Jordaan: cjordaan@entersekt.com

This project involves creating an OAuth2 authentication provider with an account creation and login screen. The login screen will be used to authenticate users. An authorization server and a resource server will be built, allowing clients to request access. The full explicit OAuth2 flow will be implemented.

## Technology Stack

- Python
- Flask

## Group Members

- Joshua Bodenstein
- Danel Adendorff
- Migael van Wyk
- Daanshil Ramgutty
- Schalk Visagie

# Sprint demo meetings:

1. 30 August
   **Link to video recording:**
   https://stellenbosch-my.sharepoint.com/:v:/g/personal/24051055_sun_ac_za/EciO02U6DnZNmDx_-aOoQrcBg1lX0cpfRX8XHTTcFkfzqQ?nav=eyJyZWZlcnJhbEluZm8iOnsicmVmZXJyYWxBcHAiOiJTdHJlYW1XZWJBcHAiLCJyZWZlcnJhbFZpZXciOiJTaGFyZURpYWxvZyIsInJlZmVycmFsQXBwUGxhdGZvcm0iOiJXZWIiLCJyZWZlcnJhbE1vZGUiOiJ2aWV3In19&e=FDvyjs
2. 29 September
   **Link to video recording:**
   https://entersekt-my.sharepoint.com/:v:/p/keegan/EYnm0gEvh3RDtkFs_Dd9DY4BRP0LlhLLF-I1fLmKQYAmcA

# Installation of Todoing

1. Clone the repo onto your local machine

2. Navigate into `todo-app` folder

```bash
cd todo-app
```

3. Run the bash script

```bash
bash run.sh
```

The script will install all the dependencies and run the application

##Testing:

1. To run the tests, navigate to the `todo-app` folder.

2. Run the following command:

```bash
 python -m pytest tests/
```

This command will execute the tests and display coverage as well as the test results.

3. To get a coverage report, run:

```bash
coverage report -m
```

**For testing Himalia:**

1. To run the tests, navigate to the `auth-provider` folder.

2. Run the following command:

```bash
pytest
```

3. To get a coverage report, run:

```bash
pytest -cov=Himalia
```
# himalia
