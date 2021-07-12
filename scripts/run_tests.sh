pip install --user pipenv
cd /opt
python -m pipenv install --dev --ignore-pipfile
python -m pipenv run pytest
