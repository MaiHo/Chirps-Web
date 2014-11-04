# TODO(Mai): Refactor this. 
# all the imports
import sqlite3
import json, requests
import datetime
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash

# For accessing the Parse backend
PARSE_HOSTNAME = 'https://api.parse.com'
PARSE_APP_ID = '***REMOVED***'
PARSE_REST_API_KEY = '***REMOVED***'

# configuration
DEBUG = True
SECRET_KEY = 'development key'
USERNAME = 'admin'
PASSWORD = 'default'

# create our little application :)
app = Flask(__name__)

# TODO: Change this to load a configuration file instead.
app.config.from_object(__name__)

# Helper function for creating parse REST API calls
def parseQuery(endpoint, params):
    headers = {"X-Parse-Application-Id": PARSE_APP_ID, 
                       "X-Parse-REST-API-Key": PARSE_REST_API_KEY,
                       "X-Parse-Session-Token": session['token'], 
                       "Content-Type": "application/json"}
    response = requests.get(PARSE_HOSTNAME + endpoint, 
        params=params, headers=headers)
    return response


@app.route('/')
def show_chirps():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    # entries = [dict(title=row[0], text=row[1]) for row in cur.fetchall()]
    # Create the parse query to get all unapproved chirps.
    endpoint = '/1/classes/Chirp'
    params = 'where={"chirpApproval":false}'
    response = parseQuery(endpoint, params)

    # list of dictionaries for each chirp in the query result
    chirps = json.loads(response.text)['results']

    # Clean up chirps for display
    for chirp in chirps:
        # Make the expiration date readable.
        dateStr = chirp['expirationDate']['iso']
        date = datetime.datetime.strptime(dateStr, '%Y-%m-%dT%H:%M:%S.%fZ')
        chirp['expirationDate']['iso'] = date.strftime('%m/%d/%Y %I:%M%p')

        # Create the string of schools to display
        schools = chirp['schools']
        schoolsStr = ''
        for index, school in enumerate(schools):
            if index == 0:
                schoolsStr += school
            else:
                schoolStr = ', %s' % school
                schoolsStr += schoolStr
        chirp['schools'] = schoolsStr

    return render_template('show_chirps.html', chirps=chirps)

@app.route('/', methods=['POST'])
def approveOrRejectChirps():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    chirps = request.form.getlist('chirpId')

    if request.form['submit'] == "Approve":
        for chirp in chirps:
            endpoint = '/1/classes/Chirp/%s' % chirp
            headers = {"X-Parse-Application-Id": PARSE_APP_ID, 
                       "X-Parse-REST-API-Key": PARSE_REST_API_KEY,
                       "X-Parse-Session-Token": session['token'], 
                       "Content-Type": "application/json"}
            params = {"chirpApproval":True}
            response = requests.put(PARSE_HOSTNAME + endpoint, 
                data=json.dumps(params), headers=headers)

    elif request.form['submit'] == "Reject":
        # delete chirps
        print ''
    return show_chirps()

# Login should check if the user is an admin, if so, log them in normally.
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Create the parse query to get all users of the admin role
        endpoint = '/1/users'
        headers = {"X-Parse-Application-Id": PARSE_APP_ID, 
                   "X-Parse-REST-API-Key": PARSE_REST_API_KEY, 
                   "Content-Type": "application/json"}
        params = 'where={"$relatedTo" : {"object" : {"__type": "Pointer", "className" : "_Role", "objectId" : "ebn69igCXX"}, "key" : "users"}}'
        response = requests.get(PARSE_HOSTNAME + endpoint, params=params, headers=headers)

        admins = json.loads(response.text)['results']


        # Check if the user is an admin
        isAdmin = False
        for admin in admins:
            if admin[u'email'] == email:
                isAdmin = True
                break

        if isAdmin:
            # log them in normally
            endpoint = '/1/login'
            params = {'username': email, 'password': password}
            user_response = requests.get(PARSE_HOSTNAME + endpoint, params=params, headers=headers)
            userResponseDict = json.loads(user_response.text)

            if u'error' not in userResponseDict:
                session['user_name'] = email
                session['logged_in'] = True
                session['token'] = userResponseDict['sessionToken']

                return redirect(url_for('show_chirps'))
            else:
                error = 'Wrong email/password combination.'
        else:
            error = 'Please login with an admin account.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_name', None)
    session.pop('token', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()