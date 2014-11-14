import logging
import sqlite3
import json, requests
import datetime
import parse_keys
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash

app = Flask(__name__)


# Constants
# TODO: Move this.
ADMIN_ROLE_OBJECT_ID = "ebn69igCXX"

# TODO: Change this to load a configuration file instead.
DEBUG = True
SECRET_KEY = 'development key'
USERNAME = 'admin'
PASSWORD = 'default'

app.config.from_object(__name__)


def parse_query(handler, endpoint, data=None,
        params=None, additional_headers=None):
    """ Creates a request to the Parse REST API.

    Args:
        endpoint: A string denoting the type of object requested.
        params: A string or dictionary denoting any query constraints.
        handler: The type of request method (either put, get, or post).
        additional_headers: Any headers besides the necessary application and
            rest API key headers.

    Returns:
        A JSON response of the results of the query.
    """
    headers = {"X-Parse-Application-Id": parse_keys.PARSE_APP_ID,
               "X-Parse-REST-API-Key": parse_keys.PARSE_REST_API_KEY,
               "Content-Type": "application/json"}
    if additional_headers != None:
        for key in additional_headers:
            headers[key] = additional_headers[key]

    response = handler(parse_keys.PARSE_HOSTNAME + endpoint, data=data,
        params=params, headers=headers)

    return response


def clean_chirps(chirps):
    """ Cleans up the dates and schools list in chirps for prettier display.
    Also deletes all unapproved expired chirps.

    Args:
        chirps: A list of dictionaries representing chirp objects.

    Returns:
        A list of dictionaries representing chirp objects, but with more
        readable entries.
    """
    # Current date and time.
    currentDateTime = datetime.datetime.now()
    chirpsToShow = []
    chirpsToDelete = []

    for chirp in chirps:
        # Extract the date from the chirp.
        dateStr = chirp['expirationDate']['iso']
        date = datetime.datetime.strptime(dateStr, '%Y-%m-%dT%H:%M:%S.%fZ')

        # If the chirp is expired, put it on the slate to delete.
        # Otherwise, clean up the fields so we can prettily show them on the
        # webpage.
        if date < currentDateTime:
            chirpsToDelete.append(chirp)
        else:
            chirp['expirationDate']['iso'] = date.strftime('%m/%d/%Y at %I:%M%p')

            # Create the string of schools and categories to display in the
            # chirp details
            chirp['schoolsStr'] = ", ".join(chirp['schools'])
            chirp['categoriesStr'] = ", ".join(chirp['categories'])

            # Convert strings to appropriate HTML class names.
            schoolsAndCategories = []
            for school in chirp['schools']:
                if ' ' in school:
                    schoolsAndCategories.append('-'.join(school.split(' ')))
                else:
                    schoolsAndCategories.append(school)
            for category in chirp['categories']:
                if ' ' in category:
                    schoolsAndCategories.append('-'.join(category.split(' ')))
                else:
                    schoolsAndCategories.append(category)

            chirp['schoolsAndCategoriesStr'] = ' '.join(schoolsAndCategories)

            # Look up user.
            chirp['user'] = '%s (%s)' % (chirp['user']['name'], chirp['user']['email'])

            chirpsToShow.append(chirp)

    if len(chirpsToDelete) > 0:
        # TODO: Send push notification to the user here about expiration and
        # unapproved.
        for chirp in chirpsToDelete:
            deleteChirp(chirp['objectId'])
        message = "Deleted " + str(len(chirpsToDelete)) + " chirps since the last admin login."
        flash(message)

    return chirpsToShow


def deleteChirp(chirpID):
    """ Deletes the chirp corresponding to the given chirp id from the Parse
        Cloud.
    """
    endpoint = '/1/classes/Chirp/%s' % chirpID
    headers = {"X-Parse-Session-Token": session['token']}
    parse_query(requests.delete, endpoint, additional_headers=headers)


def approveChirp(chirpID):
    """ Approves the chirp corresponding to the given chirp ID."""
    endpoint = '/1/classes/Chirp/%s' % chirpID
    headers = {"X-Parse-Session-Token": session['token']}
    data = {"chirpApproval":True}
    parse_query(requests.put, endpoint, data=json.dumps(data),
        additional_headers=headers)


@app.route('/')
def show_chirps():
    """ Creates the list of unapproved chirps to view. """

    # Force users to login
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # Create the parse query to get all unapproved chirps.
    endpoint = '/1/classes/Chirp'
    # TODO: Add something to show the admin that a chirp has expired.
    params = {'where': '{"chirpApproval":false}', 'order': 'expirationDate',
            'include':'user'}

    # list of dictionaries for each chirp in the query result
    response = parse_query(requests.get, endpoint, params=params)
    chirps = json.loads(response.text)['results']
    chirps = clean_chirps(chirps)

    return render_template('index.html', chirps=chirps)


@app.route('/', methods=['POST'])
def approve_or_reject_chirps():
    """ Handles the approving and rejecting of selected chirps. """
    # Can only approve chirps if logged in.
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # Grab all the ID's of chirps selected.
    chirps = request.form.getlist('chirpId')

    # Handles modifying the Chirps data to approved or deleting rejected chirps.
    # TODO: Send users push notifications for approve/reject.
    if request.form['submit'] == "Approve":
        for chirp in chirps:
            approveChirp(chirp)
    elif request.form['submit'] == "Reject":
        for chirp in chirps:
            deleteChirp(chirp)

    # TODO: Instead of re-rendering the page, use JQuery to remove the HTML
    # elements corresponding to the deleted chirps and hide them. However,
    # we may need to add another HTML attribute to the chirps like rejected
    # for those checked when the reject button is pressed. Then the JQuery for
    # filtering needs to be updated to make sure to not show chirp elements
    # with this attribute.
    return show_chirps()


# Login should check if the user is an admin, if so, log them in normally.
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # TODO: Better way to check if user is admin.
        # Create the parse query to get all users of the admin role
        endpoint = '/1/users'
        params = ('where={"$relatedTo" : {"object" : '
            '{"__type": "Pointer", "className" : "_Role", '
            '"objectId" : "%s"}, "key" : "users"}}' % ADMIN_ROLE_OBJECT_ID)
        response = parse_query(requests.get, endpoint, params=params)
        admins = json.loads(response.text)['results']

        # Check if the user is an admin
        isAdmin = False
        for admin in admins:
            if admin[u'email'] == email:
                isAdmin = True
                break
        if isAdmin:
            endpoint = '/1/login'
            params = {'username': email, 'password': password}
            headers = {"X-Parse-Application-Id": parse_keys.PARSE_APP_ID,
                       "X-Parse-REST-API-Key": parse_keys.PARSE_REST_API_KEY,
                       "Content-Type": "application/json"}
            user_response = parse_query(requests.get, endpoint, params=params)
            userResponseDict = json.loads(user_response.text)

            # Check if we logged in successfully, if not, give an error message.
            user_response = requests.get(parse_keys.PARSE_HOSTNAME + endpoint,
                    params=params, headers=headers)
            userResponseDict = json.loads(user_response.text)

            if u'error' not in userResponseDict:
                session['user_name'] = email
                session['logged_in'] = True
                session['token'] = userResponseDict['sessionToken']
                flash('You were logged in')
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

