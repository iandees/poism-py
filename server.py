import os
import requests
import xml.etree.ElementTree as ET
from flask import Flask, redirect, url_for, session, render_template, request, Response
from flask_bootstrap import Bootstrap
from rauth import OAuth1Service


app = Flask(__name__)
app.config.update(
    SECRET_KEY='just a secret key, to confound the bad guys',
    DEBUG=True,
    OSM_CLIENT_ID=os.environ.get('OSM_CLIENT_ID'),
    OSM_CLIENT_SECRET=os.environ.get('OSM_CLIENT_SECRET'),
)
Bootstrap(app)

osm = OAuth1Service(
    name='osm',
    base_url='https://api.openstreetmap.org/api/0.6/',
    consumer_key=app.config.get('OSM_CLIENT_ID'),
    consumer_secret=app.config.get('OSM_CLIENT_SECRET'),
    request_token_url='https://www.openstreetmap.org/oauth/request_token',
    access_token_url='https://www.openstreetmap.org/oauth/access_token',
    authorize_url='https://www.openstreetmap.org/oauth/authorize',
)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    request_token, request_token_secret = osm.get_request_token()
    session['request_token'] = request_token
    session['request_secret'] = request_token_secret
    authorize_url = osm.get_authorize_url(request_token)
    return redirect(authorize_url)

@app.route('/logout')
def logout():
    session.pop('request_token', None)
    session.pop('request_secret', None)
    session.pop('user_name', None)
    return redirect('index')

@app.route('/callback')
def callback():
    oauth_token = request.args.get('oauth_token')

    if oauth_token != session.get('request_token'):
        return redirect('logout')

    sess = osm.get_auth_session(session['request_token'], session['request_secret'])
    resp = sess.get('user/details')
    root = ET.fromstring(resp.text)
    user_name = root[0].attrib['display_name']
    session['user_name'] = user_name

    return redirect(url_for('nearby'))


def get_pois_around(lat, lon):
    radius = 0.001
    bbox = ','.join(map(str, [
        lat - radius, lon - radius,
        lat + radius, lon + radius
    ]))
    overpass_query = """[out:json][timeout:25];(
        node["name"]["leisure"]({bbox});
        way["name"]["leisure"]({bbox});
        node["name"]["amenity"]({bbox});
        way["name"]["amenity"]({bbox});
        node["name"]["shop"]({bbox});
        way["name"]["shop"]({bbox});
        );out body;""".format(bbox=bbox)
    resp = requests.post('https://overpass-api.de/api/interpreter', data=overpass_query)
    resp.raise_for_status()
    data = resp.json()

    def translate(obj):
        o = {
            'obj_type': obj['type'],
            'obj_id': obj['id'],
            'tags': obj['tags'],
        }

        name = o['tags'].get('name')
        if name:
            o['name'] = name

        return o

    return [translate(o) for o in data['elements']]


@app.route('/edit/nearby')
def nearby():
    if 'user_name' not in session:
        return redirect(url_for('login'))

    lat = request.args.get('lat')
    if lat:
        lat = float(lat)

    lon = request.args.get('lon')
    if lon:
        lon = float(lon)

    if not lat or not lon:
        # Triggers geolocation on the browser
        pois = []
        request_geolocation = True
    else:
        pois = get_pois_around(lat, lon)
        request_geolocation = False

    return render_template(
        'nearby.html',
        request_geolocation=request_geolocation,
        nearby_items=pois,
    )

@app.route('/edit/<obj_type>/<int:obj_id>')
def edit_object(obj_type, obj_id):
    if 'user_name' not in session:
        return redirect(url_for('login'))

    return render_template('edit_object.html')
