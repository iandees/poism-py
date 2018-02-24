import copy
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


def get_pois_around(lat, lon, radius):
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

    try:
        radius = float(request.args.get('d') or 0.001)
    except:
        radius = 0.001

    if not lat or not lon:
        # Triggers geolocation on the browser
        pois = []
        request_geolocation = True
    else:
        pois = get_pois_around(lat, lon, radius)
        request_geolocation = False

    return render_template(
        'nearby.html',
        request_geolocation=request_geolocation,
        nearby_items=pois,
        radius=radius,
        next_radius=round(radius * 1.8, 4),
    )


def parse_xml_obj(xml_obj):
    obj = {
        'type': xml_obj.tag,
        'id': int(xml_obj.attrib['id']),
        'version': int(xml_obj.attrib['version']),
        'tags': dict(),
    }

    for t in xml_obj.findall('./tag'):
        obj['tags'][t.attrib['k']] = t.attrib['v']

    if obj['type'] == 'node':
        obj['lat'] = float(xml_obj.attrib['lat'])
        obj['lon'] = float(xml_obj.attrib['lon'])
    elif obj['type'] == 'way':
        obj['nds'] = []
        for t in xml_obj.findall('./nd'):
            obj['nds'].append(t.attrib['ref'])

    return obj


def obj_to_xml(obj):
    elem = ET.Element(obj['type'])
    elem.attrib['id'] = str(obj['id'])
    elem.attrib['version'] = str(obj['version'])

    for k, v in obj['tags'].items():
        t = ET.SubElement(elem, 'tag')
        t.attrib['k'] = k
        t.attrib['v'] = v

    if obj['type'] == 'node':
        elem.attrib['lat'] = str(obj['lat'])
        elem.attrib['lon'] = str(obj['lon'])
    elif obj['type'] == 'way':
        for nd in obj['nds']:
            n = ET.SubElement(elem, 'nd')
            n.attrib['ref'] = nd

    return elem


@app.route('/edit/<obj_type>/<int:obj_id>', methods=['GET', 'POST'])
def edit_object(obj_type, obj_id):
    if 'user_name' not in session:
        return redirect(url_for('login'))

    if obj_type not in ('node', 'way', 'relation'):
        return redirect(url_for('index'))

    resp = requests.get('https://www.openstreetmap.org/api/0.6/{}/{}'.format(obj_type, obj_id))

    if resp.status_code != 200:
        app.logger.info("OSM API server returned HTTP %s for %s/%s", resp.status_code, obj_type, obj_id)
        return redirect(url_for('index'))

    root = ET.fromstring(resp.text)
    obj = parse_xml_obj(root[0])

    if request.method == 'POST':
        new_obj = copy.deepcopy(obj)
        new_obj['version'] += 1

        change_made = False
        for k, v in zip(request.form.getlist('keys'), request.form.getlist('values')):
            if not k and not v:
                continue
            elif new_obj['tags'].get(k) != v:
                new_obj['tags'][k] = v
                print("Change made on key %s. From '%s' to '%s'" % (k, obj['tags'].get(k), new_obj['tags'].get(k)))
                change_made = True

        if not change_made:
            print("No change made")
            return redirect(url_for('edit_object', obj_type=obj_type, obj_id=obj_id))

        root = ET.Element('osmChange')
        root.attrib['version'] = "0.6"
        root.attrib['generator'] = "poism"
        modify_elem = ET.SubElement(root, 'modify')
        modify_elem.append(obj_to_xml(new_obj))

        print(ET.tostring(root, 'unicode'))

        obj = new_obj

    return render_template(
        'edit_object.html',
        obj=obj,
    )


@app.route('/add')
def add():

    return render_template(
        'add_object.html',
    )
