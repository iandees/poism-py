import copy
import os
import requests
import xml.etree.ElementTree as ET
from flask import Flask, jsonify, redirect, url_for, session, render_template, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from haversine import haversine
from rauth import OAuth1Service
from osm_presets import OSMPresets


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'secrket key'),
    OSM_CLIENT_ID=os.environ.get('OSM_CLIENT_ID'),
    OSM_CLIENT_SECRET=os.environ.get('OSM_CLIENT_SECRET'),
)
Bootstrap(app)

presets = OSMPresets()
presets.load_presets()

osm = OAuth1Service(
    name='osm',
    base_url='https://api.openstreetmap.org/api/0.6/',
    consumer_key=app.config.get('OSM_CLIENT_ID'),
    consumer_secret=app.config.get('OSM_CLIENT_SECRET'),
    request_token_url='https://www.openstreetmap.org/oauth/request_token',
    access_token_url='https://www.openstreetmap.org/oauth/access_token',
    authorize_url='https://www.openstreetmap.org/oauth/authorize',
)


class ChangesetClosedException(Exception):
    pass


class PoiForm(FlaskForm):
    name = StringField("Name")
    addr_housenumber = StringField("House Number")
    addr_street = StringField("Street")
    addr_city = StringField("City")
    addr_state = StringField("State")
    addr_postcode = StringField("Postcode")
    phone = StringField("Phone")
    website = StringField("Website")
    opening_hours_complex = StringField("Opening Hours")
    submit = SubmitField("Save")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    request_token, request_token_secret = osm.get_request_token()
    session.permanent = True
    session['request_token'] = request_token
    session['request_secret'] = request_token_secret
    authorize_url = osm.get_authorize_url(request_token)
    return redirect(authorize_url)


@app.route('/logout')
def logout():
    session.pop('request_token', None)
    session.pop('request_secret', None)
    session.pop('access_token', None)
    session.pop('access_token_secret', None)
    session.pop('user_name', None)
    return redirect(url_for('index'))


@app.route('/callback')
def callback():
    oauth_token = request.args.get('oauth_token')

    if oauth_token != session.get('request_token'):
        return redirect('logout')

    token = osm.get_access_token(session['request_token'], session['request_secret'])
    access_token, access_token_secret = token
    session['access_token'] = access_token
    session['access_token_secret'] = access_token_secret
    sess = osm.get_session(token)
    resp = sess.get('user/details')
    root = ET.fromstring(resp.text)
    user_name = root[0].attrib['display_name']
    session['user_name'] = user_name

    next_url = session.pop('next', None) or url_for('nearby')

    return redirect(next_url)


def get_pois_around(lat, lon, radius):
    radius = 'around:%d,%0.6f,%0.6f' % (radius, lat, lon)

    overpass_query = """[out:json][timeout:25];(
        node["name"]["leisure"]({bbox});
        way["name"]["leisure"]({bbox});
        node["name"]["amenity"]({bbox});
        way["name"]["amenity"]({bbox});
        node["name"]["shop"]({bbox});
        way["name"]["shop"]({bbox});
        node["name"]["tourism"]({bbox});
        way["name"]["tourism"]({bbox});
        );out center body;""".format(bbox=radius)
    resp = requests.post('https://overpass-api.de/api/interpreter', data=overpass_query)
    resp.raise_for_status()
    data = resp.json()

    def translate(obj):
        o = {
            'type': obj['type'],
            'id': obj['id'],
            'tags': obj['tags'],
        }

        name = o['tags'].get('name')
        if name:
            o['name'] = name

        if obj['type'] == 'node':
            o['center'] = (obj['lon'], obj['lat'])
        elif obj['type'] == 'way':
            o['center'] = (obj['center']['lon'], obj['center']['lat'])

        return o

    # Simplify the OSM/Overpass results into something consistent
    results = [translate(o) for o in data['elements']]
    # Sort the results by distance from center
    results.sort(key=lambda i: haversine((lon, lat), i['center']))

    return results


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
        radius = int(request.args.get('d') or 50)
    except:
        radius = 500

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
        next_radius=int(radius * 1.8),
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


def open_changeset():
    token = (session['access_token'], session['access_token_secret'])

    root = ET.Element('osm')
    root.attrib['version'] = "0.6"
    root.attrib['generator'] = "poism"
    cs_elem = ET.SubElement(root, 'changeset')
    created_by_elem = ET.SubElement(cs_elem, 'tag')
    created_by_elem.attrib['k'] = 'created_by'
    created_by_elem.attrib['v'] = 'poism'
    created_by_elem = ET.SubElement(cs_elem, 'tag')
    created_by_elem.attrib['k'] = 'comment'
    created_by_elem.attrib['v'] = 'Modifying a point of interest'
    cs_text = ET.tostring(root, encoding='unicode')

    sess = osm.get_session(token)
    resp = sess.put('changeset/create', data=cs_text, headers={'Content-Type': 'text/xml'})
    app.logger.info("Response from changeset create: %s", resp.text)
    resp.raise_for_status()
    changeset_id = int(resp.text)

    return changeset_id


def apply_change(new_obj, action, changeset_id):
    token = (session['access_token'], session['access_token_secret'])

    root = ET.Element('osmChange')
    root.attrib['version'] = "0.6"
    root.attrib['generator'] = "poism"
    modify_elem = ET.SubElement(root, action)
    obj_elem = obj_to_xml(new_obj)
    obj_elem.attrib['changeset'] = str(changeset_id)
    modify_elem.append(obj_elem)
    osc_text = ET.tostring(root, encoding='unicode')
    app.logger.info("Applying change: %s", osc_text)

    sess = osm.get_session(token)
    resp = sess.post('changeset/{}/upload'.format(changeset_id), data=osc_text, headers={'Content-Type': 'text/xml'})
    app.logger.info("Response from changeset upload: %s", resp.text)

    if resp.status_code == 409 and 'was closed at' in resp.text:
        raise ChangesetClosedException()
    else:
        resp.raise_for_status()

    root = ET.fromstring(resp.text)
    return {
        'id': root[0].attrib['new_id'],
        'version': root[0].attrib['new_version'],
    }


@app.route('/pois_around.geojson')
def pois_around():
    if 'user_name' not in session:
        return redirect(url_for('login'))

    lat = request.args.get('lat')
    if lat:
        lat = float(lat)

    lon = request.args.get('lon')
    if lon:
        lon = float(lon)

    if not (lat or lon):
        return jsonify({'error': "lat and lon are required"}), 400

    try:
        radius = int(request.args.get('d') or 50)
    except:
        radius = 500

    if radius > 1000:
        radius = 1000

    pois = get_pois_around(lat, lon, radius)

    fc = {
        'type': "FeatureCollection",
        'features': []
    }

    for p in pois:
        fc['features'].append({
            'id': "https://osm.org/%s/%s/" % (p['type'], p['id']),
            'type': "Feature",
            'geometry': {'type': "Point", 'coordinates': p['center']},
            'properties': {
                'name': p['name']
            }
        })

    return jsonify(fc)


@app.route('/<obj_type>/<int:obj_id>.geojson')
def object_as_geojson(obj_type, obj_id):
    if obj_type not in ('node', 'way'):
        return jsonify({'error': "Don't know how to build geojson for that type yet. Try node or way."}), 400

    if obj_type == 'way':
        resp = requests.get('https://www.openstreetmap.org/api/0.6/way/%d/full' % obj_id)
    elif obj_type == 'node':
        resp = requests.get('https://www.openstreetmap.org/api/0.6/node/%d' % obj_id)

    if resp.status_code == 404:
        return jsonify({'error': "That object doesn't exist."}), 404
    elif resp.status_code == 410:
        return jsonify({'error': "That object was deleted."}), 410
    elif resp.status_code != 200:
        return jsonify({'error': resp.text}), resp.status_code

    xml_resp = ET.fromstring(resp.text)

    feature = {
        'type': "Feature",
        'properties': {},
        'geometry': {},
    }
    if obj_type == 'way':
        thing = xml_resp.find('./way')

        # Build node cache
        nds = dict([
            (n.attrib['id'], (float(n.attrib['lon']), float(n.attrib['lat'])))
            for n in xml_resp.findall('./node')
        ])

        # Build the polyline or polygon
        coords = [
            nds[nd_ref.attrib['ref']]
            for nd_ref in thing.findall('./nd')
        ]

        # Rudimentary check to see if it's an area
        tags = dict([(t.attrib['k'], t.attrib['v']) for t in thing.findall('./tag')])
        if tags.get('area') == 'yes' or tags.get('building'):
            poly_or_linestring = 'Polygon'
            coords = [coords]
        else:
            poly_or_linestring = 'LineString'

        feature['geometry'] = {
            'type': poly_or_linestring,
            'coordinates': coords,
        }
    elif obj_type == 'node':
        thing = xml_resp.find('./node')

        feature['geometry'] = {
            'type': "Point",
            'coordinates': [
                float(thing.attrib['lon']),
                float(thing.attrib['lat']),
            ]
        }

    feature['properties'] = {
        'id': int(thing.attrib['id']),
        'visible': thing.attrib['visible'] == 'true',
        'version': int(thing.attrib['version']),
        'changeset': int(thing.attrib['changeset']),
        'timestamp': thing.attrib['timestamp'],
        'user': thing.attrib['user'],
        'uid': int(thing.attrib['uid']),
        'tags': dict([(t.attrib['k'], t.attrib['v']) for t in thing.findall('./tag')]),
    }

    return jsonify(feature)


@app.route('/edit/<obj_type>/<int:obj_id>', methods=['GET', 'POST'])
def edit_object(obj_type, obj_id):
    if 'user_name' not in session:
        session['next'] = request.url
        return redirect(url_for('login'))

    if obj_type not in ('node', 'way'):
        return redirect(url_for('index'))

    resp = requests.get('https://www.openstreetmap.org/api/0.6/{}/{}'.format(obj_type, obj_id))

    if resp.status_code != 200:
        app.logger.info("OSM API server returned HTTP %s for %s/%s", resp.status_code, obj_type, obj_id)
        return redirect(url_for('index'))

    root = ET.fromstring(resp.text)
    obj = parse_xml_obj(root[0])
    obj_tags = obj['tags']

    form = PoiForm()

    preset = presets.match_by_tags(obj_tags)
    fields = []
    if preset:
        fields = preset.get('fields')
        app.logger.info("Matches preset %s with fields %s", preset['name'], fields)

    if request.method == 'GET':

        if 'name' in fields:
            form.name.data = obj_tags.get('name')

        if 'address' in fields:
            form.addr_housenumber.data = obj_tags.get('addr:housenumber')
            form.addr_street.data = obj_tags.get('addr:street')
            form.addr_city.data = obj_tags.get('addr:city')
            form.addr_state.data = obj_tags.get('addr:state')
            form.addr_postcode.data = obj_tags.get('addr:postcode')

        if 'phone' in fields:
            form.phone.data = obj_tags.get('phone')

        if 'website' in fields:
            form.website.data = obj_tags.get('website')

        if 'opening_hours' in fields:
            opening_hours = obj_tags.get('opening_hours')
            form.opening_hours_complex.data = opening_hours

    if form.validate_on_submit():
        new_obj = copy.deepcopy(obj)

        if 'name' in fields:
            new_obj['tags']['name'] = form.name.data

        if 'address' in fields:
            new_obj['tags']['addr:housenumber'] = form.addr_housenumber.data
            new_obj['tags']['addr:street'] = form.addr_street.data
            new_obj['tags']['addr:city'] = form.addr_city.data
            new_obj['tags']['addr:state'] = form.addr_state.data
            new_obj['tags']['addr:postcode'] = form.addr_postcode.data

        if 'phone' in fields:
            new_obj['tags']['phone'] = form.phone.data

        if 'website' in fields:
            new_obj['tags']['website'] = form.website.data

        if 'opening_hours' in fields:
            new_obj['tags']['opening_hours'] = form.opening_hours_complex.data

        # Clear out tags that are empty
        empty_keys = [k for k,v in new_obj['tags'].items() if v is None]
        for k in empty_keys:
            del new_obj['tags'][k]

        changeset_id = session.get('changeset_id')
        if not changeset_id:
            changeset_id = open_changeset()
            session['changeset_id'] = changeset_id
            app.logger.info("Created a new changeset with ID %s", changeset_id)

        try:
            apply_change(new_obj, 'modify', changeset_id)
            app.logger.info("Saved changes to https://osm.org/%s/%s/%s", new_obj['type'], new_obj['id'], new_obj['version'])
        except ChangesetClosedException:
            app.logger.info("Changeset %s closed, opening a new one and trying again", changeset_id)
            session.pop('changeset_id', None)

            changeset_id = open_changeset()
            session['changeset_id'] = changeset_id
            app.logger.info("Created a new changeset with ID %s", changeset_id)

            apply_change(new_obj, 'modify', changeset_id)

        obj = new_obj

    return render_template(
        'edit_object.html',
        form=form,
        obj=obj,
        fields=fields,
        preset=preset,
    )


@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'user_name' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_obj = {
            'type': 'node',
            'version': 1,
            'id': -1,
            'lat': round(float(request.form.get('lat')), 6),
            'lon': round(float(request.form.get('lon')), 6),
            'tags': {},
        }

        for k, v in zip(request.form.getlist('keys'), request.form.getlist('values')):
            if not k and not v:
                continue
            elif new_obj['tags'].get(k) != v:
                new_obj['tags'][k] = v

        changeset_id = session.get('changeset_id')
        if not changeset_id:
            changeset_id = open_changeset()
            session['changeset_id'] = changeset_id
            app.logger.info("Created a new changeset with ID %s", changeset_id)

        try:
            created_obj = apply_change(new_obj, 'create', changeset_id)
            app.logger.info("Saved changes to https://osm.org/%s/%s/%s", new_obj['type'], new_obj['id'], new_obj['version'])
        except ChangesetClosedException:
            app.logger.info("Changeset %s closed, opening a new one and trying again", changeset_id)
            session.pop('changeset_id', None)

            changeset_id = open_changeset()
            session['changeset_id'] = changeset_id
            app.logger.info("Created a new changeset with ID %s", changeset_id)

            created_obj = apply_change(new_obj, 'create', changeset_id)

        return redirect(url_for('edit_object', obj_type='node', obj_id=created_obj['id']))

    else:
        return render_template(
            'add_object.html',
        )
