import copy
import os
import requests
import xml.etree.ElementTree as ET
from flask import Flask, flash, jsonify, make_response, redirect, url_for, session, render_template, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from haversine import haversine
from osm_presets import OSMPresets
from werkzeug.middleware.proxy_fix import ProxyFix
from requests_oauthlib import OAuth2Session


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'secrket key'),
    OSM_CLIENT_ID=os.environ.get('OSM_CLIENT_ID'),
    OSM_CLIENT_SECRET=os.environ.get('OSM_CLIENT_SECRET'),
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
Bootstrap(app)

authorize_url = 'https://www.openstreetmap.org/oauth2/authorize'
token_url = 'https://www.openstreetmap.org/oauth2/token'
api_base_url = 'https://api.openstreetmap.org/api/0.6/'

presets = OSMPresets()
presets.load_presets()


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
    osm_auth = OAuth2Session(
        client_id=app.config.get('OSM_CLIENT_ID'),
        scope=['read_prefs', 'write_api'],
        redirect_uri=url_for('authorize', _external=True),
    )
    authorization_url, state = osm_auth.authorization_url(authorize_url)

    session['oauth_state'] = state
    return redirect(authorization_url)


@app.route('/authorize')
def authorize():
    osm_auth = OAuth2Session(
        client_id=app.config.get('OSM_CLIENT_ID'),
        redirect_uri=url_for('authorize', _external=True),
        state=session['oauth_state'],
    )
    token = osm_auth.fetch_token(
        token_url=token_url,
        client_secret=app.config.get('OSM_CLIENT_SECRET'),
        authorization_response=request.url,
    )
    session['oauth_params'] = token

    userreq = osm_auth.get('https://api.openstreetmap.org/api/0.6/user/details')
    root = ET.fromstring(userreq.text)
    user_name = root[0].attrib['display_name']
    session['user_name'] = user_name

    next_url = session.pop('next', None) or url_for('nearby')

    return redirect(next_url)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def get_pois_around(lat, lon, radius):
    radius = 'around:%d,%0.6f,%0.6f' % (radius, lat, lon)

    overpass_query = """[out:json][timeout:25];(
        node["name"]["amenity"]({bbox});
        way["name"]["amenity"]({bbox});
        node["name"]["craft"]({bbox});
        way["name"]["craft"]({bbox});
        node["name"]["leisure"]({bbox});
        way["name"]["leisure"]({bbox});
        node["name"]["shop"]({bbox});
        way["name"]["shop"]({bbox});
        node["name"]["tourism"]({bbox});
        way["name"]["tourism"]({bbox});
        );out center body;""".format(bbox=radius)
    resp = requests.post('https://overpass-api.de/api/interpreter', data=overpass_query, timeout=20)
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
    if 'user_name' not in session or 'oauth_params' not in session:
        return redirect(url_for('login'))

    lat = request.args.get('lat', type=float)
    lon = request.args.get('lon', type=float)
    radius = request.args.get('d', 150, type=int)
    limit = request.args.get('l', 15, type=int)

    if not lat or not lon:
        # Triggers geolocation on the browser
        pois = []
        request_geolocation = True
    else:
        try:
            pois = get_pois_around(lat, lon, radius)
        except (requests.HTTPError, requests.exceptions.ReadTimeout) as e:
            flash("Problem getting POIs: %s" % e)
            pois = []
        request_geolocation = False

    return render_template(
        'nearby.html',
        request_geolocation=request_geolocation,
        nearby_items=pois[:limit],
        radius=radius,
        next_radius=int(radius * 1.8),
        limit=limit,
        next_limit=int(limit * 1.8),
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
        if not v:
            continue

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

    osm = OAuth2Session(
        client_id=app.config.get('OSM_CLIENT_ID'),
        token=session['oauth_params'],
    )

    resp = osm.put(api_base_url + 'changeset/create', data=cs_text, headers={'Content-Type': 'text/xml'})
    app.logger.info("Response from changeset create: %s", resp.text)
    resp.raise_for_status()
    changeset_id = int(resp.text)

    return changeset_id


def apply_change(new_obj, action, changeset_id):
    root = ET.Element('osmChange')
    root.attrib['version'] = "0.6"
    root.attrib['generator'] = "poism"
    modify_elem = ET.SubElement(root, action)
    obj_elem = obj_to_xml(new_obj)
    obj_elem.attrib['changeset'] = str(changeset_id)
    modify_elem.append(obj_elem)
    osc_text = ET.tostring(root, encoding='unicode')
    app.logger.info("Applying change: %s", osc_text)

    osm = OAuth2Session(
        client_id=app.config.get('OSM_CLIENT_ID'),
        token=session['oauth_params'],
    )

    resp = osm.post(api_base_url + 'changeset/{}/upload'.format(changeset_id), data=osc_text, headers={'Content-Type': 'text/xml'})
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


@app.route('/presets.json')
def presets_json():
    def convert(kv):
        name, data = kv
        if not (name.startswith("amenity/") or \
            name.startswith("craft/") or \
            name.startswith("leisure/") or \
            name.startswith("shop/") or \
            name.startswith("tourism/")):

            return None

        if 'point' not in data.get('geometry', []):
            return None

        names = presets._names.get(name)
        terms = (names.get('terms') or '').split(',')
        terms.insert(0, names.get('name').lower())
        terms = ' '.join(set(filter(None, terms)))

        return {
            "icon": data.get("icon"),
            "id": name,
            "text": names.get("name"),
            "terms": terms,
        }

    filtered_presets = list(filter(None, map(convert, presets._presets.items())))

    resp = make_response(jsonify(results=filtered_presets, pagination=dict(more=False)))
    resp.cache_control.public = True
    resp.cache_control.max_age = 60
    return resp


@app.route('/pois_around.geojson')
def pois_around():
    lat = request.args.get('lat', type=float)
    lon = request.args.get('lon', type=float)

    if not (lat or lon):
        return jsonify({'error': "lat and lon are required"}), 400

    try:
        radius = request.args.get('d', 125, type=int)
    except Exception:
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
        tags = dict([(t.attrib['k'], t.attrib['v']) for t in thing.findall('./tag')])

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
        tags = dict([(t.attrib['k'], t.attrib['v']) for t in thing.findall('./tag')])

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
        'tags': tags,
    }

    return jsonify(feature)


def apply_form_to_tags(tags, fields, form):
    if 'name' in fields:
        tags['name'] = form.name.data

    if 'address' in fields:
        tags['addr:housenumber'] = form.addr_housenumber.data
        tags['addr:street'] = form.addr_street.data
        tags['addr:city'] = form.addr_city.data
        tags['addr:state'] = form.addr_state.data
        tags['addr:postcode'] = form.addr_postcode.data

    if 'phone' in fields:
        tags['phone'] = form.phone.data

    if 'website' in fields:
        tags['website'] = form.website.data

    if 'opening_hours' in fields:
        tags['opening_hours'] = form.opening_hours_complex.data

    # Remove tags that are empty
    keys_to_delete = list(k for k in tags.keys() if tags[k] is None)
    for k in keys_to_delete:
        del tags[k]

    return tags


def apply_tags_to_form(tags, fields, form):
    if 'name' in fields:
        form.name.data = tags.get('name')

    if 'address' in fields:
        form.addr_housenumber.data = tags.get('addr:housenumber')
        form.addr_street.data = tags.get('addr:street')
        form.addr_city.data = tags.get('addr:city')
        form.addr_state.data = tags.get('addr:state')
        form.addr_postcode.data = tags.get('addr:postcode')

    if 'phone' in fields:
        form.phone.data = tags.get('phone')

    if 'website' in fields:
        form.website.data = tags.get('website')

    if 'opening_hours' in fields:
        opening_hours = tags.get('opening_hours')
        form.opening_hours_complex.data = opening_hours

    return form


@app.route('/edit/<obj_type>/<int:obj_id>', methods=['GET', 'POST'])
def edit_object(obj_type, obj_id):
    if 'user_name' not in session or 'oauth_params' not in session:
        session['next'] = request.url
        return redirect(url_for('login'))

    if obj_type not in ('node', 'way'):
        return redirect(url_for('index'))

    resp = requests.get(api_base_url + '{}/{}'.format(obj_type, obj_id))

    if resp.status_code != 200:
        app.logger.info("OSM API server returned HTTP %s for %s/%s", resp.status_code, obj_type, obj_id)
        return redirect(url_for('index'))

    root = ET.fromstring(resp.text)
    obj = parse_xml_obj(root[0])
    obj_tags = obj['tags']

    form = PoiForm()

    preset = presets.match_by_tags(obj_tags)

    new_preset_name = request.args.get('new_preset')
    old_preset = None
    if new_preset_name:
        new_preset = presets.get_by_id(new_preset_name)
        if not new_preset:
            flash("Don't know that new category")
            return redirect(url_for('edit_object', obj_type=obj_type, obj_id=obj_id))

        old_preset = preset
        preset = new_preset

    fields = []
    if preset:
        fields = preset.get('fields')
        app.logger.info("Matches preset %s with fields %s", preset['name'], fields)
    else:
        fields = ["name"]
        preset = {
            'icon': 'fas-vector-square',
            'name': 'Unknown Preset',
            'fields': ["name"],
        }
        app.logger.info("No preset matches")

    if request.method == 'GET':
        apply_tags_to_form(obj_tags, fields, form)

    if form.validate_on_submit():
        new_obj = copy.deepcopy(obj)

        if old_preset and new_preset:
            # Need to remove the old preset's tags from the object
            for k, v in old_preset.get('tags', {}).items():
                existing_value = new_obj['tags'].get(k)
                if existing_value == v:
                    del new_obj['tags'][k]
            for k, v in old_preset.get('addTags', {}).items():
                existing_value = new_obj['tags'].get(k)
                if existing_value == v:
                    del new_obj['tags'][k]

        apply_form_to_tags(new_obj['tags'], fields, form)

        changeset_id = session.get('changeset_id')
        if not changeset_id:
            changeset_id = open_changeset()
            session['changeset_id'] = changeset_id
            app.logger.info("Created a new changeset with ID %s", changeset_id)

        try:
            apply_change(new_obj, 'modify', changeset_id)
            app.logger.info("Saved changes to https://osm.org/%s/%s", new_obj['type'], new_obj['id'])
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
        preset=preset,
        old_preset=old_preset,
    )


@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'user_name' not in session or 'oauth_params' not in session:
        return redirect(url_for('login'))

    lat = request.args.get("lat", type=float)
    lon = request.args.get("lon", type=float)
    if lat is None or lon is None:
        return redirect(url_for("nearby"))

    preset_val = request.args.get("preset")
    preset = presets.get_by_id(preset_val)

    if preset_val and not preset:
        flash("That preset is not recognized")
        return redirect(url_for("add", lat=lat, lon=lon))

    obj = {}

    form = PoiForm()
    if preset:
        fields = preset['fields']
        tags_from_preset = preset.get('tags') or {}
        tags_from_preset.update(preset.get('addTags') or {})

    if form.validate_on_submit():
        new_obj = {
            'type': 'node',
            'version': 1,
            'id': -1,
            'lat': lat,
            'lon': lon,
            'tags': tags_from_preset,
        }

        apply_form_to_tags(new_obj['tags'], fields, form)

        changeset_id = session.get('changeset_id')
        if not changeset_id:
            changeset_id = open_changeset()
            session['changeset_id'] = changeset_id
            app.logger.info("Created a new changeset with ID %s", changeset_id)

        try:
            created_obj = apply_change(new_obj, 'create', changeset_id)
            app.logger.info("Saved changes to https://osm.org/%s/%s", new_obj['type'], new_obj['id'])
        except ChangesetClosedException:
            app.logger.info("Changeset %s closed, opening a new one and trying again", changeset_id)
            session.pop('changeset_id', None)

            changeset_id = open_changeset()
            session['changeset_id'] = changeset_id
            app.logger.info("Created a new changeset with ID %s", changeset_id)

            created_obj = apply_change(new_obj, 'create', changeset_id)
            app.logger.info("Saved changes to https://osm.org/%s/%s", new_obj['type'], new_obj['id'])

        return redirect(url_for('edit_object', obj_type='node', obj_id=created_obj['id']))

    if not preset_val:
        return render_template(
            'add_object.html',
        )

    apply_tags_to_form(tags_from_preset, fields, form)

    return render_template(
        'edit_object.html',
        form=form,
        obj=obj,
        preset=preset,
        creating_new_place=True,
    )
