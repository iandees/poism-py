import copy
import requests


class OSMPresets(object):
    def __init__(self, app=None):
        self._presets = None
        self._names = None

    def load_presets(self):
        resp = requests.get('https://raw.githubusercontent.com/openstreetmap/id-tagging-schema/main/dist/presets.min.json', timeout=15.0)
        resp.raise_for_status()
        self._presets = resp.json()

        resp = requests.get('https://raw.githubusercontent.com/osmlab/name-suggestion-index/main/dist/presets/nsi-id-presets.min.json', timeout=15.0)
        resp.raise_for_status()
        nsi_presets = resp.json()['presets']
        self._presets.update(nsi_presets)

        resp = requests.get('https://raw.githubusercontent.com/openstreetmap/id-tagging-schema/main/dist/translations/en.min.json')
        resp.raise_for_status()
        self._names = resp.json()['en']['presets']['presets']

    def _resolve_references(self, path, preset):
        """ Populate implied presets and referential relationships. """
        fields = preset.get('fields', [])

        # Presets with no 'fields' attribute should pull their fields from the parent preset.
        if not fields:
            path_copy = copy.copy(path)
            while path_copy:
                path_parts = path_copy.rsplit("/", 1)
                if len(path_parts) < 2:
                    break

                parent_preset_name = path_parts[0]
                parent_preset = self._presets.get(parent_preset_name)
                if parent_preset:
                    parent_fields = parent_preset.get('fields', [])
                    fields.extend(parent_fields)
                path_copy = parent_preset_name

        fields.extend(preset.get('moreFields', []))

        # Fields with {} surrounding the name should be replaced with the fields from the named preset
        for i, p in enumerate(fields):
            if p[0] == '{' and p[-1] == '}':
                referred_preset = self._presets.get(p[1:-1])
                if referred_preset:
                    del fields[i]
                    fields[i:i] = referred_preset['fields']

        preset['fields'] = fields
        return preset

    def get_by_id(self, id):
        match = self._presets.get(id)

        if match:
            match = self._resolve_references(id, match)
            if not match.get('name'):
                match['name'] = self._names.get(id).get('name')

        return copy.deepcopy(match)

    def match_by_tags(self, tags):
        candidates = []

        for preset_name, preset_data in self._presets.items():
            candidate_tags = preset_data.get('tags')
            candidate_points = 0

            for candidate_k, candidate_v in candidate_tags.items():
                tag_v = tags.get(candidate_k)
                if tag_v:
                    candidate_points += 1
                    if tag_v == candidate_v:
                        candidate_points += 1
                    else:
                        candidate_points -= 1
                else:
                    candidate_points -= 1

            if candidate_points > 0:
                candidates.append((candidate_points, preset_name, preset_data))

        if candidates:
            points, name, data = sorted(candidates, key=lambda i: i[0], reverse=True)[0]
            data = self._resolve_references(name, data)
            if not data.get('name'):
                data['name'] = self._names.get(name).get('name')
            return copy.deepcopy(data)
        else:
            return None


if __name__ == "__main__":
    p = OSMPresets()
    p.load_presets()

    resp = requests.get("https://poism.dev.openstreetmap.us/node/6918736677.geojson")
    test_tags = resp.json().get("properties").get("tags")
    print(p.match_by_tags(test_tags))
