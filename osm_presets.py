import requests


class OSMPresets(object):
    def __init__(self, app=None):
        self.presets = None

    def load_presets(self):
        resp = requests.get('https://raw.githubusercontent.com/openstreetmap/iD/master/data/presets/presets.json')
        resp.raise_for_status()
        self.presets = resp.json().get('presets')
        self._populate_parents()

    def _populate_parents(self):
        """ Popuate implied presets and referential relationships. """
        for name, data in self.presets.items():
            fields = data.get('fields', [])

            # Presets with no 'fields' attribute should pull their fields from the parent preset.
            if not fields:
                parent_preset_name = name.rsplit('/', 1)[0]
                parent_preset = self.presets.get(parent_preset_name)
                if parent_preset:
                    fields = parent_preset.get('fields', [])

            fields.extend(data.get('moreFields', []))

            # Fields with {} surrounding the name should be replaced with the fields from the named preset
            for i, p in enumerate(fields):
                if p[0] == '{' and p[-1] == '}':
                    referred_preset = self.presets.get(p[1:-1])
                    if referred_preset:
                        del fields[i]
                        fields[i:i] = referred_preset['fields']

            data['fields'] = fields

    def match_by_tags(self, tags):
        candidates = []

        for preset_name, preset_data in self.presets.items():
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

            if candidate_points > 0:
                candidates.append((candidate_points, preset_data))

        if candidates:
            return sorted(candidates, key=lambda i: i[0], reverse=True)[0][1]
        else:
            return None


if __name__ == "__main__":
    p = OSMPresets()
    p.load_presets()

    test_tags = {
        "addr:city": "Saint Paul",
        "addr:housenumber": "755",
        "addr:postcode": "55104",
        "addr:state": "MN",
        "addr:street": "North Prior Avenue",
        "craft": "brewery",
        "email": "info@blackstackbrewing.com",
        "name": "BlackStack Brewing",
        "opening_hours": "Mo-Th 08:00-23:00; Fr 08:00-00:00; Sa 09:00-00:00; Su 09:00-22:00",
        "phone": "+1-612-369-2932",
        "website": "https://www.blackstackbrewing.com/",
    }
    print(p.match_by_tags(test_tags))

    test_tags = {
        "amenity": "theatre",
        "building": "yes",
        "name": "Celtic Junction",
        "type": "multipolygon",
    }
    print(p.match_by_tags(test_tags))
