import json
with open('deployments/monitoring/grafana/provisioning/dashboards/rsbp.json') as f:
    d = json.load(f)
for p in d.get('panels', []):
    if p['type'] == 'stat':
        p.setdefault('options', {})['reduceOptions'] = {'calcs': ['sum'], 'fields': '', 'values': False}
        for t in p.get('targets', []):
            if not any(a.get('type') == 'date_histogram' for a in t.get('bucketAggs', [])):
                t.setdefault('bucketAggs', []).append({'field': '@timestamp', 'id': str(int(max([a.get('id', '0') for a in t.get('bucketAggs', [])]+['1']))+1), 'settings': {'interval': 'auto', 'min_doc_count': '0'}, 'type': 'date_histogram'})
with open('deployments/monitoring/grafana/provisioning/dashboards/rsbp.json', 'w') as f:
    json.dump(d, f, indent=2)
