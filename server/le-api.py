#!/usr/bin/env python3

import requests
import re
import rapidjson as json
from pprint import pprint, pformat
from werkzeug.exceptions import NotFound, Unauthorized
from flask import Flask, request
app = Flask(__name__)

app.config['MAX_CONTENT_LENGTH'] = 64 * 1024

import uwsgi

class URL(str):
    def __new__(cls, s):
        if not s.startswith('http'):
            s += 'http://'
        if not s.endswith('/'):
            s += '/'
        return str.__new__(cls, s)



class Conf:
    external_zones = {}

    import logging
    def _Auth_loader(self, data_dict):
        _m = 'here'
        _m_set = False
        if 'mode' in data_dict:
            _m = data_dict['mode']
            del data_dict['mode']
            _m_set = True

        for subclass in Auth.__subclasses__():
            if subclass.__name__.lower().startswith(_m):
                return subclass(data_dict, conf=self)
        if _m_set:
            print("Unknown auth mode: {}".format(_m))
        else:
            print("Unknown auth config structure (no mode set)")

        exit(1)

    def __repr__(self):
        return str('Conf object: {}'.format(self.__dict__))

    def __init__(self, **kwargs):
        conf_schema = {'pdns_api_url': URL,
                       'pdns_server_id': str,
                       'pdns_api_key': str,
                       'allowed_prefixes': list,
                       'external': list,
                       'auth': self._Auth_loader}

        init_queues = {'primitive': [], 'complex': []}

        for k,v in conf_schema.items():
            if k in kwargs:
                def _get_deferred(k, v):
                    def _deferred():
                        self.logging.debug('>>>> setting Conf attr: {}: {} (val: {})'.format(k, v, kwargs[k]))
                        setattr(self, k, v(kwargs[k]))
                        del conf_schema[k]
                        del kwargs[k]

                    return _deferred

                self.logging.debug('>>>>> type of {}: {} (isinstance of object?: {})'.format(k, v, isinstance(v, object)))
                if v in (str, list, URL, int, bool, float):
                    self.logging.debug('>>>> appending to primitive queue: {} {} (val: {})'.format(k, v, kwargs[k]))
                    init_queues['primitive'].append(_get_deferred(k, v))
                else:
                    self.logging.debug('>>>> appending to complex queue: {} {} (val: {})'.format(k, v, kwargs[k]))
                    init_queues['complex'].append(_get_deferred(k, v))

        self.logging.debug('>>>> before primitive queue')

        for _ in init_queues['primitive']:
            _()

        self.logging.debug('>>>> before complex queue')

        for _ in init_queues['complex']:
            _()

        for _ in conf_schema.keys():
            setattr(self, _, None)
            self.logging.error('Setting default None for: {}'.format(_))

        for k, v in kwargs.items():
            self.logging.error('Unrecognized configuration data: "{}": {}'.format(k, repr(v)))
        if len(kwargs):
            exit(1)

from abc import ABC, abstractmethod

class Auth(ABC):
    @abstractmethod
    def get(self, key):
        pass


class HereAuth(Auth):
    class AuthKeyRecord:
        def __repr__(self):
            return "<AKRecord: {}>".format(self.__dict__)

        def __init__(self, domains):
            self._admin = False

            if domains == '*':
                self._admin = True
            else:
                assert isinstance(domains, list)
                assert len(domains) > 0

                self._regexed_domains = tuple(_.replace('*', '[a-z0-9_-]+').replace('.', '\.') for _ in filter(lambda t: '*' in t, domains))
                self._domains = tuple(_ for _ in domains if _ not in self._regexed_domains)

        @property
        def domains(self):
            if self._admin:
                return '*'
            return tuple(self._domains + self._regexed_domains)

        def domain_matches(self, domain):
            if self._admin:
                return True

            if domain in self._domains:
                return True

            if any(map(lambda t: re.match(t, domain), self._regexed_domains)):
                return True

            return False

    def get(self, key):
        return self.keys.get(key, False)

    def __repr__(self):
        return "<HereAuth {}>".format(self.keys)

    def __init__(self, data_dict, conf):
        self.allowed_prefixes = getattr(conf, 'allowed_prefixes', [])
        assert type(self.allowed_prefixes) is list

        if 'keys' not in data_dict:
            print("Missing member `keys` in auth object")
            exit(1)
        keys = data_dict['keys']
        self.keys = {}

        for i in keys:
            if 'key' not in i or 'domains' not in i:
                print("Wrong record in auth list: {}\n missing must contain `key` and `domains` members")
                exit(1)

            if i['key'] in self.keys:
                print("FATAL: You should merge domains for key: {}".format(i['key']))
                exit(1)

            if type(i['domains']) is list:
                domains = list(i['domains'])  # make a copy fo' sure, to avoid getting a reference that'd be a bit awkwaaaaard when iterating on and appending to at the same time
                for _ in i['domains']:
                    for pre in self.allowed_prefixes:
                        domains.append(pre + _)
            else:
                domains = i['domains']

            self.keys[i['key']] = self.AuthKeyRecord(domains)


def load_config():
    cf = uwsgi.opt.get('config-file')
    if not cf:
        print("Cannot find config file: {}".format(cf))
        exit(1)

    conf_data = json.loads(open(cf).read())
    app.logger.debug('loading config from {}'.format(cf.decode('ascii', 'ignore')))
    return Conf(**conf_data)



def is_domain_valid(domain):
    if re.fullmatch('[a-z0-9-._]+\.[a-z]+', domain):
        return True
    return False


def is_zone_exists(zone):
    r = requests.get('{}api/v1/servers/{}/zones/{}'.format(conf.pdns_api_url, conf.pdns_server_id, zone), headers={'X-API-Key': conf.pdns_api_key})
    if r.status_code == 422 or r.status_code == 404:
        return False
    return True


def find_zone_for_domain(domain):
    d = domain.split('.')
    zone = None
    while d:
        zone = '.'.join(d)
        if is_zone_exists(zone):
            app.logger.debug('Found zone for domain ({}): {}'.format(domain, zone))
            break
        d.pop(0)

    if not d:
        return False
    return zone

def trim_last_dot(domain):
    return domain.rstrip('.')

def ensure_last_dot(domain):
    return '{}.'.format(trim_last_dot(domain))


from enum import Enum

class RecOps(Enum):
    add_or_replace = 1
    delete = 2

def add_or_replace_record(zone_or_ext, domain, content, type="TXT", ttl=3600, replace=True):
    app.logger.debug('add_or_replace_record: zone: {} domain: {}  content: {} replace: {}'.format(zone_or_ext, domain, content, replace))
    return fiddle_with_records(zone_or_ext, domain, content, what=RecOps.add_or_replace, type=type, ttl=ttl, replace=replace)


def delete_record(zone_or_ext, domain, content, type="TXT"):
    return fiddle_with_records(zone_or_ext, domain, content, what=RecOps.delete, type=type)


def fiddle_with_records(zone_or_ext, domain, content, what: RecOps, **how):
    assert isinstance(what, RecOps)

    if isinstance(zone_or_ext, dict):
        return zone_or_ext['instance'].fiddle_with_records(zone_or_ext['data'], domain, content, what, **how)

    return pdns_fiddle(zone_or_ext, domain, content, what, **how)

def pdns_fiddle(zone, domain, content, what: RecOps, **how):
#    if not domain.endswith('.'):
#        domain = '{}.'.format(domain)

    r = requests.get(f'{conf.pdns_api_url}api/v1/servers/{conf.pdns_server_id}/zones/{zone}', headers={'X-API-Key': conf.pdns_api_key})
    if r.status_code != 200:
        print("ERROR")
        print(r.text)
        return

    zone_data = json.loads(r.text)

    zone_name = zone_data.get('name')
    rrsets = zone_data.get('rrsets', [])

    app.logger.debug('fiddling with: zone name: {} ({} RRsets) domain: {}, trying to: {} {} - {}'.format(zone_name, len(rrsets), domain, what, content, how))

    records = []

    fqdn = ensure_last_dot(domain)

    if what == RecOps.delete and content == "":
        app.logger.info('deleting every matching RRset for name: {}'.format(fqdn))
    else:
        for rr in rrsets:
            if rr.get('name') == fqdn and rr.get('type') == how.get('type'):
                orig_records = rr.get('records', [])
                app.logger.debug('rr.get name == domain found ({}), type = {}, existing records: {}'.format(domain, how.get('type'), len(orig_records)))

                for rec in orig_records:
                    if rec.get('content') == content and rr.get('disabled', False) == False:
                        app.logger.debug('record {} already present and enabled'.format(content))

                        if what == RecOps.delete or how.get('replace', False):
                            continue

                    # docs inconsistency
                    # we need to leave name in, but the docs does not show that
                    # https://doc.powerdns.com/md/httpapi/api_spec/#url-apiv1serversserver95idzoneszone95id
                    # https://doc.powerdns.com/md/httpapi/README/#examples-authoritative-server
                    # del rr['name']
                    app.logger.debug('appppppppppppending! {}'.format(rec))

                    records.append(rec)

        if what == RecOps.add_or_replace:
            records += [{
                        "content": content,
                        "disabled": False,
                        "ttl": how.get('ttl'),  # API docs bug?
                        "type": how.get('type'), # API docs bug?
                        "name": fqdn # API docs bug?
                    }]

    req = {
        "rrsets": [
            {
                "name": fqdn,
                "type": "TXT",
                "ttl": 86400,
                "changetype": "REPLACE",
                "records": records
            }
        ]
    }


    print("Request")
    print(json.dumps(req, indent=4))

    r = requests.patch('{}api/v1/servers/{}/zones/{}'.format(conf.pdns_api_url, conf.pdns_server_id, zone), headers={'X-API-Key': conf.pdns_api_key}, json=req)
    if r.status_code < 400:
        return True
    else:
        app.logger.error('got an error from pdns: {}'.format(r.text))


@app.before_request
def auth():
    if hasattr(request, 'url_rule') and request.url_rule: print(request.url_rule.__dict__)

    k = request.headers.get('API-Key')
    if not k:
        print("No API-Key header present.")
        return Unauthorized()

    r = conf.auth.keys.get(k)
    if not r:
        print("Unknown API-Key received")
        return Unauthorized()

    setattr(request, '__auth', r)


@app.route("/", methods=["GET"])
def hello():
    return "use /api/<zone>"


@app.route("/api/<domain>", methods=["GET"])
def api_get(domain):
    domain = trim_last_dot(domain)

    app.logger.debug("request __auth: {}, domain: {}".format(request.__auth, domain))

    if not request.__auth.domain_matches(domain):
        app.logger.info("Unknown domain: {} for key (prefix): {}...".format(domain, request.headers.get('API-Key')[0:10]))
        return Unauthorized()

    if not is_domain_valid(domain):
        return "not valid domain"

    if is_external_zone(domain):
        return "ok"

    zone = find_zone_for_domain(domain)
    if not zone:
        return NotFound()

    return "ok"


def parse_request_body(req):
    # don't worry about too large data, let's hope MAX_CONTENT_LENGTH is not naive and doesn't believe just any random Content-Length header
    if len(req.get_data()) < 2:
        return "huh"

    return json.dumps(req.get_data())  # yes, get_data uses (in the request object) an internal cache by default


@app.route("/api/<domain>", methods=["POST"])
def api_post(domain):
    domain = trim_last_dot(domain)

    if not request.__auth.domain_matches(domain):
        return Unauthorized()

    if not is_domain_valid(domain):
        return "not valid domain"

    ext = is_external_zone(domain)
    if ext:
        if ext['instance'].fiddle_with_records(ext['data'], domain, parse_request_body(request), what=RecOps.add_or_replace, type="TXT", ttl=3600, replace=False):
            return "ok"
        else:
            return "err :C"

    zone = find_zone_for_domain(domain)

    if not zone:
        return NotFound()


    if add_or_replace_record(zone, domain, parse_request_body(request), replace=False):
        return "ok"
    else:
        return "err :C"


@app.route("/api/<domain>", methods=["DELETE"])
def api_delete(domain):
    domain = trim_last_dot(domain)

    if not request.__auth.domain_matches(domain):
        return Unauthorized()

    if not is_domain_valid(domain):
        return "not valid domain"

    ext = is_external_zone(domain)
    if ext:
        return ext['instance'].delete_record(ext['data'], domain)


    zone = find_zone_for_domain(domain)
    if not zone:
        return NotFound()

    data = request.get_data()  # yes, get_data uses (in the request object) an internal cache by default

    if data == b'':
        content = ""
    else:
        content = json.dumps(data)

    app.logger.debug('DELETE: content = {}'.format(content))

    if delete_record(zone, domain, content, type="TXT"):
        return "deleted"
    else:
        return "omg error :C"

    return "l8r"


class ExtCloudflare:
    domains = {}

    def __init__(self, domains):
        for domain in domains:
            name = domain['name']
            zone_id = domain['zone_id']
            token = domain['token']

            r = requests.get(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', headers={'Authorization': f'Bearer {token}'})
            if r.status_code != 200:
                print(f"Error validating Cloudflare token for domain {name} (zone id: {zone_id})")
                sys.exit(1)
            else:
                print(f"Cloudflare: validated token for {name}")

                conf.external_zones[name] = {
                    'instance': self,
                    'data': {
                        'zone_id': zone_id, 'token': token
                    }
                }

        self.domains = domains

    def does_record_exists(self, domain):
        pass
        

    def delete_domain(self, data, domain):
        zone_id = data['zone_id']
        token = data['token']
 
        r = requests.get(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={domain}', headers={'Authorization': f'Bearer {token}'})
        # TODO: handle multiple records
        record_id = json.loads(r.text)['result'][0]
            
        r = requests.delete(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}', headers={'Authorization': f'Bearer {token}'})

    def fiddle_with_records(self, data, domain, content, what: RecOps, **how):
        zone_id = data['zone_id']
        token = data['token']
        print(f"fiddling! domain: {domain}, zone: {zone_id}, content: {content}, what: {what}, ... how: {how}")

        # fiddling! domain: _acme-challenge.dns-doh.end.systems., zone: ba21a77aca47ab46af42aaf69432323e, content: "omg", what: RecOps.add_or_replace, ... how: {'type': 'TXT', 'ttl': 3600, 'replace': False}

        if what is RecOps.add_or_replace:
            r = requests.get(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={domain}', headers={'Authorization': f'Bearer {token}'})
            if r.status_code == 200:
                record_id = json.loads(r.text)['result_info']['total_count']
                r = requests.patch(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}', headers={'Authorization': f'Bearer {token}'})

        # https://api.cloudflare.com/#dns-records-for-a-zone-update-dns-record
        return
        # uh oh deadcode!

        page = 1
        zone_date = []
        while True:
            r = requests.get(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?per_page=50&page={page}', headers={'Authorization': f'Bearer {token}'})
            rj = json.loads(r.text)
            zone_data += json.loads(r.text)['result']
            if rj['result_info']['total_pages'] == rj['result_info']['page']:
                break




def is_external_zone(zone_name):
    print(f"is external zone? {zone_name}")
    for ext_zone in conf.external_zones.keys():
        if zone_name.endswith(ext_zone):
            return conf.external_zones[ext_zone]
    return False

def validate_external_config(config):
    if not config.external:
        return
    ext = config.external
    for e in ext:
        if e['type'] == "cloudflare":
            ExtCloudflare(e['domains'])



def __bootstrap():
    global conf
    conf = load_config()
    validate_external_config(conf)


if __name__ == "__main__":
    import sys

    debug = True
    if '--no-debug' in sys.argv:
        debug = False

    print("Starting Flask app")
    __bootstrap()
    app.run(debug=debug)
    print("Bye")

else:
    import logging

    # Log only in production mode.
    if not app.debug:
        stream_handler = logging.StreamHandler()
        app.logger.addHandler(stream_handler)

        loglevel = uwsgi.opt.get('log-level', b'').decode('ascii', 'ignore').lower()

        if loglevel == 'debug':
            app.logger.setLevel(logging.DEBUG)
            logging.getLogger().setLevel(logging.DEBUG)
        else:
            app.logger.setLevel(logging.INFO)

    app.logger.info("started with log-level: {}".format(loglevel))
    __bootstrap()
    app.logger.debug('bootstrap done, conf = {}'.format(repr(conf)))
