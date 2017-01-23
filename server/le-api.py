#!/usr/bin/env python3

import requests
import re
import rapidjson as json
from pprint import pprint
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
    r = requests.get('{}servers/{}/zones/{}'.format(conf.pdns_api_url, conf.pdns_server_id, zone), headers={'X-API-Key': conf.pdns_api_key})
    if r.status_code == 422:
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


from enum import Enum

class RecOps(Enum):
    add_or_replace = 1
    delete = 2

def add_or_replace_record(domain, content, type="TXT", ttl=3600, replace=True):
    return fiddle_with_records(domain, content, what=RecOps.add_or_replace, type=type, ttl=ttl, replace=replace)


def delete_record(domain, content, type="TXT"):
    return fiddle_with_records(domain, content, what=RecOps.delete, type=type)


def fiddle_with_records(domain, content, what: RecOps, **how):
    assert isinstance(what, RecOps)

    zone = find_zone_for_domain(domain)
    if not zone:
        return False
    r = requests.get('{}servers/{}/zones/{}'.format(conf.pdns_api_url, conf.pdns_server_id, zone), headers={'X-API-Key': conf.pdns_api_key})
    zone_data = json.loads(r.text)

    records = []
    for rr in zone_data.get('records', []):
        if rr.get('name') == domain and rr.get('type') == how.get('type'):
            if rr.get('content') == content:
                if what == RecOps.delete or how.get('replace', False):
                    continue

            # docs inconsistency
            # we need to leave name in, but the docs does not show that
            # https://doc.powerdns.com/md/httpapi/api_spec/#url-apiv1serversserver95idzoneszone95id
            # https://doc.powerdns.com/md/httpapi/README/#examples-authoritative-server
            # del rr['name']
            records.append(rr)

    if what == RecOps.add_or_replace:
        records += [{
                    "content": content,
                    "disabled": False,
                    "ttl": how.get('ttl'),  # API docs bug?
                    "type": how.get('type'), # API docs bug?
                    "name": domain # API docs bug?
                }]

    req = {
        "rrsets": [
            {
                "name": domain,
                "type": "TXT",
                "ttl": 86400,
                "changetype": "REPLACE",
                "records": records
            }
        ]
    }


    print("Response from PowerDNS server")
    print(json.dumps(req, indent=4))

    r = requests.patch('{}servers/{}/zones/{}'.format(conf.pdns_api_url, conf.pdns_server_id, zone), headers={'X-API-Key': conf.pdns_api_key}, json=req)
    if r.status_code < 400:
        return True


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

    app.logger.debug("request __auth: {}, domain: {}".format(request.__auth, domain))

    if not request.__auth.domain_matches(domain):
        print("Unknown domain: {} for key (prefix): {}...".format(domain, request.headers.get('API-Key')[0:10]))
        return Unauthorized()

    if not is_domain_valid(domain):
        return "not valid domain"

    zone = find_zone_for_domain(domain)
    if not zone:
        return NotFound()

    return "ok"

@app.route("/api/<domain>", methods=["POST"])
def api_post(domain):
    if not request.__auth.domain_matches(domain):
        return Unauthorized()

    if not is_domain_valid(domain):
        return "not valid domain"

    zone = find_zone_for_domain(domain)
    if not zone:
        return NotFound()

    # don't worry about too large data, let's hope MAX_CONTENT_LENGTH is not naive and doesn't believe just any random Content-Length header
    if len(request.get_data()) < 2:
        return "huh"

    content = json.dumps(request.get_data())  # yes, get_data uses (in the request object) an internal cache by default
    if add_or_replace_record(domain, content):
        return "ok"
    else:
        return "err :C"


@app.route("/api/<domain>", methods=["DELETE"])
def api_delete(domain):
    if not request.__auth.domain_matches(domain):
        return Unauthorized()

    if not is_domain_valid(domain):
        return "not valid domain"

    zone = find_zone_for_domain(domain)
    if not zone:
        return NotFound()


    content = json.dumps(request.get_data())  # yes, get_data uses (in the request object) an internal cache by default
    if delete_record(domain, content, type="TXT"):
        return "deleted"
    else:
        return "omg error :C"

    return "l8r"

def __bootstrap():
    global conf
    conf = load_config()


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
