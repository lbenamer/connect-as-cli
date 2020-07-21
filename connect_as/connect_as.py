import os
import json


import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress ssl warning in dev env
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class ConnectAsException(Exception):
    def __init__(self, message):
        super(ConnectAsException, self).__init__(message)


class ConnectAs(object):
    ENVS = {
        'dev': 'https://dev.',
        'preprod': 'https://preprod.',
        'prod': 'https://',
    }
    DOMAIN = 'admin.partoo.co'
    ENDPOINTS = {
        'login': '/api/v2/connection/login',
        'search_user': '/api/v2/user/search',
        'generate_token': '/api/v2/connection/generate_token',
        'connection': '/app/connection',
    }
    CACHE_DIRECTORY = '/tmp/connect_as/'
    COOKIES = 'cookies.json'
    USERS = 'users.json'

    def __init__(self, env):
        self.env = env
        self._cookies = None
        self._saved_users = None

    @property
    def base_url(self):
        return self.ENVS.get(self.env) + self.DOMAIN

    @property
    def _verify_ssl(self):
        return self.env != 'dev'

    @property
    def cookies(self):
        if not self._cookies:
            self._cookies = self._load_json(self.COOKIES)

        return self._cookies

    def _check_cache_directory(self):
        """
        Create cache directory if not exist.
        """
        if not os.path.isdir(self.CACHE_DIRECTORY):
            os.mkdir(self.CACHE_DIRECTORY)

    def _check_file_exist(self, filename):
        """
        Create filename in cache directory if not exist.
        :type filename: str
        """
        file_path = self.CACHE_DIRECTORY + filename
        if not os.path.exists(file_path):
            with open(file_path, 'w+'):
                pass

    def _load_json(self, filename, default={}):
        """
        Load json file from cache directory.
        Create directory and file if not exists.

        :param filename: file name in CACHE_DIRECTORY
        :type filename: str
        :param default: default value if file is empty, defaults to {}
        :type default: dict, optional
        :return: serialize JSON data or default
        :rtype: dict or list
        """
        self._check_cache_directory()
        self._check_file_exist(filename)
        with open(self.CACHE_DIRECTORY + filename, 'r') as fd:
            try:
                data = json.load(fd)
            except ValueError:
                data = default
            finally:
                return data

    def _to_json(self, data, filename):
        """
        Serialize data to JSON and save in filename.

        :param data: data to serialize
        :type data: dict or list
        :param filename: file name in CACHE_DIRECTORY
        :type filename: str
        """
        self._check_cache_directory()
        with open(self.CACHE_DIRECTORY + filename, 'w+') as fd:
            json.dump(data, fd)

    def _save_cookies(self, cookies):
        self._cookies = cookies
        self._to_json(cookies, self.COOKIES)

    @property
    def saved_users(self):
        if not self._saved_users:
            self._saved_users = self._load_json(self.USERS)

        return self._saved_users

    def save_user(self):
        save_selected_user = raw_input(
            'Do you want to save this user [y/n]: '
        )
        if save_selected_user == 'y':
            description = raw_input('Add a description: ')
            user = self._users.get(self.user_choice)
            formatted_user = dict(
                query=user['email'],
                role=user['role'],
                org_id=user['org_id'],
                description=description
            )
            id = len(self.saved_users)
            self._saved_users[id] = formatted_user
            self._to_json(self._saved_users, self.USERS)
            print('You can now use: python cli.py -i {id}'.format(id=id))

    def _get(self, endpoint, params={}, payload={}):
        url = self.ENVS.get(self.env) + self.DOMAIN + self.ENDPOINTS.get(endpoint)
        r = requests.get(
            url,
            params=params,
            json=payload,
            cookies=self.cookies,
            verify=self._verify_ssl
        )

        if r.status_code == 200:
            return r.json()

        # TODO: raise ConnectAsEx
        else:
            print ('ERROR : {url} : {status_code}'.format(
                url=url,
                status_code=r.status_code
            ))
            return False

    def _login(self, email, password):
        url = self.ENVS.get(self.env) + self.DOMAIN + self.ENDPOINTS.get('login')
        payload = {
            'email': email,
            'password': password,
        }
        r = requests.post(url, json=payload, verify=False)

        if r.status_code != 200:
            return False
        return r

    def _request_credentials(self):
        email = raw_input('Email: ')
        password = raw_input('Password: ')

        return email, password

    def _authentication(self):
        email, password = self._request_credentials()
        r = self._login(email, password)
        if r:
            self._save_cookies(r.cookies.get_dict())
            print(u'Login Success !')
            return True
        else:
            print(u'Invalid Credentials', r.json().get('errors').get('json'))
            return self._authentication()

    @property
    def _cookie_session_is_valid(self):
        return self._search_user_query({'user_query': 'xxxxxxxxxxx'})

    def connect_app(self):
        if not self.cookies or not self._cookie_session_is_valid:
            self._authentication()
            return self.connect_app()

        return True

    def _format_users(self, users):
        self._users = {}
        for index, user in enumerate(users):
            self._users[index] = {
                key: user[key]
                for key in user
                if key in ['first_name', 'last_name', 'org_id', 'email', 'role', 'id']
            }

    def _filter_users(self, users):
        return [
            user
            for user in users
            if user['role'] not in ['ADMIN']
        ]

    def _search_user_query(self, filters):
        search_params = dict(
            display_business_ids=False,
            page=0,
        )

        query = filters.get('query')
        org_id = filters.get('org_id')
        role = filters.get('role')

        if query:
            search_params['query'] = query
        if org_id:
            search_params['org_id'] = org_id
        if role:
            search_params['role'] = role

        r = self._get(
            endpoint='search_user',
            params=search_params
        )

        return r

    def _interactive_filters(self):
        filters = {}
        print(u'Search User Filters')
        filters['org_id'] = raw_input('Org Id : ')
        filters['role'] = raw_input('Role : ')
        filters['query'] = raw_input('Search user: ')
        return filters

    def search_user(self, id=None, **filters):
        if id or id == 0:
            filters = self.saved_users.get(str(id))
        if not filters:
            filters = self._interactive_filters()

        r = self._search_user_query(filters)
        if not r:
            print(u'No user found for ')
        return self._format_users(self._filter_users(r.get('users')))

    def display_users(self):
        print(u'Choose one user :')
        print(u'INDEX  --  USER_NAME  --  ORG  --  EMAIL  --  ROLE')
        for index, user in self._users.items():
            print(u'{index} - {user_name} - ORG: {org} - {email} - {role}'.format(
                index=index,
                user_name=user.get('first_name') + ' ' + user.get('last_name'),
                org=user.get('org_id'),
                email=user.get('email'),
                role=user.get('role')
            ))

    def display_saved_users(self):
        print('ID  --  EMAIL  --  ORG_ID  --  ROLE  -- DESCRIPTION')
        for id, user in self.saved_users.items():
            print(u'{id} - {email} - {org_id} - {role} - {description}'.format(
                id=id,
                email=user.get('query'),
                org_id=user.get('org_id'),
                role=user.get('role'),
                description=user.get('description')
            ))

    def choose_user(self, choice=None):
        try:
            self.user_choice = int(raw_input('Index of selected user (type anything to search again!): '))
        except ValueError:
            self.user_choice = None
            raise ConnectAsException('Invalid user choice')

    def get_token(self, save=False):
        user = self._users.get(self.user_choice)
        url = self.base_url + self.ENDPOINTS.get('generate_token')
        payload = dict(
            user_id=user.get('id'),
            ttl=60,
        )

        r = requests.post(url, json=payload, cookies=self._cookies, verify=self._verify_ssl)
        if r.status_code == 200:
            self.current_token = r.json().get('token')
        elif r.status_code == 403:
            raise ConnectAsException(
                'ConnectAs ADMIN ROLE not possible due to security policy'
            )
        else:
            raise ConnectAsException('Failed to get_token')

    def open_browser(self):
        url = '{env}{domain}{endpoint}?connection_token={token}'.format(
            env=self.ENVS.get(self.env),
            domain='app.partoo.co',
            base_url=self.base_url,
            endpoint=self.ENDPOINTS.get('connection'),
            token=self.current_token,
        )

        print(u'Open url: {url}'.format(url=url))
        exec_str = 'open -na /Applications/Google\ Chrome.app  --args --new-window --incognito "{url}"'.format(url=url)
        try:
            os.system(exec_str)
        except Exception as e:
            print('Failed to open browser')
            pass

    def select_user(self, **kwargs):
        try:
            self.search_user(**kwargs)
            self.display_users()
            self.choose_user()
            self.save_user()
            self.get_token()
        except ConnectAsException:
            return self.select_user()

    def main(self):
        self.connect_app()
        self.select_user()
        self.open_browser()
