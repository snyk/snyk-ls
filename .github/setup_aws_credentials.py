#!/usr/bin/env python3

#  © 2022 Snyk Limited All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
from argparse import ArgumentParser

try:
    import requests
except ImportError:
    # Any version of requests will do
    from pip._vendor import requests

print('Using `requests` from:')
print(requests.__file__)

parser = ArgumentParser()
parser.add_argument('--role-arn')
parser.add_argument('--web-identity-token-file', default="webidentity.json")
parser.add_argument('--region', default='eu-west-2')


def main():
    args = parser.parse_args()

    github_env_file = os.environ['GITHUB_ENV']

    role_arn = args.role_arn
    append_file(f'AWS_ROLE_ARN={role_arn}', github_env_file)

    web_identity_token_file = args.web_identity_token_file
    append_file(f'AWS_WEB_IDENTITY_TOKEN_FILE={web_identity_token_file}', github_env_file)

    region = args.region
    append_file(f'AWS_DEFAULT_REGION={region}', github_env_file)

    token_url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']
    token_request_token = os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']
    token_response = requests.get(token_url, headers={
        'Authorization': f'bearer {token_request_token}',
    })

    token = token_response.json()['value']
    with open(web_identity_token_file, 'x') as f:
        f.write(token)
        f.close()


# https://docs.github.com/en/actions/learn-github-actions/environment-variables#passing-values-between-steps-and-jobs-in-a-workflow
def append_file(line, file):
    if not line.endswith('\n'):
        line += '\n'

    with open(file, 'a') as f:
        f.write(line)


if __name__ == '__main__':
    main()
