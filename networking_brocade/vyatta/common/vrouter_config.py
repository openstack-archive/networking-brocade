# Copyright 2015 Brocade Communications System, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


TOKEN_GROUP = 'group'
TOKEN_PARAM = 'param'
TOKEN_END = 'end'


def parse_line(line):
    value = None
    if line.endswith('{'):
        key = line[:-1].strip()
        token = TOKEN_GROUP
    elif line.endswith('}'):
        key = line[:-1].strip()
        token = TOKEN_END
    else:
        token = TOKEN_PARAM
        chunks = line.split(' ', 1)
        key = chunks.pop(0)
        if chunks:
            value = chunks[0]

    return token, key, value


def config_iter(config):
    for line in config.splitlines():
        line = line.strip()
        if line:
            yield line


def parse_group(lines):
    result = {}

    for line in lines:
        token, key, value = parse_line(line)

        if token == TOKEN_PARAM:
            result[key] = value
        elif token == TOKEN_GROUP:
            result[key] = parse_group(lines)
        else:
            break

    return result


def parse_config(config):
    lines = config_iter(config)
    return parse_group(lines)
