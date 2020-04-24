import datetime
import os
import re
import subprocess
import time

from compiler import config, mappings, parser
import json


m = {}

def list_handles(elements, key):
    handles = {}
    for e in elements:
        id = e[key]
        for h in e['handles']:
            handles[h] = id
    print("handles", handles)
    return handles

def load_json_topology(filename):
    data = json.loads(open(filename).read())

    getkey = lambda x: data['topology'][x] if x in data['topology'] else []

    devices = getkey('devices')
    middleboxes = getkey('middleboxes')
    switches = getkey('switches')
    links = getkey('links')

    devices_handles = list_handles(devices, 'hostname')
    middleboxes_handles = list_handles(middleboxes, 'type')

    return {'devices':devices_handles,'middleboxes':middleboxes_handles}

def extract_operation(nile_intent, op, op_idx):
    extracted_op = nile_intent[op_idx:].replace(op, '')
    next_op = next(((x for x in re.split('\W+', extracted_op) if x in config.NILE_OPERATIONS)), False)
    next_op_idx = nile_intent.find(next_op) if next_op else -1
    extracted_op = nile_intent[op_idx:next_op_idx] if next_op_idx >= 0 else nile_intent[op_idx:]

    return extracted_op


def extract_values(nile_intent, op, value_id):
    values = []
    op_idx = nile_intent.find(op)
    if op_idx >= 0:
        extracted_op = extract_operation(nile_intent, op, op_idx)
        extracted_op = re.sub('\s(?=[^\(\)]*\))', '-', extracted_op) #reaplce spaces inside values for dividers
        for term in extracted_op.replace(op, '').strip().split():
            print (term)
            m = re.search(value_id + '\((.+)\)(,?)', term)
            if m:
                values.append(m.group(1).replace('\'', ''))
    print values
    return values


def compile(nile_intent):
    compiled = ''

    middleboxes = extract_values(nile_intent, 'add', 'middlebox')
    src_targets = extract_values(nile_intent, 'from', 'endpoint')
    dest_targets = extract_values(nile_intent, 'to', 'endpoint')

    if not middleboxes:
        raise ValueError('No middlebox provided. Ask the user again.')

    if not src_targets or not dest_targets:
        raise ValueError('No targets provided. Ask the user again.')

    ip = 2
    # creating middleboxes
    for mb in middleboxes:
        mb_start = 'firewall' if mb == 'firewall' else 'snort' # support only firewall and ids middleboxes
        mb_start_cmd = '"./start_{}.sh 100 100 100 100 \'128KB\' 0 &"'.format(mb_start)
        mb_sh = 'echo {}\nvim-emu compute start -d vnfs_dc -n {} -i rjpfitscher/genic-vnf --net "(id=input,ip=10.0.0.{}0/24),(id=output,ip=10.0.0.{}1/24)" -c {}\n'.format(
            mb, mb, ip, ip, mb_start_cmd)
        ip += 1
        compiled += mb_sh

    # chaining middleboxes
    for idx, mb in enumerate(middleboxes):
        if idx == 0:
            src = src_targets[0]
            src_sh = 'echo {}\nvim-emu network add -b -src {}:client-eth0 -dst {}:input\n'.format(src + '-' + mb, src, mb)
            compiled += src_sh
        elif idx == len(middleboxes) - 1:
            dest = dest_targets[0]
            dest_sh = 'echo {}\nvim-emu network add -b -src {}:output -dst {}:server-eth0\n'.format(mb + '-' + dest, mb, dest)
            compiled += dest_sh

        if idx != len(middleboxes) - 1:
            next_mb = middleboxes[idx + 1]
            chain_mb_sh = 'echo {}\nvim-emu network add -b -src {}:output -dst {}:input\n'.format(mb + '-' + next_mb, mb, next_mb)
            compiled += chain_mb_sh

    return compiled

def compile_yacc(nile_intent):
    policy = ''

    filename = 'res/topology.json'
    handles = load_json_topology(filename)

    parser.yacc_compile(nile_intent)

    endpoints = parser.endpoints
    middleboxes = parser.middleboxes

    #for debug purpose 
    print 'endpoint source is: '+endpoints[0]
    print 'endpoint destination is : '+endpoints[1]
    for middlebox in middleboxes:
        print 'middleboxe is: '+middlebox

    if not middleboxes:
        raise ValueError('No middlebox provided. Ask the user again.')

    if len(endpoints) < 2:
        raise ValueError('No targets provided. Ask the user again.')

    if endpoints[0] not in handles['devices'].keys():
        raise ValueError('Client '+endpoints[0]+' not found')
    policy += 'Endpoint 1: '+ handles['devices'][endpoints[0]]

    if endpoints[1] not in handles['devices'].keys():
        raise ValueError('Client '+endpoints[1]+' not found')
    policy += '\nEndpoint 2: '+ handles['devices'][endpoints[1]]

    for middlebox in middleboxes:
        if middlebox not in handles['middleboxes'].keys():
            raise ValueError('Middlebox '+middlebox+' not found')
        policy += '\nAdd middlebox: '+handles['middleboxes'][middlebox]

    return policy


def deploy(policy):
    try:
        script_name = 'res/scripts/{}_intent.sh'.format(datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H%M%S'))
        with open(script_name, 'w') as script:
            script.write(policy)
            os.chmod(script_name, 0o777)

        subprocess.check_call('./' + script_name, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as err:
        raise ValueError('Deployment of compiled intent failed. Error: {}'.format(err))


def handle_request(request):
    status = {
        'code': 200,
        'details': 'Deployment success.'
    }

    intent = request.get('intent')
    policy = None
    try:
        policy = compile_yacc(intent)
        #deploy(policy)
    except ValueError as err:
        print 'Error: {}'.format(err)
        status = {
            'code': 404,
            'details': str(err)
        }

    return {
        'status': status,
        'input': {
            'type': 'nile',
            'intent': intent
        },
        'output': {
            'type': 'sonata-nfv commands',
            'policy': policy
        }
    }

# m = mappings.read()
