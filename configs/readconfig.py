import os, sys
import ConfigParser
import requests


ENV_CONFIG = {
    'dev': 'dev',
    'prod': 'prod'
}

ENV=os.environ["ENV"]


def load_env_configuration(env):
    if not env:
        print('Please define the ENV')
        sys.exit(1)
    config = ConfigParser.RawConfigParser()
    config.read((os.path.join(os.getcwd(), 'configs/%s.cfg' % ENV_CONFIG[env])))
    return config


global configp
configp = load_env_configuration(ENV)


def get_aws_keys(env):
    aws_config = ConfigParser.RawConfigParser()
    aws_config.read((os.path.join(os.getcwd(), 'configs/%s.cfg' % ENV_CONFIG[env])))
    aws_account_details = requests.get('%s/%s' % (aws_config.get('aws', 'aws_nagarro_creds_api'),aws_config.get('aws', 'aws_account_id')))
    return(aws_account_details.json())


if ENV != 'dev':
    global aws_configp
    aws_configp = get_aws_keys(ENV)