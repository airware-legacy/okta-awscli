""" AWS authentication """
# pylint: disable=C0325
import os
import base64
import xml.etree.ElementTree as ET
from collections import namedtuple
from configparser import RawConfigParser
import boto3
from botocore.exceptions import ClientError

from oktaawscli.aws_accts_conf import aws_acct_ids

class AwsAuth(object):
    """ Methods to support AWS authentication using STS """

    def __init__(self, profile, okta_profile, verbose, logger):
        home_dir = os.path.expanduser('~')
        self.creds_dir = home_dir + "/.aws"
        self.creds_file = self.creds_dir + "/credentials"
        self.profile = profile
        self.verbose = verbose
        self.logger = logger
        self.role = ""

        okta_config = home_dir + '/.okta-aws'
        parser = RawConfigParser()
        parser.read(okta_config)

        if parser.has_option(okta_profile, 'role'):
            self.role = parser.get(okta_profile, 'role')
            self.logger.debug("Setting AWS role to %s" % self.role)

    def choose_aws_role(self, assertion):
        """ Choose AWS role from SAML assertion """
        aws_attribute_role = 'https://aws.amazon.com/SAML/Attributes/Role'
        attribute_value_urn = '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
        roles = []
        role_tuple = namedtuple("RoleTuple", ["principal_arn", "role_arn", "role_name", "account_id", "account_name"])
        root = ET.fromstring(base64.b64decode(assertion))
        for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if saml2attribute.get('Name') == aws_attribute_role:
                for saml2attributevalue in saml2attribute.iter(attribute_value_urn):
                    principal_arn, role_arn = saml2attributevalue.text.split(',')
                    role_name = role_arn.split('/')[1]
                    account_id = role_arn.split(':')[4]
                    try:
                        account_name =  aws_acct_ids[account_id]
                    except KeyError:
                        account_name =  account_id
                    roles.append(role_tuple(principal_arn, role_arn, role_name, account_id, account_name))

        roles.sort(key=lambda e:e.account_name+e.role_name)

        selection_list = []

        col1 = len(str(len(roles) + 1)) + 2 # 1 to get index, 1 for the ':', 1 for the space
        col2 = max(len(e.account_name) for e in roles) + 1
        format_string = "{:<" + str(col1) +"}{:<" + str(col2) +"}{}"

        for index, role in enumerate(roles):
            # Return the role as soon as it matches the saved role
            # Proceed to user choice if it's not found.
            if self.role:
                if role.role_name == self.role:
                    self.logger.info("Using predefined role: %s" % self.role)
                    return roles[index]

            selection_list.append(format_string.format(str(index + 1) + ":", role.account_name, role.role_name))

        if self.role:
            self.logger.info("Predefined role, %s, not found in the list of roles assigned to you."
                             % self.role)
            self.logger.info("Please choose a role.")

        for index, selection in enumerate(selection_list):
            print(selection)

        role_choice = int(input('Please select the AWS role: ')) - 1
        return roles[role_choice]

    @staticmethod
    def get_sts_token(role_arn, principal_arn, assertion):
        """ Gets a token from AWS STS """

        # Connect to the GovCloud STS endpoint if a GovCloud ARN is found.
        arn_region = principal_arn.split(':')[1]
        if arn_region == 'aws-us-gov':
            sts = boto3.client('sts', region_name='us-gov-west-1')
        else:
            sts = boto3.client('sts')

        response = sts.assume_role_with_saml(RoleArn=role_arn,
                                             PrincipalArn=principal_arn,
                                             SAMLAssertion=assertion)
        credentials = response['Credentials']
        return credentials

    def check_sts_token(self, profile):
        """ Verifies that STS credentials are valid """
        # Don't check for creds if profile is blank
        if not profile:
            return False

        parser = RawConfigParser()
        parser.read(self.creds_file)

        if not os.path.exists(self.creds_dir):
            self.logger.info("AWS credentials path does not exist. Not checking.")
            return False

        elif not os.path.isfile(self.creds_file):
            self.logger.info("AWS credentials file does not exist. Not checking.")
            return False

        elif not parser.has_section(profile):
            self.logger.info("No existing credentials found. Requesting new credentials.")
            return False

        session = boto3.Session(profile_name=profile)
        sts = session.client('sts')
        try:
            sts.get_caller_identity()

        except ClientError as ex:
            if ex.response['Error']['Code'] == 'ExpiredToken':
                self.logger.info("Temporary credentials have expired. Requesting new credentials.")
                return False

        self.logger.info("STS credentials are valid. Nothing to do.")
        return True

    def write_sts_token(self, profile, access_key_id, secret_access_key, session_token):
        """ Writes STS auth information to credentials file """
        region = 'us-east-1'
        output = 'json'
        if not os.path.exists(self.creds_dir):
            os.makedirs(self.creds_dir)
        config = RawConfigParser()

        if os.path.isfile(self.creds_file):
            config.read(self.creds_file)

        if not config.has_section(profile):
            config.add_section(profile)

        config.set(profile, 'output', output)
        config.set(profile, 'region', region)
        config.set(profile, 'aws_access_key_id', access_key_id)
        config.set(profile, 'aws_secret_access_key', secret_access_key)
        config.set(profile, 'aws_session_token', session_token)

        with open(self.creds_file, 'w+') as configfile:
            config.write(configfile)
        self.logger.info("Temporary credentials written to profile: %s" % profile)
        self.logger.info("Invoke using: aws --profile %s <service> <command>" % profile)
