import boto3
import collections
import ipaddress
import os
import json
import requests
import pandas as pd


SECURITY_PROFILE = 'security'
TARGET_PROFILE = 'target_security'
LOG_BUCKET_NAME = 'flaws2-logs'


class Defender:
    def __init__(self, security_profile, target_profile, log_s3_bucket):
        self.security_session = boto3.session.Session(profile_name=security_profile)
        self.target_session = boto3.session.Session(profile_name=target_profile)
        self.log_s3_bucket = log_s3_bucket

        self.aws_ip_ranges = self.get_valid_aws_ip_ranges()
        self.target_roles_df = self.retrieve_target_roles()
        self.verified_aws_ip = set()
        self.verified_non_aws_ip = set()

    def download_logs(self):
        s3 = self.security_session.resource('s3')
        log_bucket = s3.Bucket(self.log_s3_bucket)

        if not os.path.exists(self.log_s3_bucket):
            os.mkdir(self.log_s3_bucket)

        for obj in log_bucket.objects.all():
            path, filename = os.path.split(obj.key)
            log_bucket.download_file(obj.key, f'./{self.log_s3_bucket}/{filename}')

        gunzip_cmd = 'find . -type f -exec gunzip -q {} \;'
        os.system(gunzip_cmd)

    def retrieve_target_roles(self):
        iam_resource = self.target_session.client('iam')

        roles = iam_resource.list_roles()['Roles']

        for role in roles:
            print(role['Arn'])

        roles_df = pd.DataFrame(roles)
        return roles_df

    def read_events_to_dataframe(self):
        jq_cmd = f"cat ./{self.log_s3_bucket}/*.json | jq -cr '.Records[]|[.eventVersion, .eventTime, .sourceIPAddress, .userIdentity.arn, .userIdentity.accountId, .userIdentity.type, .userIdentity.sessionContext.sessionIssuer.arn, .eventName]|@tsv' | sort > events.csv"
        os.system(jq_cmd)

        column_names = ["EventVersion", "EventTime", "SourceIpAddr", "UserArn", "AccountId", "UserIdentityType", "Arn",
                        "EventName"]
        events = 'events.csv'
        return pd.read_csv(events, names=column_names, sep='\t')

    def detect_attacks(self):
        events_df = self.read_events_to_dataframe()
        events_df = events_df.merge(self.target_roles_df, on='Arn')

        for index, row in events_df.iterrows():
            role_policy = row.get('AssumeRolePolicyDocument')
            if not role_policy:
                continue

            request_service = role_policy['Statement'][0]['Principal']['Service']
            source_ip = row['SourceIpAddr']
            arn = row['Arn']

            if self.is_aws_service(role_policy) and (not self.is_aws_ip(source_ip)):
                event_time = row['EventTime']

                print(f'=============== Attack Detected !!! ================\n'
                      f'EventTime:\t {event_time}\n'
                      f'SourceIP:\t {source_ip}\n'
                      f'Service:\t {request_service}\n'
                      f'IAMRole:\t {arn}\n')

    def is_aws_service(self, role_policy):
        service = role_policy['Statement'][0]['Principal']['Service']
        aws_suffix = '.amazonaws.com'

        if service.endswith(aws_suffix):
            return True
        else:
            return False

    def get_valid_aws_ip_ranges(self):
        aws_url = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
        data = requests.get(aws_url).json()

        aws_ip_cidrs = []
        aws_ips = collections.defaultdict(list)

        for ip in data.get('prefixes'):
            region = ip.get('region')
            ip_cidr = ip.get('ip_prefix')
            aws_ips[region].append(ip_cidr)
            aws_ip_cidrs.append(ip_cidr)

        return aws_ip_cidrs

    def is_aws_ip(self, ip_addr):
        if ip_addr in self.verified_aws_ip:
            return True

        if ip_addr in self.verified_non_aws_ip:
            return False

        for aws_ip_cidr in self.aws_ip_ranges:
            if ipaddress.ip_address(ip_addr) in ipaddress.ip_network(aws_ip_cidr):
                self.verified_aws_ip.add(ip_addr)
                return True

        self.verified_non_aws_ip.add(ip_addr)
        return False


if __name__ == "__main__":
    defender = Defender(SECURITY_PROFILE, TARGET_PROFILE, LOG_BUCKET_NAME)
    defender.download_logs()
    defender.detect_attacks()
