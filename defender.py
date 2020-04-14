import boto3
import os
import pandas as pd


SECURITY_PROFILE = 'security'
TARGET_PROFILE = 'target_security'
LOG_BUCKET_NAME = 'flaws2-logs'


class Defender:
    def __init__(self, security_profile, target_profile, log_s3_bucket):
        self.security_session = boto3.session.Session(profile_name=security_profile)
        self.target_session = boto3.session.Session(profile_name=target_profile)
        self.log_s3_bucket = log_s3_bucket
        self.target_roles_df = self.retrieve_target_roles()

    def download_logs(self):
        s3 = self.security_session.resource('s3')
        log_bucket = s3.Bucket(LOG_BUCKET_NAME)

        if not os.path.exists(self.log_s3_bucket):
            os.mkdir(self.log_s3_bucket)

        for obj in log_bucket.objects.all():
            path, filename = os.path.split(obj.key)
            log_bucket.download_file(obj.key, f'./{LOG_BUCKET_NAME}/{filename}')

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


    def detect_attack(self):
        print(self.target_roles_df.columns)
        print(self.target_roles_df['Arn'])

        events_df = self.read_events_to_dataframe()
        events_df = events_df.merge(self.target_roles_df, on='Arn')

        for index, row in events_df.iterrows():
            role_policy = row.get('AssumeRolePolicyDocument')
            if not role_policy:
                continue

            request_service = role_policy['Statement'][0]['Principal']['Service']
            source_ip = row['SourceIpAddr']
            arn = row['Arn']

            # print(source_ip, request_service)

            if self.is_aws_service(role_policy) and self.invalid_aws_ip(source_ip):
                event_time = row['EventTime']

                print(f'=============== Attack Identified ================\n'
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

    def invalid_aws_ip(self, ip_addr):
        if ip_addr == '104.102.221.250':
            return True
        else:
            return False


# download log files
defender = Defender(SECURITY_PROFILE, TARGET_PROFILE, LOG_BUCKET_NAME)

defender.download_logs()

# target_roles_df = defender.read_role_from_csv()


defender.detect_attack()

# events_df = defender.read_events_to_dataframe()
# print(events_df.columns)
#
# events_df = events_df.merge(target_roles_df, on='Arn')
# print(events_df.columns)
# print(events_df[['EventVersion', 'SourceIpAddr', 'Arn', 'AssumeRolePolicyDocument']])


# def read_to_dataframe(self):
#     file_list = glob.glob('*.json')
#
#     df = pd.DataFrame()
#
#     for file in file_list:
#         data = pd.read_json(file, lines=True)
#         print(data['Records'])
#         df = df.append(data['Records'], ignore_index=True)
#
#     return df
#
# def read_role_from_csv(self):
#     return pd.read_csv('target_roles.csv')






