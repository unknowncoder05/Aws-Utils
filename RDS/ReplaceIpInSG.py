#ACTION: raplace All Security groups IP
#WHERE: selected Data Bases
#IF: Security Groups Tag is Equal To the Specified

import boto3

TAG_NAME ="TAG"
NEW_IP = "IP/32"
DDBB = ["test-db-1","test-db-2"]


rdsc = boto3.client('rds')
dbi=rdsc.describe_db_instances(
Filters=[
        {'Name': 'db-instance-id','Values': [ DB ]}
        for DB  in DDBB
        ]
)
ec2 = boto3.resource('ec2')
for i in dbi["DBInstances"]:
    print("DBinstance>",i["DBInstanceIdentifier"])
    for sg in i["VpcSecurityGroups"]:
        print("sg>",sg["VpcSecurityGroupId"])
        security_group=ec2.SecurityGroup(sg["VpcSecurityGroupId"])
        rule_to_change = None
        for permission in security_group.ip_permissions:
            print("port>",permission["FromPort"])
            for ipp in permission["IpRanges"]:
                if(TAG_NAME == ipp["Description"]):
                    rule_to_change = ipp
                    break
            print("Removing>",rule_to_change["CidrIp"],permission["FromPort"])
            security_group.revoke_ingress(
                CidrIp = rule_to_change["CidrIp"],
                FromPort=permission["FromPort"],
                ToPort=permission["FromPort"],
                IpProtocol=permission["IpProtocol"],
            )
            print("Adding>",NEW_IP)
            security_group.authorize_ingress(
                IpPermissions=[
                    {
                    'FromPort': permission["FromPort"],
                    'ToPort': permission["FromPort"],
                    'IpProtocol': permission["IpProtocol"],
                    'IpRanges': [
                            {
                                'CidrIp': NEW_IP,
                                'Description': TAG_NAME
                            },
                        ],
                    }
                ],
            )
