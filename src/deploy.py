"""
    Scope of  module:
    * Fetch aws credentials from env or user-input
    * Verify credentials and permissions
    * Select location to deploy
    * Select VPC/subnet to deploy
    * Create IAM Role for deployment
    * Create security group
    * Launch instance in selected location, VPC, subnet

    @TODO:
    * Use policy_simulator to test out permissions for credentials in one-go

"""
import logging
import sys
import pprint
import os
import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import EndpointConnectionError

global PlatformName
global PolicyDocument
global TrustPolicyDocument
global PolicyName
global InstanceTypes
global logger
global log_dir

PlatformName = 'KinantPlatform'
PolicyName = 'KinantPlatformIAMPolicy'
TrustPolicyDocument = """{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}"""
PolicyDocument = """{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:List*",
                "elasticfilesystem:Describe*",
                "elasticfilesystem:CreateMountTarget",
                "kms:Get*",
                "s3:Get*",
                "ec2:*",
                "kms:Describe*",
                "s3:List*"
            ],
            "Resource": "*"
        }
    ]
}"""

InstanceTypes = ['t2.medium', 't2.large', 't2.xlarge']
log_dir = 'logs'

def create_IAM_role(session):
    client = session.client('iam')
    global logger
    logger.info('Creating IAM Role:%s', PlatformName)
    try:
        client.create_role(
            RoleName=PlatformName,
            AssumeRolePolicyDocument=TrustPolicyDocument,
            Description='KinantPlatform IAM Role'
        )
        logger.info('\tIAM Role created:%s', PlatformName)
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            logger.warn('\tRole already Exists.')
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error('AWS credentials do not have permission to create a IAM Role.')
            logger.error('Restart with proper credentials.')
            sys.exit()
        else:
            logger.critical('Unexpected Client error:%s', e)
            sys.exit()
    except:
        logger.critical("Unexpected error:%s", sys.exc_info())
        sys.exit()

    logger.info('Attaching following document as Inline Policy to Role:')
    logger.info('%s', PolicyDocument)
    try:
        response = client.put_role_policy(
            RoleName=PlatformName,
            PolicyName=PolicyName,
            PolicyDocument=PolicyDocument,
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error('AWS credentials do not have permission to attach policy to a IAM Role.')
            logger.error('Restart with proper credentials.')
            sys.exit()
        else:
            logger.critical('Unexpected Client error:%s', e)
            sys.exit()
    except:
        logger.critical("Unexpected error:%s", sys.exc_info())
        sys.exit()

    logger.info('Creating Instance Profile:%s', PlatformName)
    try:
        response = client.create_instance_profile(
            InstanceProfileName=PlatformName
        )
        logger.info('\tCreated Instance Profile:%s', PlatformName)
        logger.info('')
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            logger.warn('\tInstance Profile already Exists.')
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error('AWS credentials do not have permission to create instance profile.')
            logger.error('Restart with proper credentials.')
            sys.exit()
        else:
            logger.critical('Unexpected Client error:%s', e)
            sys.exit()
    except:
        logger.critical("Unexpected error:%s", sys.exc_info())
        sys.exit()

    logger.info('Attaching Role to Instance Profile')
    try:
        response = client.add_role_to_instance_profile(
            InstanceProfileName=PlatformName,
            RoleName=PlatformName
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'LimitExceeded':
            logger.warn('\tRole Already attached to Instance Profile.')
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error(
                'AWS credentials do not have permission to '
                'attach instance profile to Role.'
            )
            logger.error('Restart with proper credentials.')
            sys.exit()
        else:
            logger.critical('Unexpected Client error:%s', e)
            sys.exit()
    except:
        logger.critical("Unexpected error:%s", sys.exc_info())
        sys.exit()
    logger.info('')

def create_security_group(session, vpc):
    global logger
    logger.info('Creating AWS security group in region:%s and VPC:%s.', session.region_name, vpc)
    client = session.client('ec2')
    try:
        response = client.create_security_group(
            Description='Security group for KinantPlatform',
            GroupName=PlatformName,
            VpcId=vpc
        )
        logger.info('\tCreated AWS security group:%s', PlatformName)
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
            logger.warn('\tSecurity Group Already Exists.')
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error('AWS credentials do not have permission to create security group')
            logger.error('Restart with proper credentials.')
            sys.exit()
        else:
            logger.critical('Unexpected Client Error:')
            logger.critical('%s', e)
            sys.exit()
    except:
        logger.critical("Unexpected error:%s", sys.exc_info())
        sys.exit()

    sgid = ''
    try:
        response = client.describe_security_groups(
            Filters=[{'Name':'vpc-id', 'Values':[vpc]}, {'Name':'group-name', 'Values':[PlatformName]}]
        )
        sgid = response['SecurityGroups'][0]['GroupId']
    except ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error('AWS credentials do not have permission to create security group.')
            logger.error('Restart with proper credentials.')
            sys.exit()
        else:
            logger.critical('Unexpected Client Error:%s', e)
            sys.exit()
    except:
        logger.critical("Unexpected error:%s", sys.exc_info())
        sys.exit()

    try:
        response = client.authorize_security_group_ingress(
            GroupId=sgid,
            IpProtocol="tcp",
            CidrIp="0.0.0.0/0",
            FromPort=8000,
            ToPort=8000
        )
        response = client.authorize_security_group_ingress(
            GroupId=sgid,
            IpProtocol="tcp",
            CidrIp="0.0.0.0/0",
            FromPort=8443,
            ToPort=8443
        )
        response = client.authorize_security_group_ingress(
            GroupId=sgid,
            IpProtocol="tcp",
            CidrIp="0.0.0.0/0",
            FromPort=22,
            ToPort=22
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
            pass
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error('AWS credentials do not have permission to add ingress permission to security group.')
            logger.error('Restart with proper credentials.')
            sys.exit()
        else:
            logger.critical('Unexpected Client Error:%s', e)
            sys.exit()
    except:
        logger.critical("Unexpected error:%s", sys.exc_info())
        sys.exit()
    return sgid

def get_ami_id():
    # TODO: fetch AMI-id from backend for a given location and customer-id
    global logger
    ami = accept_valid_input(
        'Enter AMI id for your region, '
        'contact us at contactus@kinant.com in case you dont have our AMI id:'
    )
    logger.debug('User Input AMI-id:%s', ami)
    #ami = 'ami-10547475'
    return ami

def get_instance_type():
    global logger
    logger.info('Choose instance-type, pick one of the following:%s', InstanceTypes)
    instance_type = ''
    while instance_type not in InstanceTypes:
        instance_type = input('Enter instance-type:')
        if instance_type not in InstanceTypes:
            logger.info('Incorrect response, try again...')
    logger.debug('User Input:%s', instance_type)
    logger.info('')
    return instance_type

def get_name(tags):
    for t in tags:
        for key in t:
            if t[key] == 'Name':
                return t['Value']
    return ''

def print_subnets(subnets):
    global logger
    logger.info('Listing Subnets:')
    for s in subnets:
        logger.info(
            '\tSubnetId:%s AvailabilityZone:%s State:%s',
            s['SubnetId'], s['AvailabilityZone'], s['State']
        )
        logger.info('')

def get_subnet_list(subnets):
    l = []
    for s in subnets:
        l.append(s['SubnetId'])
    return l

def input_subnet(subnets):
    global logger
    subnet = ''
    while subnet not in subnets:
        subnet = input("Enter SubnetId:")
        if subnet not in subnets:
            logger.info('Incorrect response, please enter again...')
    logger.debug('User Input:%s', subnet)
    return subnet

def print_vpcs(vpcs):
    global logger
    logger.info('Listing VPCs:')
    for v in vpcs:
        if v['IsDefault'] == True:
            logger.info('\tVpcId:%s (default)', v['VpcId'])
        else:
            logger.info('\tVpcId:%s', v['VpcId'])
        if 'Tags' in v:
            name = get_name(v['Tags'])
            if name != '':
                logger.info('\t\tName:%s', name)

def get_vpc_list(vpcs):
    l = []
    default = ''
    for v in vpcs:
        l.append(v['VpcId'])
        if v['IsDefault'] == True:
            default = v['VpcId']
    return l, default

def input_vpc(vpcs, default):
    global logger
    vpc = input("Enter VpcId(empty for default):")
    if vpc == '':
        return default
    else:
        if vpc not in vpcs:
            logger.info('Incorrect response, please enter again...')
            vpc = input_vpc(vpcs, default)
    logger.debug('User Input:%s', vpc)
    return vpc

def get_vpc_id(session):
    """Returns user selected vpc-id
    """
    ec2 = session.client('ec2')
    vpcs = ec2.describe_vpcs()
    vpcs = vpcs['Vpcs']
    print_vpcs(vpcs)
    (vpcs, default) = get_vpc_list(vpcs)
    vpc = input_vpc(vpcs, default)
    return vpc

def get_subnet_id(session, vpc):
    """Returns user selected subnet-id for a given vpc
    """
    ec2 = session.client('ec2')
    subnets = ec2.describe_subnets(Filters=[{'Name':'vpc-id', 'Values':[vpc]}])
    subnets = subnets['Subnets']
    print_subnets(subnets)
    (subnets) = get_subnet_list(subnets)
    subnet = input_subnet(subnets)
    return subnet

def get_tag_spec():
    kv = [{'Key':'Name', 'Value':PlatformName}]
    instance_tag = {'ResourceType':'instance', 'Tags':kv} 
    volume_tag = {'ResourceType':'volume', 'Tags':kv}
    spec = [instance_tag, volume_tag]
    return spec

def print_instance_info(session, instance_id):
    try:
        client = session.client('ec2')
        response = client.describe_instances(InstanceIds=[instance_id])
    except ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error('AWS credentials do not have permission to launch an instance.')
            logger.error('Restart with proper credentials.')
            sys.exit()
        else:
            logger.critical('Unexpected Client Error:%s', e)
            sys.exit()
    except:
        logger.critical("Unexpected error:%s", sys.exc_info())
        sys.exit()
    meta = response['Reservations'][0]['Instances'][0]
    display_meta = dict()
    display_meta['InstanceId'] = meta['InstanceId']
    display_meta['InstanceType'] = meta['InstanceType']
    display_meta['SecurityGroups'] = meta['SecurityGroups']
    display_meta['SubnetId'] = meta['SubnetId']
    display_meta['VpcId'] = meta['VpcId']
    display_meta['PrivateIpAddress'] = meta['NetworkInterfaces'][0]['PrivateIpAddress']
    try:
        display_meta['NetworkAssosiation'] = meta['NetworkInterfaces'][0]['Association']
    except KeyError:
        pass
    logger.info("Instance Metadata:")
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(display_meta)
    logger.debug(display_meta)


def create_instance(session, subnet, ami, sg_id):
    ec2 = session.resource('ec2')
    instance_type = get_instance_type()
    tag_spec = get_tag_spec()
    logger.info('Creating Instance...')
    try:
        response = ec2.create_instances(
            ImageId=ami,
            InstanceType=instance_type,
            IamInstanceProfile={'Name': PlatformName},
            SubnetId=subnet,
            SecurityGroupIds=[sg_id],
            MinCount=1,
            MaxCount=1,
            TagSpecifications=tag_spec
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error('AWS credentials do not have permission to launch an instance.')
            logger.error('Restart with proper credentials.')
            sys.exit()
        else:
            logger.critical('Unexpected Client Error:%s', e)
            sys.exit()
    except:
        logger.critical('Unexpected error:%s', sys.exc_info())
        sys.exit()
    logger.info("\tInstance created")
    print_instance_info(session, response[0].id)

def accept_valid_input(display_str):
    val = ''
    while val == '':
        val = input(display_str)
    return val

def create_new_session():
    aws_access_key_id = accept_valid_input('Enter AWS Access Key ID:')
    aws_secret_access_key = accept_valid_input('Enter AWS Secret Access Key:')
    region_name = accept_valid_input('Enter AWS region:') 
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
    )
    return session

def input_region(session):
    global logger
    regions = session.get_available_regions('ec2')
    logger.info('Chose one from following:%s', regions)
    region = ''
    while region not in regions:
        region = input('Enter region to deploy:')
        if region not in regions:
            logger.warn('Incorrect response, try again.')
    logger.debug('User Input:%s', region)
    return region

def check_credentials(session, ami):
    global logger
    # Run dummy deploy command to check location and credentials.
    ec2 = session.resource('ec2')
    try:
        ec2.create_instances(
            ImageId=ami,
            InstanceType='t2.nano',
            MinCount=1,
            MaxCount=1,
            DryRun=True
        )
    except EndpointConnectionError as e:
        logger.error('Invalid location specified:%s', session.region_name)
        logger.error('Restart with correct location.')
        sys.exit()
    except ClientError as e:
        if e.response['Error']['Code'] == 'AuthFailure':
            logger.error('Authorization Failure, AWS was not able to validate the provided access credentials.')
            logger.error('Restart with proper credentials.')
            sys.exit()
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error('AWS credentials do not have permission to launch an instance.')
            logger.error('Restart with proper credentials.')
            sys.exit()
        elif e.response['Error']['Code'] == 'InvalidAMIID.NotFound' or e.response['Error']['Code'] == 'InvalidAMIID.Malformed':
            logger.error('Invalid AMI-id:%s, restart with correct AMI-id', ami)
            logger.error('Get in touch with us at contactus@kinant.com in case you dont have our AMI-id.')
            sys.exit()
        elif e.response['Error']['Code'] == 'DryRunOperation':
            pass
        else:
            logger.critical('Unexpected Client Error:%s', e)
            sys.exit()
    except:
        logger.critical("Unexpected error:%s", sys.exc_info())
        sys.exit()
    return session

def create_session():
    """Returns a session handler
    """
    global logger
    prompt = 'tmp_string'
    logger.debug('Fetching AWS credentials.')
    while prompt != '' and prompt != 'y' and prompt != 'Y':
        prompt = input(
            'Press Enter to fetch AWS credentials from enviornment,'
            'press y/Y to manually enter credentials:'
        )
        if prompt != '' and prompt != 'y' and prompt != 'Y':
            logger.warn('Incorrect response, try again...')
    logger.debug('User Input:%s', prompt)
    if prompt == '':
        session = boto3.Session()
        credentials = session.get_credentials()
        if hasattr(credentials, 'get_frozen_credentials'):
            logger.info('\tFound credentials in enviornment.\n')
            if session.region_name == '':
                logger.warn('No default region configured.')
                region = input_region(session)
                session = boto3.Session(region_name=region)
            else:
                region = session.region_name
                logger.info('Choosing default region:%s', region)
                prompt = input('Press Enter to continue, or Y/y to change region:')
                logger.debug('User Input:%s', prompt)
                if prompt == 'y' or prompt == 'Y':
                    region = input_region(session)
                session = boto3.Session(region_name=region)
        else: # No credentials found in env
            logger.warn(
                'Unable to locate AWS credentials from enviornment.\n'
                'Either exit and run aws-cli to configure your enviornment'
                '(use:$aws configure), or\n'
                'continue to enter your aws credentials.'
            )
            prompt = input('Enter Y/y to continue:')
            if prompt == 'y' or prompt == 'Y':
                session = create_new_session()
            else:
                sys.exit()
    else: # Prompt to Enter credentials
        session = create_new_session()
    logger.info('')
    return session

def get_network_ids(session):
    """Returns selected vpc and subnet
    """
    vpc = get_vpc_id(session)
    subnet = get_subnet_id(session, vpc)
    logger.info('')
    return vpc, subnet

def create_log_dir():
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

def get_file_handle():
    from datetime import datetime
    fname = str(datetime.now())
    handle = logging.FileHandler(log_dir + '/' + fname)
    handle.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)-8s %(message)s')
    handle.setFormatter(formatter)
    return handle

def get_stream_handle():
    handle = logging.StreamHandler(sys.stdout)
    handle.setLevel(logging.INFO)
    return handle

def configure_logging():
    """Configures global logger

    Configures logger such that, all logs with level >= debug
    are logged in the log file in folder log_dir and all logs
    with level >= info are logged onto console.
    """
    create_log_dir()
    global logger
    logger = logging.getLogger('Logger')
    logger.setLevel(logging.DEBUG)
    fh = get_file_handle()
    sh = get_stream_handle()
    logger.addHandler(fh)
    logger.addHandler(sh)

def display_intro():
    logger.info(
        '\tWelcome to %s deployment utility.\n'
        '\tDuring the course of the deployment, we will:\n'
        '\t\t1. Check for AWS credentials.\n'
        '\t\t2. Select VPC/Subnet for deployment.\n'
        '\t\t3. Create a security group in the said VPC.\n'
        '\t\t4. Create an IAM Role for the instance to be deployed.\n'
        '\t\t5. Deploy the Platfrom instance.',
        PlatformName
    )
    input('press ENTER to continue.')

def deploy():
    display_intro()
    session = create_session()
    ami = get_ami_id()
    check_credentials(session, ami)
    (vpc, subnet) = get_network_ids(session)
    sg_id = create_security_group(session, vpc)
    create_IAM_role(session)
    create_instance(session, subnet, ami, sg_id)


if __name__ == '__main__':
    configure_logging()
    deploy()

