import boto3
import time
import os
from configs.readconfig import configp

#--------------------------------Variable declaration section starts---------------------------------------#

if os.environ["ENV"] == 'dev':
	aws_access_key_id = configp.get('aws','aws_access_key_id')
	aws_secret_access_key = configp.get('aws','aws_secret_access_key')
else:
	from configs.readconfig import aws_configp
	aws_access_key_id = aws_configp['accessKey']
	aws_secret_access_key = aws_configp['serverAccessKey']

aws_region_name = configp.get('aws', 'aws_region_name')
aws_ec2_key = configp.get('aws','aws_ec2_key')
aws_ec2_value = configp.get('aws','aws_ec2_value')
assessment_run_time = configp.get('aws','assessment_run_time')
timestr = time.strftime("%Y%m%d-%H%M%S")
aws_assessment_target_name = configp.get('aws', 'aws_assessment_target_name') + '_' + timestr
aws_assessment_template_name = configp.get('aws', 'aws_assessment_template_name') + '_' + timestr
aws_assessment_run_name = configp.get('aws', 'aws_assessment_run_name') + '_' + timestr
cve_rule_arn = configp.get('aws', 'cve_rule_arn')

#--------------------------------Variable declaration section Ends---------------------------------------#



client = boto3.client('inspector',
						aws_access_key_id = aws_access_key_id,
						aws_secret_access_key = aws_secret_access_key,
						region_name = aws_region_name
)


client_ssm = boto3.client('ssm',
						aws_access_key_id = aws_access_key_id,
						aws_secret_access_key = aws_secret_access_key,
						region_name = aws_region_name
)

		
def create_inspector_targets():
	resource_group_ec2 = client.create_resource_group(
		resourceGroupTags=[
			{
				'key': aws_ec2_key,
				'value': aws_ec2_value
			},
		]
	)
	
	assessment_target_ec2 = client.create_assessment_target(
		assessmentTargetName=aws_assessment_target_name,
		resourceGroupArn=resource_group_ec2['resourceGroupArn']
	)
	
	print(assessment_target_ec2)
	return(assessment_target_ec2)


def install_inspector_agent():
	response = client_ssm.send_command(
		Targets=[
			{
				'Key': 'tag:' + aws_ec2_key,
				'Values': [aws_ec2_value]
			},
		],
		DocumentName='AmazonInspector-ManageAWSAgent',
		Parameters={
			'Operation': [
				'Install'
			]
		}
	)
	print(response)


def create_inspector_assessment_template(assessmentTargetArn):

	assessment_template = client.create_assessment_template(
		assessmentTargetArn=assessmentTargetArn,
		assessmentTemplateName=aws_assessment_template_name,
		durationInSeconds=int(assessment_run_time),
		rulesPackageArns=[
			cve_rule_arn
		]
	)
	print(assessment_template)
	return(assessment_template)


def run_assessment(assessmentTemplateArn):
	run_assessment = client.start_assessment_run(
		assessmentTemplateArn=assessmentTemplateArn,
		assessmentRunName=aws_assessment_run_name
	)
	print(run_assessment)
	return(run_assessment)
	
	
def check_assessment_status(assessmentRunArn):
	check_assessment_status = client.describe_assessment_runs(
		assessmentRunArns=[
			assessmentRunArn
		]
	)
	print(check_assessment_status)

	
def main():
	assessment_target_ec2_arn = create_inspector_targets()
	install_inspector_agent()
	assessment_template_arn = create_inspector_assessment_template(assessment_target_ec2_arn['assessmentTargetArn'])
	run_assessment_arn = run_assessment(assessment_template_arn['assessmentTemplateArn'])
	check_assessment_status(run_assessment_arn['assessmentRunArn'])

main()