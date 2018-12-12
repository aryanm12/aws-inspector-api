import boto3
import MySQLdb
import csv
import time
import os
from configs.readconfig import configp

# --------------------------------Variable declaration section starts---------------------------------------#

if os.environ["ENV"] == 'dev':
    aws_access_key_id = configp.get('aws', 'aws_access_key_id')
    aws_secret_access_key = configp.get('aws', 'aws_secret_access_key')
else:
    from configs.readconfig import aws_configp
    aws_access_key_id = aws_configp['accessKey']
    aws_secret_access_key = aws_configp['serverAccessKey']

aws_region_name = configp.get('aws', 'aws_region_name')
mysql_host = configp.get('mysql', 'mysql_host')
mysql_user = configp.get('mysql', 'mysql_user')
mysql_password = configp.get('mysql', 'mysql_password')
mysql_db = configp.get('mysql', 'mysql_db')
timestr = time.strftime("%Y%m%d")
#timestr = '20181205'
aws_assessment_run_name = configp.get('aws', 'aws_assessment_run_name') + '_' + timestr
download_dir = "aws_vulnerability" + '_' + timestr + ".csv"

# --------------------------------Variable declaration section Ends---------------------------------------#


conn = MySQLdb.Connection(
    host=mysql_host,
    user=mysql_user,
    passwd=mysql_password,
    db=mysql_db,
    autocommit='true'
)


client = boto3.client('inspector',
                      aws_access_key_id = aws_access_key_id,
                      aws_secret_access_key = aws_secret_access_key,
                      region_name = aws_region_name
                      )


def list_todays_assessment_run():
    list_todays_assessment_run = client.list_assessment_runs(
        filter={
            'namePattern': aws_assessment_run_name + '*',
            'states': [
                'COMPLETED',
            ]
        }
    )
    return (list_todays_assessment_run)


def list_findings_last_assessments(assessmentRunArn):
    list_findings_last_assessments = client.list_findings(
        assessmentRunArns=[
            assessmentRunArn
        ],
        maxResults=500
    )
    return (list_findings_last_assessments['findingArns'])


def save_findings_to_csv(findings_arn):
    os.remove(download_dir)
    csv = open(download_dir, "a")
    columnTitleRow = "Plugin_ID, CVE, CVSS, Risk, Host, Protocol, Port, Name, Synopsis, Description, Solution, See_Also, Plugin_Output\n"
    csv.write(columnTitleRow)

    for finding in findings_arn:
        describe_findings = client.describe_findings(
            findingArns=[
                finding
            ],
            locale='EN_US'
        )
        Plugin_ID = 'NA'
        CVE = describe_findings['findings'][0]['id']
        CVSS = describe_findings['findings'][0]['attributes'][0]['value']
        Risk = describe_findings['findings'][0]['severity']
        Host = describe_findings['findings'][0]['assetAttributes']['networkInterfaces'][0]['publicIp']
        Protocol = 'NA'
        Port = 'NA'
        Name = describe_findings['findings'][0]['title']
        Synopsis = 'NA'
        Description = "\"" + describe_findings['findings'][0]['description'].replace("\"", "\"\"") + "\""
        Solution = "\"" + describe_findings['findings'][0]['recommendation'].replace("\"", "\"\"") + "\""
        See_Also = 'NA'
        Plugin_Output = 'NA'
        row = Plugin_ID + "," + CVE + "," + CVSS + "," + Risk + "," + Host + "," + Protocol + "," + Port + "," + Name + "," + Synopsis + "," + Description + "," + Solution + "," + See_Also + "," + Plugin_Output + "\n"
        csv.write(row)


def import_csv_to_mysql_table():
    cursor = conn.cursor()
    cursor.execute('TRUNCATE TABLE aws_vulnerability')
    csv_data = csv.reader(file(download_dir))
    headers = next(csv_data)
    for row in csv_data:
        cursor.execute('INSERT INTO `aws_vulnerability`(`Plugin_ID`, `CVE`, `CVSS`, \
        `Risk`, `Host`, `Protocol`, `Port`, `Name`, `Synopsis`, `Description`, `Solution`, \
        `See_Also`, `Plugin_Output`, `inserted_on`)' \
        'VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                       (row[0], row[1], row[2], row[3], row[4], row[5], \
                        row[6], row[7], row[8], row[9], row[10], row[11], row[12], timestr))
    cursor.close()



def main():
    assessment_run_arn = list_todays_assessment_run()
    findings_arn = list_findings_last_assessments(assessment_run_arn['assessmentRunArns'][0])
    save_findings_to_csv(findings_arn)
    import_csv_to_mysql_table()


main()
