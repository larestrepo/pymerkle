import pytest
from moto import mock_aws
import boto3
from pymerkle.concrete.dynamo import DynamoDBTree

@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    return {
        'aws_access_key_id': 'test',
        'aws_secret_access_key': 'test',
        'region_name': 'us-east-2'
    }

@pytest.fixture
def dynamodb(aws_credentials):
    with mock_aws():
        yield boto3.client(
            'dynamodb',
            region_name=aws_credentials['region_name'],
            aws_access_key_id=aws_credentials['aws_access_key_id'],
            aws_secret_access_key=aws_credentials['aws_secret_access_key']
        )

@mock_aws
@pytest.mark.parametrize(
    "names",
    [[], ["TestTable"], ["TestTable1", "TestTable2"]],
    ids=["no-table", "one-table", "multiple-tables"],
)
def test_list_tables_boto3(names):
    conn = boto3.client("dynamodb", region_name="us-west-2")
    for name in names:
        conn.create_table(
            TableName=name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
    assert conn.list_tables()["TableNames"] == names

@mock_aws
def test_create_table(dynamodb, aws_credentials):
    tags = {'Environment': 'Development', 'Project': 'ExampleProject'}
    handler = DynamoDBTree(
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key'],
        region_name=aws_credentials['region_name'],
        table_name='leaf',
        tags=tags
    )

    # Verify the table was created
    response = dynamodb.describe_table(TableName='default_app-leaf-dev')
    assert response['Table']['TableName'] == 'default_app-leaf-dev'
    assert response['Table']['ProvisionedThroughput']['ReadCapacityUnits'] == 5
    assert response['Table']['ProvisionedThroughput']['WriteCapacityUnits'] == 5