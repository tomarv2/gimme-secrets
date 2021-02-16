from click.testing import CliRunner
from src.gimme_secrets.cli import entrypoint
import os
import boto3
from moto import mock_ssm
import pytest


# @pytest.fixture(scope='module')
# def aws_credentials():
#     """Mocked AWS Credentials for moto."""
#     os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
#     os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
#     os.environ['AWS_SECURITY_TOKEN'] = 'testing'
#     os.environ['AWS_SESSION_TOKEN'] = 'testing'
#     os.environ['AWS_DEFAULT_REGION'] = 'us-west-2'
#
#
# @pytest.fixture(scope='module')
# def ssm(aws_credentials):
#     with mock_ssm():
#         yield boto3.client('ssm')
#
#
# def test_get_mock_ssm(ssm):
#     # We need to create the ssm entry first since this is all in Moto's 'virtual' AWS account
#     ssm.put_parameter(
#         Name='demo_parameter',
#         Description='name',
#         Value="hello world",
#         Type='String',
#         Overwrite=True,
#         Tier='Standard',
#         DataType='text'
#     )
#     from src.cli import entrypoint
#     runner = CliRunner()
#     response = runner.invoke(entrypoint, ["get", "--name", "demo_parameter"])
#     assert response.output == "hello world\n"


@mock_ssm
def test_get_mock_ssm():
    # We need to create the ssm entry first since this is all in Moto's 'virtual' AWS account
    client = boto3.client('ssm')
    client.put_parameter(
        Name='test',
        Description='name',
        Value='text',
        Type='String',
        Overwrite=True,
        Tier='Standard',
        DataType='text'
    )
    parameter = client.get_parameter(Name='test', WithDecryption=True)
    print('*' * 50)
    print(parameter)
    # print("value: {0}".format(parameter['Parameter']['Value']))
    # assert parameter == 'is awesome'


def test_parameter_store_get():
    runner = CliRunner()
    response = runner.invoke(entrypoint, ["get", "--name", "demo4", "--cloud", "aws"])
    assert response.exit_code == 0
    assert "hello" in response.output


def test_parameter_store_put_result():
    runner = CliRunner()
    response = runner.invoke(entrypoint, ["put", "--name", "demo"])
    assert response.exit_code == 0
    assert "hello world" in response.output


def test_encrypt():
    runner = CliRunner()
    response = runner.invoke(entrypoint, ["put", "--name", "demo"])
    assert response.exit_code == 0
    assert "hello world" in response.output


def test_decrypt():
    runner = CliRunner()
    response = runner.invoke(entrypoint, ["put", "--name", "demo"])
    assert response.exit_code == 0
    assert "hello world" in response.output

