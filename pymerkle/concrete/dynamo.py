import binascii
import json
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from typing import Any
from pymerkle.core import BaseMerkleTree

class ResponseDynamoDBException(Exception):
    """Custom exception for DynamoDB response errors."""
    pass


class DynamoDBTree(BaseMerkleTree):
    """
    Persistent Merkle-tree implementation using a SQLite database as storage.

    Inserted data is expected to be in binary format and hashed without
    further processing.

    .. note:: The database schema consists of a single table called *leaf*
        with two columns: *index*, which is the primary key serving as leaf
        index, and *entry*, which is a blob field storing the appended data.

    :param dbfile: database filepath
    :type dbfile: str
    :param algorithm: [optional] hashing algorithm. Defaults to *sha256*
    :type algorithm: str
    """
    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, region_name: str = "us-east-2", table_name: str = 'leaf', tags: dict=None, algorithm='sha256', **opts):
        try:
            self.dynamodb = boto3.client(
                'dynamodb',
                region_name=region_name,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key
            )
            
            # Check if the table exists
            table_name = f"{opts.get('app_name', 'default_app')}-{table_name}-{opts.get('env', 'dev')}"
            try:
                self.dynamodb.describe_table(TableName=table_name)
                print(f"Table {table_name} already exists. Using the existing table.")
            except self.dynamodb.exceptions.ResourceNotFoundException:
                # Table does not exist, create it
                table_params = {
                    'TableName': table_name,
                    'KeySchema': [
                        {
                            'AttributeName': 'id',
                            'KeyType': 'HASH'
                        }
                    ],
                    'AttributeDefinitions': [
                        {
                            'AttributeName': 'id',
                            'AttributeType': 'N'
                        }
                    ],
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                }
                if tags:
                    table_params['Tags'] = [{'Key': k, 'Value': v} for k, v in tags.items()]
                self.dynamodb.create_table(**table_params)
                self.create = True
                print(f"Table {table_name} created successfully.")
                
        except (NoCredentialsError, PartialCredentialsError) as e:
            raise ResponseDynamoDBException(f"Credentials error: {e}")
        super().__init__(algorithm, **opts)
        self.table_name = table_name


    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.dynamodb.close()

    def delete_db(self):
        self.dynamodb.delete_table(TableName=self.table_name)

    def _store_leaf(self, data: Any, digest_hex: str) -> int:
        """
        Creates a new leaf storing the provided data along with its
        hash value.

        :param data: data entry
        :type data: whatever expected according to application logic
        :param digest: hashed data
        :type digest: bytes
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """
        try:
            new_id = self._get_size() + 1
            self.dynamodb.put_item(
                TableName=self.table_name,
                Item={
                    'id': {'N': str(new_id)},
                    'entry': {'S': json.dumps(data)},
                    # 'hash_bytes': {'S': data.hex()},
                    'hash_hex': {'S': digest_hex}
                }
            )
            return new_id
        except Exception as e:
            raise ResponseDynamoDBException(f"Failed to store leaf: {e}")


    def _get_leaf(self, index: int):
        """
        Returns the hash stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        try:
            response = self.dynamodb.get_item(
                TableName=self.table_name,
                Key={'id': {'N': str(index)}}
            )
            # convert hex to bytes
            hash_bytes: bytes = binascii.unhexlify(response['Item']['hash_hex']['S'])
            return hash_bytes
        except Exception as e:
            raise ResponseDynamoDBException(f"Failed to get leaf: {e}")
    
    def _get_leaf_hex(self, index: int):
        """
        Returns the hash stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        try:
            response = self.dynamodb.get_item(
                TableName=self.table_name,
                Key={'id': {'N': str(index)}}
            )
            return response['Item']['hash_hex']['S']
        except Exception as e:
            raise ResponseDynamoDBException(f"Failed to get leaf hex: {e}")

    def _get_leaves(self, offset, width):
        """
        Returns in respective order the hashes stored by the leaves in the
        specified range.

        :param offset: starting position counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        """
        try:
            response = self.dynamodb.scan(
                TableName=self.table_name,
                FilterExpression='id BETWEEN :start_id AND :end_id',
                ExpressionAttributeValues={
                    ':start_id': {'N': str(offset + 1)},
                    ':end_id': {'N': str(offset + width)}
                }
            )
            sorted_items = sorted(response['Items'], key=lambda x: int(x['id']['N']))
            return [binascii.unhexlify(item['hash_hex']['S']) for item in sorted_items]
        except Exception as e:
            raise ResponseDynamoDBException(f"Failed to get leaves: {e}")
    
    def _get_leaves_hex(self, offset, width):
        """
        Returns in respective order the hashes stored by the leaves in the
        specified range.

        :param offset: starting position counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        """
        try:
            response = self.dynamodb.scan(
                TableName=self.table_name,
                FilterExpression='id BETWEEN :start_id AND :end_id',
                ExpressionAttributeValues={
                    ':start_id': {'N': str(offset + 1)},
                    ':end_id': {'N': str(offset + width)}
                }
            )
            return [item['hash_hex']['S'] for item in response['Items']]
        except Exception as e:
            raise ResponseDynamoDBException(f"Failed to get leaves hex: {e}")

    def _get_size(self):
        """
        :returns: current number of leaves
        :rtype: int
        """
        try:
            response = self.dynamodb.scan(
                
                TableName=self.table_name,
                Select='COUNT'
            )
            return response['Count']
        except Exception as e:
            raise ResponseDynamoDBException(f"Failed to get size: {e}")

    def get_entry(self, index: int):
        """
        Returns the unhashed data stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        try:
            response = self.dynamodb.get_item(
                TableName=self.table_name,
                Key={'id': {'N': str(index)}}
            )
            return response['Item']['entry']['S']
        except Exception as e:
            raise ResponseDynamoDBException(f"Failed to get entry: {e}")

    def append_entries(self, entries, chunksize=100_000):
        """
        Bulk operation for appending a batch of entries.

        :param entries: data entries to append
        :type entries: iterable of bytes
        :param chunksize: [optional] number entries to insert per
            database transaction.
        :type chunksize: int
        :returns: index of last appended entry
        :rtype: int
        """
        try:
            last_id = self._get_size()
            for chunk in self._hash_per_chunk(entries, chunksize):
                with self.dynamodb.batch_writer() as batch:
                    for (data, digest, hash_hex) in chunk:
                        last_id += 1
                        batch.put_item(
                            Item={
                                'id': {'N': str(last_id)},
                                'entry': {'B': data},
                                'hash_bytes': {'B': digest},
                                'hash_hex': {'S': hash_hex}
                            }
                        )
            return last_id
        except Exception as e:
            raise ResponseDynamoDBException(f"Failed to append entries: {e}")

    def update_item_by_index(self, index: int, update_data: dict) -> bool:
        """
        Updates an item in the DynamoDB table where the index is equal to the provided value.

        :param index: The index of the item to update
        :type index: int
        :param update_data: A dictionary of the attributes to update
        :type update_data: dict
        :return: True if the update was successful, False otherwise
        :rtype: bool
        """
        try:
            update_expression = "SET " + ", ".join(f"{k} = :{k}" for k in update_data.keys())
            expression_attribute_values = {f":{k}": {'S': json.dumps(v) if isinstance(v, dict) else v} for k, v in update_data.items()}

            self.dynamodb.update_item(
                TableName=self.table_name,
                Key={'id': {'N': str(index)}},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_attribute_values
            )
            return True
        except Exception as e:
            print(f"Failed to update item: {e}")
            return False

    def get_index_by_digest_hex(self, digest_hex: str) -> None | int:
        """
        Returns the index (id) where the hash_hex is equal to the provided digest_hex.

        :param digest_hex: The hexadecimal digest to search for
        :type digest_hex: str
        :return: The index (id) if found, None otherwise
        :rtype: int or None
        """
        try:
            # Scan for the item with matching hash_hex
            response = self.dynamodb.scan(
                TableName=self.table_name,
                FilterExpression="hash_hex = :digest_hex",
                ExpressionAttributeValues={":digest_hex": {'S': digest_hex}}
            )

            # Check if any items were found
            items = response.get('Items', [])
            if not items:
                return None

            # Return the id (assuming it's unique)
            return int(items[0]['id']['N'])

        except Exception as e:
            print(f"Failed to retrieve index by digest: {e}")
            return None