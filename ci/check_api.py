"""Offline P01 contract checks; optional official-schema/example validation.

The default uses only the standard library. --full-schema also requires jsonschema
in the caller's verification environment; it never downloads or installs anything.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'docs/api/openapi-v1.json'
INTENT_FIELDS = ('id actor_id planning_job_id kind store_instance_id config_revision '
                 'core_plan_id core_plan_digest created_unix_ms expires_unix_ms confirmation').split()


def resolve(document, reference):
    assert reference.startswith('#/'), reference
    value = document
    for part in reference[2:].split('/'):
        value = value[part.replace('~1', '/').replace('~0', '~')]
    return value


def check(document):
    assert document['openapi'] == '3.1.2'
    assert document['security'] == [{'bearerToken': []}, {'sessionCookie': []}]
    schemas = document['components']['schemas']
    permissions = set(schemas['Permission']['enum']) | {'session.exchange'}
    count = 0
    operation_ids = set()

    def walk(value):
        if isinstance(value, dict):
            if '$ref' in value:
                resolve(document, value['$ref'])
            if value.get('type') == 'object':
                assert value.get('additionalProperties') is False, value
                assert set(value.get('required', [])) <= set(value['properties'])
            if isinstance(value.get('kind'), str) and value['kind'] in ('restore', 'retention') and all(k in value for k in INTENT_FIELDS):
                payload = {k: value[k] for k in INTENT_FIELDS}
                encoded = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
                assert value['digest'] == hashlib.sha256(b'backupctl-api-intent-v1\0' + encoded).hexdigest()
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    for path, item in document['paths'].items():
        assert path.startswith('/api/v1/')
        for method, operation in item.items():
            if method == 'parameters':
                continue
            assert method in ('get', 'post', 'delete')
            name = operation['operationId']
            assert name not in operation_ids
            operation_ids.add(name)
            assert operation['x-permission'] in permissions
            assert operation.get('security', document['security']) or name == 'createSession'
            assert {'400', '401', '403', '404', '429', '500', '503'} <= operation['responses'].keys()
            parameters = [resolve(document, p['$ref']) if '$ref' in p else p
                          for p in item.get('parameters', []) + operation.get('parameters', [])]
            assert set(re.findall(r'\{([^}]+)\}', path)) == {
                p['name'] for p in parameters if p['in'] == 'path' and p.get('required')}
            if operation.get('x-durable-job') or operation.get('x-idempotent-cancellation'):
                assert any(p['name'] == 'Idempotency-Key' and p.get('required') for p in parameters)
                assert '409' in operation['responses']
            if operation.get('x-durable-job'):
                assert {'200', '202'} <= operation['responses'].keys()
                assert {'Location', 'Retry-After'} <= operation['responses']['202']['headers'].keys()
                assert operation['responses']['202']['content']['application/json']['schema'] == {
                    '$ref': '#/components/schemas/JobResponse'}
            if method == 'post':
                body = operation['requestBody']
                assert body['required']
                resolve(document, body['content']['application/json']['schema']['$ref'])
                assert 'example' in body['content']['application/json']
            count += 1
    assert count == 20 and len(operation_ids) == 20
    return count


def structural_negative_controls(document):
    changes = [
        lambda s: s['components']['schemas']['BackupRequest'].update(additionalProperties=True),
        lambda s: s['paths']['/api/v1/backups']['post'].update(security=[]),
        lambda s: s['paths']['/api/v1/backups']['post']['parameters'].pop(),
        lambda s: s['components']['schemas']['ArtifactRequest']['properties'].update(
            artifact_id={'$ref': '#/components/schemas/Missing'}),
    ]
    for change in changes:
        candidate = copy.deepcopy(document)
        change(candidate)
        try:
            check(candidate)
        except (AssertionError, KeyError):
            continue
        raise AssertionError('Invalid contract passed a negative control')


def full_check(document, schema_path):
    from jsonschema import Draft202012Validator, FormatChecker

    official = json.loads(schema_path.read_text())
    assert official['$id'] == 'https://spec.openapis.org/oas/3.1/schema/2025-09-15'
    Draft202012Validator(official).validate(document)
    schemas = document['components']['schemas']

    def validator(name):
        schema = schemas[name]
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(dict(schema, components=document['components']),
                                    format_checker=FormatChecker())

    examples = 0
    for name, schema in schemas.items():
        for example in schema.get('examples', []):
            validator(name).validate(example)
            examples += 1
    for item in document['paths'].values():
        for operation in item.values():
            if not isinstance(operation, dict) or 'requestBody' not in operation:
                continue
            media = operation['requestBody']['content']['application/json']
            validator(media['schema']['$ref'].rsplit('/', 1)[1]).validate(media['example'])
            examples += 1
    invalid = [
        ('BackupRequest', {'profile_id': None, 'confirm_synthetic': False}),
        ('BackupRequest', {'profile_id': None, 'confirm_synthetic': True, 'config_path': '/tmp/other'}),
        ('VerificationRequest', {'artifact_id': 'not-a-uuid', 'level': 'archive'}),
        ('VerificationRequest', {'artifact_id': schemas['ArtifactRequest']['examples'][0]['artifact_id'], 'level': 'full'}),
        ('RestorePlanRequest', dict(schemas['RestorePlanRequest']['examples'][0], security='dr_full', sections='pre_data')),
        ('RestoreRequest', dict(schemas['RestoreRequest']['examples'][0], confirm_digest='wrong')),
        ('RestoreRequest', dict(schemas['RestoreRequest']['examples'][0], confirm_target='production_database')),
        ('RetentionPreviewRequest', {'operation': 'prune', 'profile_id': None, 'keep_last': 0}),
        ('RetentionPreviewRequest', {'operation': 'delete', 'artifact_id': schemas['ArtifactRequest']['examples'][0]['artifact_id'], 'keep_last': 2}),
        ('ProtectionRequest', dict(schemas['ProtectionRequest']['examples'][0], reason='')),
        ('Job', dict(schemas['Job']['examples'][0], core_job_id='invented')),
        ('Job', dict(schemas['Job']['examples'][0], created_unix_ms=9007199254740992)),
        ('Job', dict(schemas['Job']['examples'][0], state='succeeded')),
        ('Job', dict(schemas['Job']['examples'][0], state='running', result=schemas['RestoreResult']['examples'][0])),
    ]
    for name, value in invalid:
        assert not validator(name).is_valid(value), (name, value)
    print(f'Official OpenAPI schema, {examples} positive examples and {len(invalid)} negative examples pass')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-schema', type=Path)
    args = parser.parse_args()
    document = json.loads(CONTRACT.read_text())
    count = check(document)
    structural_negative_controls(document)
    print(f'API contract: {count} operations, local refs/closed objects/permissions/receipts/digests and 4 negative controls pass')
    if args.full_schema:
        full_check(document, args.full_schema)


if __name__ == '__main__':
    main()
