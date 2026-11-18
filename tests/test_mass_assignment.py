from security.mass_assignment import (
    filter_payload,
    is_sensitive_field,
    apply_patch,
    validate_fields,
    allowed_fields
)


def test_allowed():
    assert allowed_fields() == {'name', 'email'}

def test_admin():
    assert is_sensitive_field('is_admin') is True

def test_role():
    assert is_sensitive_field('role') is True

def test_filter():
    assert filter_payload({'name': 'a', 'is_admin': True}) == {'name': 'a'}

def test_nested():
    assert filter_payload({'profile': {'name': 'a', 'role': 'admin'}}) == {'profile': {'name': 'a'}}

def test_underscore():
    assert filter_payload({'_internal': 1}) == {}

def test_patch():
    assert apply_patch({'name': 'a'}, {'is_admin': True}) == {'name': 'a'}

def test_unknown():
    assert validate_fields({'debug': 1}) is False

def test_case():
    assert is_sensitive_field('IsAdmin') is True

def test_array():
    assert validate_fields({'role[]': ['admin']}) is False

def test_tenant():
    assert filter_payload({'tenant': 't2'}) == {}

def test_safe():
    assert validate_fields({'name': 'a', 'email': 'x'}) is True

def test_empty():
    assert filter_payload({}) == {}

def test_assoc():
    assert apply_patch({'name': 'a'}, {'profile': {'role': 'admin'}}) == {'name': 'a', 'profile': {}}

def test_response():
    assert filter_payload({'name': 'a', 'password': 'x'}) == {'name': 'a'}
