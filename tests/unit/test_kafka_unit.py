"""Kafka-Adapter ohne Broker: Validierung, Normalisierung, Privilegien-Regeln, Passwortvergleich."""

import pytest
from conftest import doc

from ordivus.adapters.base import Secret
from ordivus.adapters.kafka import KafkaAdapter, _privileged_acl

A = KafkaAdapter()
TARGET = {"bootstrapServers": ["k1:9093"], "username": "ordivus"}


def target(**spec):
    return {"kind": "Target", "metadata": {"name": "k"}, "spec": {**TARGET, **spec}}


def acl(**spec):
    base = {"principal": "User:app", "resourceType": "topic", "resourceName": "t", "operations": ["read"]}
    return doc("KafkaAcl", "a", **{**base, **spec})


def test_valid_target_and_example_shape():
    assert A.validate(target(securityProtocol="SASL_SSL", tls={"caFile": "/ca.pem"}, mechanism="SCRAM-SHA-256",
                             scram={"mechanism": "SCRAM-SHA-512", "iterations": 8192}, superUsers=["User:root"],
                             scope={"principals": {"include": ["User:app-*"]}})) == []


@pytest.mark.parametrize("spec, error", [
    ({"bootstrapServers": []}, "bootstrapServers"),
    ({"bootstrapServers": ["k1"]}, "host:port"),
    ({"bootstrapServers": ["user@k1:9093"]}, "host:port"),
    ({"bootstrapServers": ["k1:99999"]}, "host:port"),
    ({"securityProtocol": "PLAINTEXT"}, "securityProtocol"),
    ({"mechanism": "PLAIN"}, "spec.mechanism"),
    ({"username": "a b"}, "username"),
    ({"securityProtocol": "SASL_PLAINTEXT", "tls": {}}, "requires securityProtocol SASL_SSL"),
    ({"tls": {"verify": False}}, "spec.tls.verify"),
    ({"scram": {"iterations": 100}}, "iterations"),
    ({"scram": {"iterations": True}}, "iterations"),
    ({"superUsers": ["admin"]}, "superUsers"),
    ({"scope": {"topics": {}}}, "spec.scope.topics"),
    ({"scope": {"principals": {"include": "User:*"}}}, "spec.scope.principals"),
    ({"extra": 1}, "unknown field spec.extra"),
])
def test_invalid_target(spec, error):
    assert any(error in e for e in A.validate(target(**spec))), A.validate(target(**spec))


@pytest.mark.parametrize("spec, error", [
    ({"principal": "app"}, "principal"),
    ({"principal": "User:a b"}, "principal"),
    ({"resourceType": "BROKER"}, "resourceType"),
    ({"resourceType": "CLUSTER", "resourceName": "x"}, "kafka-cluster"),
    ({"resourceName": ""}, "resourceName"),
    ({"patternType": "MATCH"}, "patternType"),
    ({"patternType": "PREFIXED", "resourceName": "*"}, "LITERAL"),
    ({"permission": "MAYBE"}, "permission"),
    ({"operations": []}, "operations"),
    ({"operations": ["ANY"]}, "operations"),
    ({"host": "a/b"}, "host"),
    ({"user": "x"}, "unknown field spec.user"),
])
def test_invalid_acl(spec, error):
    assert any(error in e for e in A.validate(acl(**spec))), A.validate(acl(**spec))


@pytest.mark.parametrize("name", ["a b", "a,b", "a=b", "", "x" * 256, "User:x", "*"])
def test_invalid_user_names(name):
    assert A.validate(doc("KafkaUser", name)) != []


def test_user_name_override():
    d = {"kind": "KafkaUser", "metadata": {"name": "orders"}, "spec": {"name": "app.orders"}}
    assert A.validate(d) == [] and A.desired(d).id == "app.orders"


def test_acl_normalization_and_key():
    r = A.desired(acl(operations=["write", "READ", "read"], resourceType="Topic", patternType="prefixed"))
    assert r.attrs == {"principal": "User:app", "resourceType": "TOPIC", "resourceName": "t", "patternType": "PREFIXED",
                       "permission": "ALLOW", "host": "*", "operations": ["READ", "WRITE"]}
    assert r.id == '["User:app","TOPIC","PREFIXED","t","ALLOW","*"]'  # Operationen gehören nicht zum Schlüssel


@pytest.mark.parametrize("spec, privileged", [
    ({"resourceType": "CLUSTER", "resourceName": "kafka-cluster", "operations": ["DESCRIBE"]}, True),
    ({"operations": ["ALL"]}, True), ({"operations": ["ALTER"]}, True), ({"operations": ["ALTER_CONFIGS"]}, True),
    ({"operations": ["CLUSTER_ACTION"]}, True), ({"resourceName": "*", "operations": ["WRITE"]}, True),
    ({"resourceName": "*", "operations": ["DELETE"]}, True),
    ({"resourceType": "USER", "operations": ["DESCRIBE"]}, True),
    ({"principal": "User:root"}, True), ({"principal": "User:root", "permission": "DENY"}, True),
    ({"principal": "User:*", "permission": "DENY"}, True),
    ({"resourceName": "*", "operations": ["READ"]}, False), ({"operations": ["WRITE", "CREATE", "DELETE"]}, False),
    ({"operations": ["ALL"], "permission": "DENY"}, False), ({"principal": "User:*"}, False),
])
def test_privileged_rules(spec, privileged):
    attrs = A.desired(acl(**spec)).attrs
    assert (_privileged_acl(attrs, {"User:root"}) is not None) is privileged


def test_insecure_transport():
    assert A.insecure_transport({"securityProtocol": "SASL_PLAINTEXT"})
    assert not A.insecure_transport({}) and not A.insecure_transport({"securityProtocol": "SASL_SSL"})


def test_verify_password_detects_mechanism_mismatch_without_login():
    observed = A.desired(doc("KafkaUser", "u")).__class__("KafkaUser", "u", {"credentials": {"SCRAM-SHA-256": 4096}})
    assert A.verify_password(None, TARGET, observed, Secret("x")) is False
    observed = observed.__class__("KafkaUser", "u", {"credentials": {"SCRAM-SHA-512": 4096}})
    assert A.verify_password(None, {**TARGET, "scram": {"iterations": 8192}}, observed, Secret("x")) is False
