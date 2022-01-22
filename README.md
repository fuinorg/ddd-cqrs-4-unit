# ddd-cqrs-4-unit
Unit test utilities for [ddd-4-java](https://github.com/fuinorg/ddd-4-java) and [cqrs-4-java](https://github.com/fuinorg/cqrs-4-java) based projects.

[![Build Status](https://github.com/fuinorg/ddd-cqrs-unit/actions/workflows/maven.yml/badge.svg)](https://github.com/fuinorg/ddd-cqrs-unit/actions/workflows/maven.yml)
[![Coverage Status](https://sonarcloud.io/api/project_badges/measure?project=ddd-cqrs-unit&metric=coverage)](https://sonarcloud.io/dashboard?id=ddd-cqrs-unit)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.fuin/ddd-cqrs-unit/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.fuin/ddd-cqrs-unit/)
[![LGPLv3 License](http://img.shields.io/badge/license-LGPLv3-blue.svg)](https://www.gnu.org/licenses/lgpl.html)
[![Java Development Kit 11](https://img.shields.io/badge/JDK-11-green.svg)](https://openjdk.java.net/projects/jdk/11/)

## In-memory Crypto Service
The [InMemoryCryptoService](src/main/java/org/fuin/dddcqrsunit/InMemoryCryptoService.java) can be used for simple in-memory tests.

## Vault Crypto Service
The [VaultCryptoService](src/main/java/org/fuin/dddcqrsunit/VaultCryptoService.java) can be used for unit tests with the HashiCorp Vault [Transit Secrets Engine](https://www.vaultproject.io/docs/secrets/transit).
