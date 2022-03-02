# Keycloak Example

- Sling Instance: http://localhost:9080/ (Sling '12' snapshot)
- Keycloak Docker: http://localhost:7070/ (Keycloak 17.0)
- see also
  - https://github.com/apache/sling-org-apache-sling-auth-saml2

# local test setup

## Apache Sling

### config.local (/libs/composum/platform/config.local)

org.apache.sling.auth.saml2.AuthenticationHandlerSAML2~keycloak.cfg.json
```json
{
  "path": "/",
  "service.ranking:Integer": 300,
  "entityID": "http://localhost:9080/",
  "acsPath": "/auth/saml",
  "saml2userIDAttr": "urn:oid:1.2.840.113549.1.9.1",
  "saml2userHome": "/home/users/external{/domain/}",
  "saml2groupMembershipAttr": "group",
  "syncGroups": [
    "composum-platform-external"
  ],
  "syncAttrs": [
    "urn:oid:1.2.840.113549.1.9.1=./profile/email",
    "urn:oid:2.5.4.42=./profile/givenName",
    "urn:oid:2.5.4.4=./profile/familyName"
  ],
  "saml2SessionAttr": "saml2AuthInfo",
  "saml2IDPDestination": "http://localhost:7070/realms/local/protocol/saml",
  "saml2LogoutURL": "http://localhost:7070/realms/local/protocol/saml",
  "saml2SPEnabled": true,
  "saml2SPEncryptAndSign": false,
  "jksFileLocation": "",
  "jksStorePassword": "",
  "idpCertAlias": "",
  "spKeysAlias": "",
  "spKeysPassword": ""
}
```

### Users & ACLs

<details>
  <summary>Click to expand!</summary>

#### SetupHook

system users
- system/composum/platform/composum-platform-slingsaml

groups
- composum/platform/composum-platform-external
- composum/platform/composum-platform-user
  - members:
    - composum-platform-external

setup scripts
- /conf/composum/platform/slingsaml/acl/service.json
- /conf/composum/platform/slingsaml/acl/external.json

#### config (/libs/composum/platform/config)

org.apache.sling.serviceusermapping.impl.ServiceUserMapperImpl.amended-slingsaml.cfg.json
```json
{
  "service.ranking:Integer": 1000,
  "user.mapping": [
    "org.apache.sling.auth.saml2:Saml2UserMgtService=[composum-platform-slingsaml]"
  ]
}
```
#### /conf/composum/platform/slingsaml/acl

service.json
```json
[
  {
    "path": [
      "/"
    ],
    "acl": {
      "principal": "composum-platform-slingsaml",
      "rule": {
        "grant": "jcr:read",
        "restrictions": {
          "rep:glob": ""
        }
      }
    }
  },
  {
    "path": [
      "/home"
    ],
    "acl": {
      "principal": "composum-platform-slingsaml",
      "rule": {
        "grant": "jcr:all"
      }
    }
  }
]
```

external.json
```json
[
  {
    "path": [
      "/",
      "/var",
      "/var/composum"
    ],
    "jcr:primaryType": "sling:Folder",
    "acl": {
      "principal": "composum-platform-user",
      "rule": {
        "grant": "jcr:read",
        "restrictions": {
          "rep:glob": ""
        }
      }
    }
  },
  {
    "path": [
      "/apps",
      "/libs",
      "/var/composum/clientlibs"
    ],
    "jcr:primaryType": "sling:Folder",
    "acl": {
      "principal": "composum-platform-user",
      "rule": {
        "grant": "jcr:read"
      }
    }
  }
]
```

</details>

## Keycloak

### Users

Create users as you want for testing and assign a group 'composum-platform-external' to the users
to ensure that these users have access to the Sling repository content. This group is mapped during
user synchronisation.

### Client 'local'

exported configuration excerpt

```json
{
  "clientId": "http://localhost:9080/",
  "name": "Local",
  "rootUrl": "",
  "adminUrl": "http://localhost:7070/realms/local/protocol/saml",
  "baseUrl": "http://localhost:9080/",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "redirectUris": [
    "http://localhost:9080/*"
  ],
  "consentRequired": false,
  "frontchannelLogout": false,
  "protocol": "saml",
  "attributes": {
    "saml_single_logout_service_url_redirect": "http://localhost:9080/auth/saml/loggedout",
    "saml.authnstatement": "false",
    "display.on.consent.screen": "false",
    "saml_name_id_format": "email"
  },
  "fullScopeAllowed": true,
  "defaultClientScopes": [
    "email-saml",
    "groups",
    "properties"
  ],
  "optionalClientScopes": []
}
```

download: [exported client configuration](./src/test/config/keycloak/client/local/http___localhost_9080_.json)

### Client Scopes

('Assigned Defaul Client Scopes' in the client configuration)

- email-saml
- groups
- properties

<details>
  <summary>Click to expand!</summary>

#### email-saml

- Name: 'email-saml'
- Protocol: saml
- consent: off

mappers

- X500 email / AttributeStatement Mapper / User Property
    - Protocol: saml
    - Name: 'X500 email'
    - Mapper Type: User Property
    - Property: 'email'
    - Friendly Name: 'email'
    - SAML Attribute Name: 'urn:oid:1.2.840.113549.1.9.1'

#### groups

- Name: 'groups'
- Protocol: saml
- consent: 'off'

mappers

- groups / Group Mapper / Group List
    - Protocol: saml
    - Name: 'groups'
    - Mapper Type: Group list
    - Property: 'group'
    - Friendly Name: 'Group Member'
    - Single Group Attribute: off
    - Full group path: off

#### properties

- Name: 'properties'
- Protocol: saml
- consent: 'off'

mappers

- X500 givenName / AttributeStatement Mapper / User Property
    - Protocol: saml
    - Name: 'X500 givenName'
    - Mapper Type: User Property
    - Property: 'firstName'
    - Friendly Name: 'givenName'
    - SAML Attribute Name: 'urn:oid:2.5.4.42'
- X500 surname / AttributeStatement Mapper / User Property
    - Protocol: saml
    - Name: 'X500 surname'
    - Mapper Type: User Property
    - Property: 'lastName'
    - Friendly Name: 'surname'
    - SAML Attribute Name: 'urn:oid:2.5.4.4'

</details>
