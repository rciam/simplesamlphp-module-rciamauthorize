# simplesamlphp-module-rciamauthorize
SimpleSAMLphp module for managing user authorisation based on attribute matching

## Authorize
Filter that provides a user authorization filter based on attribute matching for those applications that do not cleanly separate authentication from authorization and set some default permissions for authenticated users.
There are three configuration options that can be defined: deny , regex , and rejectMsg All other filter configuration options are considered attribute matching rules.
Unauthorized users will be shown a 403 Forbidden page.

```php
'authproc' => [
    ...
    60 => array[
        'class' => 'rciamauthorize:Authorize',
        'regex' => false,
        'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => 'urn:mace:example.org:group:vo.example.org:role=member#foo.example.org',
        'rejectMsg' => [
            'en' => '<p>This service is only available to members of the <EXAMPLE> Virtual Organisation (<tt>vo.example.org</tt>).</p><p>Click <a href="<VO_REGISTRATION_URL>">HERE</a> to request membership.</p><p>Please, refer to <a href="<VO_INFO_PAGE>"><VO_INFO_PAGE></a> for more information.</p>',
        ],
    ]
]
```

## OIDCAuthorize
Filter that is similar to `Authorize` but is specific for OIDC clients.

```php
'authproc' => [
    ... 
    100 => [
        'class' => 'rciamauthorize:OIDCAuthorize',
        'keycloakSp' => 'https://www.example.org/keycloaksp',
        'clients' => [
            'client_id' => [
                'regex' => false,
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => 'urn:mace:example.org:group:vo.example.org:role=member#foo.example.org',
                'rejectMsg' => [
                    'en' => '<p>This service is only available to members of the <EXAMPLE> Virtual Organisation (<tt>vo.example.org</tt>).</p><p>Click <a href="<VO_REGISTRATION_URL>">HERE</a> to request membership.</p><p>Please, refer to <a href="<VO_INFO_PAGE>"><VO_INFO_PAGE></a> for more information.</p>',
                ],
                'logoUrl' => '<LOGO_URL>',
            ],
        ],
    ],
```

## Compatibility matrix

This table matches the module version with the supported SimpleSAMLphp version.

| Module |  SimpleSAMLphp |
|:------:|:--------------:|
| v1.x   | v1.14          |
| v2.x   | v1.17+         |

## License

Licensed under the Apache 2.0 license, for details see `LICENSE`.
