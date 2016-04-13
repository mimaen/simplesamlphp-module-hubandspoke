#Hub & Spoke utilities for SimpleSAMLphp

##TargetedID

A flexible way for generate one or more values for the [eduPersonTargetedId attribute](http://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonTargetedID).

**hubandspoke:TargetedID** is an [Authentication Processing Filter](https://simplesamlphp.org/docs/stable/simplesamlphp-authproc) for SimpleSAMLphp, based on [core:TargetedID](https://simplesamlphp.org/docs/stable/core:authproc_targetedid) by Olav Morken, UNINETT AS.

This filter generates one or more values for the **eduPersonTargetedID** attribute, using:

* an attribute identifying the authenticated **user**
* (optionally) a value identifying the **SP** requesting authentication
* (optionally) a value identifying the **IdP**
* (optionally) a fixed random value for **salting** the result
* a **hash** algorithm

Configuration allows:

* set alternative attributes (in order of preference) to identify the user
* set alternative attributes (in order of preference) to identify the target
* set alternative attributes (in order of preference) to identify the IdP
* transform the target identifier
* filter SP and/or users (send a value only for matching entities)

Read the docs to see all the options.

###Configuration samples

* eduPersonTargetedId with one unique **standard** value:
```php
    'authproc' => array(
        50 => 'hubandspoke:TargetedID',
    ),
```
    sha256(userID + '@@' + targetID + '@@' + sourceID)

* eduPersonTargetedId obfuscated with a **salt**:
```php
    'authproc' => array(
        50 => array(
            'class' => 'hubandspoke:TargetedID',
            'salt'  => 'randomString',
        ),
    ),
```
    sha256(salt + '@@' + userID + '@@' + targetID + '@@' + sourceID + '@@' + salt)

* eduPersonTargetedId with a different **formula**:
```php
    'authproc' => array(
        50 => array(
            'class'  => 'hubandspoke:TargetedID',
            'userID' => 'Attributes/mail',
            'fields' => array('salt', 'userID', 'targetID'),
            'salt'   => 'randomString',
        ),
    ),
```
    sha256(salt + '@@' + mail + '@@' + targetID)

* eduPersonTargetedId with **two** values:
```php
    'authproc' => array(
        50 => array(
            'class'  => 'hubandspoke:TargetedID',
            'salt'   => 'randomString',
            'values' => array(
                'new' => array(
                    'fieldSeparator' => '//',
                ),
                'old' => array(
                    'hashFunction' => 'md5',
                    'fields'       => array('userID'),
                ),
            ),
        ),
    ),
```
    sha256(salt + '//' + userID + '//' + targetID + '//' + sourceID + '//' + salt)
    md5(userID)

* eduPersonTargetedId with two values **prefixed**:
  * one of them only for a specific SP (http://*.example.com)
  * the other one for all SP, but considering the same SP all URL https://*.blogs.example.com (same eduPersonTargetedId)
```php
    'authproc' => array(
        50 => array(
            'class'  => 'hubandspoke:TargetedID',
            'salt'   => 'randomString',
            'values' => array(
                'new' => array(
                    'prefix'          => '{new}',
                    'targetTransform' => array(
                        '#^(https?://)[^./]+\.(blogs\.example\.com/?).*$#' => '$1$2',
                    ),
                ),
                'old' => array(
                    'prefix'       => '{old}',
                    'hashFunction' => 'md5',
                    'userID'       => array('Attributes/mail', 'UserID'),
                    'fields'       => 'userID',
                    'ifTarget'     => '#^https?://([^./]+\.)*example\.com(/|$)#',
                ),
            ),
        ),
    ),
```
    '{new}' + sha256(salt + '@@' + userID + '@@' + targetID* + '@@' + sourceID + '@@' + salt)
    '{old}' + md5(userID) 						  only for *.example.com
