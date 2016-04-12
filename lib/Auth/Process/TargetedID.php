<?php

/**
 * Filter to generate the eduPersonTargetedID attribute.
 *
 * Based on core:TargetedID, by Olav Morken, UNINETT AS.
 *
 * This filter generates one or more values for the eduPersonTargetedID attribute, using:
 *
 * - an attribute identifying the authenticated user
 * - (optionally) a value identifying the SP requesting authentication
 * - (optionally) a value identifying the IdP
 * - (optionally) a fixed random value for salting the result
 * - a hash algorithm
 *
 * Configuration allows:
 *
 * - set alternative attributes (in order of preference) to identify the user
 * - set alternative attributes (in order of preference) to identify the target
 * - set alternative attributes (in order of preference) to identify the IdP
 * - transform the target identifier
 * - filter SP and/or users (send a value only for matching entities)
 *
 * Read the docs to see all the options.
 *
 * @author Miguel Macías, UPV
 * @package SimpleSAMLphp
 */
class sspmod_hubandspoke_Auth_Process_TargetedID extends SimpleSAML_Auth_ProcessingFilter {


	/**
	 * Default values for every switch configuring the attribute
	 */
	private $defaults = array(
		'userID' => 'UserID',
		'ifUser' => NULL,
		'targetID' => array('saml:RequesterID', 'core:SP'),
		'targetTransform' => NULL,
		'ifTarget' => NULL,
		'sourceID' => array('Attributes/schacHomeOrganization', 'core:IdP'),
		'salt' => NULL,
		'hashFunction' => 'sha256',
		'fields' => array('salt', 'userID', 'targetID', 'sourceID', 'salt'),
		'fieldSeparator' => '@@',
		'prefix' => NULL,
		'nameId' => false
	);


	/**
	 * Configuration for the values to be generated
	 */
	private $confValues = array();


	/**
	 * Initialize this filter.
	 *
	 * @param array $config  Configuration information about this filter.
	 * @param mixed $reserved  For future use.
	 */
	public function __construct($config, $reserved) {
		parent::__construct($config, $reserved);

		assert('is_array($config)');

		// the 'values' array sets configuration for each value of the attribute
		if (!array_key_exists('values', $config))
			$config['values']= array('default' => array());

		foreach ($config['values'] as $name => $parameters) {
			// order of preference: (hard-coded) defaults, first level configuration, specific configuration
			// if a parameter is missing -> use the same parameter configured at a higher level
			// to 'remove' a parameter -> specify an empty value (NULL, array(), '') to disable
			$this->confValues[$name]= array_merge($this->defaults, $config, $parameters);
			// checking hash algorithm is valid
			$hashAlg= $this->confValues[$name]['hashFunction'];
			if (!empty($hashAlg) && !in_array($hashAlg, hash_algos()))
				throw new Exception('eduPersonTargetedId: hash algorithm (' . $hashAlg . ') not supported');
		}
	}


	/**
	 * Apply filter to add the targeted ID.
	 *
	 * @param array &$state  The current state.
	 */
	public function process(&$state) {
		assert('is_array($state)');
		assert('array_key_exists("Attributes", $state)');

		$state['Attributes']['eduPersonTargetedID'] = array();
		foreach ($this->confValues as $name => $parameters) {
			$dataRetrieved= array();

			// get the identifier of the authenticated user (mandatory)
			$data= (empty($parameters['userID']))?
				'':
				self::getValue ($state, (array) $parameters['userID'], 'eduPersonTargetedId: not user id found');
			// check that user is not filtered out for this value of the attribute
			if (!empty($parameters['ifUser']) && !self::someMatch($data, (array) $parameters['ifUser'])) {
				SimpleSAML_Logger::debug('eduPersonTargetedId, ' . $name . ' skipped: userID = ' . $data);
				continue;
			}
			$dataRetrieved['userID']= $data;

			// get the identifier of the destination (optional)
			$data= (empty($parameters['targetID']))?
				'':
				self::getValue ($state, (array) $parameters['targetID'], NULL);
			// transform, if needed, the identifier
			if (is_array($parameters['targetTransform'])) {
				foreach($parameters['targetTransform'] as $pattern => $replacement)
					$data= preg_replace($pattern, $replacement, $data);
			}
			// check that destination is not filtered out for this value of the attribute
			if (!empty($parameters['ifTarget']) && !self::someMatch($data, (array) $parameters['ifTarget'])) {
				SimpleSAML_Logger::debug('eduPersonTargetedId, ' . $name . ' skipped: targetID = ' . $data);
				continue;
			}
			$dataRetrieved['targetID']= $data;

			// get the identifier of the source (optional)
			$data= (empty($parameters['sourceID']))?
				'':
				self::getValue ($state, (array) $parameters['sourceID'], NULL);
			$dataRetrieved['sourceID']= $data;

			// get a salt for obfuscating the hash
			$data= (empty($parameters['salt']))?
				'':
				$parameters['salt'];
			$dataRetrieved['salt']= $data;

			// generate the value applying the hash function
			$dataRaw= array();
			foreach((array) $parameters['fields'] as $field) {
				$data= $dataRetrieved[$field];
				if (!empty($data))
					$dataRaw[]= $data;
			}
			$dataRaw= implode($parameters['fieldSeparator'], $dataRaw);
			$eduPersonTargetedId= hash($parameters['hashFunction'], $dataRaw);

			// set a prefix, if needed
			if (!empty($parameters['prefix']))
				$eduPersonTargetedId= $parameters['prefix'] . $eduPersonTargetedId;

			// log
			SimpleSAML_Logger::debug('eduPersonTargetedId, ' . $name . ' function: ' . $parameters['hashFunction'] . '(' . $dataRaw . ')');
			SimpleSAML_Logger::debug('eduPersonTargetedId, ' . $name . ' value: ' . $eduPersonTargetedId);

			// Convert to a name identifier element
			if ($parameters['nameId'])
				$eduPersonTargetedId= self::toNameId($eduPersonTargetedId, $dataRetrieved['sourceID'], $dataRetrieved['targetID']);

			// add the attribute
			$state['Attributes']['eduPersonTargetedID'][]= $eduPersonTargetedId;
		}
	}

	/**
	 * Get a value from a set of alternative options (in order of preference)
	 *
	 * @param array &$state  The current state.
	 * @param array $options  The list of options to retrieve the value.
	 * @param string $error  Message if not found.
	 * @return string  The value obtained
	 */
	private static function getValue(&$state, $options, $error) {
            assert('is_array($options)');

            $value= '';
            foreach($options as $attributeName) {
		// separe with / for enter next level
		// example: Attributes/uid => $state['Attributes']['uid']
                list($level1, $level2)= explode('/', $attributeName . '/');
                if (array_key_exists($level1, $state)) {
                    $data= $state[$level1];
                    if (!empty($level2)) {
                        if (is_array($data) && array_key_exists($level2, $data))
                            $data= $data[$level2];
                        else
                            $data= null;
                    }
                    if (!empty($data)) {
			$data= (array) $data;	// if value is string => insert into a new array
                        $value= $data[0];	// first value selected
                        break;
                    }
                }
            }
            if (empty($value) && !empty($error))
                throw new Exception($error);

            return $value;
	}

	/**
	 * Check that a string matches one (or more) of a list of regular expressions
	 *
	 * @param string $value  The string to check.
	 * @param string $listRegExp  Array with all the regular expressions to check.
	 * @return boolean  True if there is at least one regular expression matching the string
	 */
	private static function someMatch($value, $listRegExp) {
            assert('is_array($listRegExp)');

	    foreach($listRegExp as $regExp) {
		if (preg_match($regExp, $value)) {
		    return true;
		}
	    }

	    return false;
	}

	/**
	 * Convert the targeted ID to a SAML 2.0 name identifier element
	 *
	 * @param string $value  The value of the attribute.
	 * @param string $source  Identifier of the IdP.
	 * @param string $destination  Identifier of the SP.
	 * @return string  The XML representing the element
	 */
	private static function toNameId($value, $source, $destination) {
            $nameId = array(
                'Format' => SAML2_Const::NAMEID_PERSISTENT,
                'Value' => $value,
            );

            if (!empty($source)) {
                $nameId['NameQualifier'] = $source;
            }
            if (!empty($destination)) {
                $nameId['SPNameQualifier'] = $destination;
            }

            $doc = SAML2_DOMDocumentFactory::create();
            $root = $doc->createElement('root');
            $doc->appendChild($root);

            SAML2_Utils::addNameId($root, $nameId);

            return $doc->saveXML($root->firstChild);
	}

}
