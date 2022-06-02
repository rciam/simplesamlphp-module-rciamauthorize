<?php

namespace SimpleSAML\Module\rciamauthorize\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Auth\State;
use SimpleSAML\Module;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Logger;
use SimpleSAML\Error;

/**
 * Filter to authorize only certain users.
 * See docs directory.
 *
 * @author Ernesto Revilla, Yaco Sistemas SL., Ryan Panning
 * @package SimpleSAMLphp
 */
class OIDCAuthorize extends ProcessingFilter
{

  /**
   * Flag to deny/unauthorize the user a attribute filter IS found
   *
   * @var bool
   */
  protected $deny;

  /**
   * Flag to turn the REGEX pattern matching on or off
   *
   * @var bool
   */
  protected $regex;

  /**
   * Array of localised rejection messages
   *
   * @var array
   */
  protected $rejectMsg;

  /**
   * Logo URL
   *
   * @var string
   */
  protected $logoUrl;

  /**
   * Array of valid users. Each element is a regular expression. You should
   * use \ to escape special chars, like '.' etc.
   *
   */
  protected $validAttributeValues = [];

  /**
   *  Keycloak Sp
   */
  protected $keycloakSp;

  /**
   * Initialize this filter.
   * Validate configuration parameters.
   *
   * @param array $config  Configuration information about this filter.
   * @param mixed $reserved  For future use.
   */
  public function __construct($config, $reserved)
  {
    parent::__construct($config, $reserved);

    assert('is_array($config)');

    if (array_key_exists('keycloakSp', $config)) {
      if (!is_string($config['keycloakSp'])) {
        Logger::error(
          "[OIDCAuthorize] Configuration error: 'keycloakSp' not an string");
        throw new \Exception(
          "[OIDCAuthorize] configuration error: 'keycloakSp' not an string");
      }
      $this->keycloakSp = $config['keycloakSp'];
    }

    foreach ($config['clients'] as $client_id => $client_config) {
      // Check for the deny option, get it and remove it
      // Must be bool specifically, if not, it might be for a attrib filter below
      if (isset($client_config['deny']) && is_bool($client_config['deny'])) {
        $this->deny[$client_id] = $client_config['deny'];
        unset($client_config['deny']);
      } else {
        $this->deny[$client_id] = false;
      }

      // Check for the regex option, get it and remove it
      // Must be bool specifically, if not, it might be for a attrib filter below
      if (isset($client_config['regex']) && is_bool($client_config['regex'])) {
        $this->regex[$client_id] = $client_config['regex'];
        unset($client_config['regex']);
      }

      // Check for the rejectMsg option, get it and remove it
      // Must be array of languages
      if (isset($client_config['rejectMsg']) && is_array($client_config['rejectMsg'])) {
        $this->rejectMsg[$client_id] = $client_config['rejectMsg'];
        unset($client_config['rejectMsg']);
      }
      // Check for the logoUrl option, get it and remove it
      // Must be a string
      if (isset($client_config['logoUrl']) && is_string($client_config['logoUrl'])) {
        $this->logoUrl = $client_config['logoUrl'];
        unset($client_config['logoUrl']);
      }

      foreach ($client_config as $attribute => $values) {
        if (is_string($values)) {
          $values = [$values];
        }
        if (!is_array($values)) {
          throw new Exception(
            'Filter OIDC Authorize: Attribute values is neither string nor array: ' . var_export($attribute, true)
          );
        }
        foreach ($values as $value) {
          if (!is_string($value)) {
            throw new Exception(
              'Filter OIDC Authorize: Each value should be a string for attribute: '
                . var_export($attribute, true) . ' value: ' . var_export($value, true)
                . ' Config is: ' . var_export($config, true)
            );
          }
        }
        $this->validAttributeValues[$client_id][$attribute] = $values;
      }
    }
  }

  /**
   * Apply filter to validate attributes.
   *
   * @param array &$request  The current request
   */
  public function process(&$request)
  {
    assert('is_array($request)');

    $client_id = null;

    if (!empty($request['saml:RelayState']) 
      && !empty($this->keycloakSp) 
      && $request['Destination']['entityid'] == 
                $this->keycloakSp) {
      $client_id = explode('.', $request['saml:RelayState'], 3)[2];
      if(empty($client_id)) {
        throw new Error\Error(
            ['UNHANDLEDEXCEPTION', 'Could not extract client ID from saml:RelayState']
        );  
      }
    } else if(!empty($request['saml:RelayState'])) {
      $client_id = $request['saml:RelayState'];
    } else {
      throw new Error\Error(
          ['UNHANDLEDEXCEPTION', 'Request missing saml:RelayState']
      );
    }
    
    // Check if client_id exists in module configuration
    if (array_key_exists($client_id, $this->validAttributeValues)) {
      $authorize = $this->deny[$client_id];
      $attributes = &$request['Attributes'];
      foreach ($this->validAttributeValues[$client_id] as $name => $patterns) {
        if (array_key_exists($name, $attributes)) {
          foreach ($patterns as $pattern) {
            $values = $attributes[$name];
            if (!is_array($values)) {
              $values = [$values];
            }
            foreach ($values as $value) {
              if ($this->regex[$client_id]) {
                $matched = preg_match($pattern, $value);
              } else {
                $matched = ($value == $pattern);
              }
              if ($matched) {
                Logger::debug("[rciamauthorize:OIDCAuthorize] User's attribute value matched with a rule for the client " . $client_id);
                $authorize = ($this->deny[$client_id] ? false : true);
                break 3;
              }
            }
          }
        }
      }

      if (!$authorize) {
        Logger::info("[rciamauthorize:OIDCAuthorize] Access to client " . $client_id . " forbidden");
        // Store the rejection message array in the $request
        if (!empty($this->rejectMsg[$client_id])) {
          $request['authprocAuthorize_reject_msg'] = $this->rejectMsg[$client_id];
        }
        // Store the logo URL in the $request
        if (!empty($this->logoUrl[$client_id])) {
          $request['authprocAuthorize_logo_url'] = $this->logoUrl[$client_id];
        }
        $this->unauthorized($request);
      }
    } else {
      Logger::debug("[rciamauthorize:OIDCAuthorize] Ignoring client with id:" . $client_id);
    }
  }
  /**
   * When the process logic determines that the user is not
   * authorized for this service, then forward the user to
   * an 403 unauthorized page.
   *
   * Separated this code into its own method so that child
   * classes can override it and change the action. Forward
   * thinking in case a "chained" ACL is needed, more complex
   * permission logic.
   *
   * @param array $request
   */
  protected function unauthorized(&$request)
  {
    // Save state and redirect to 403 page
    $id = State::saveState($request, 'rciamauthorize:OIDCAuthorize');
    $url = Module::getModuleURL('rciamauthorize/oidc_authorize_403.php');
    HTTP::redirectTrustedURL($url, ['StateId' => $id]);
  }
}
