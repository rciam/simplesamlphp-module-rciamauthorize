<?php

namespace SimpleSAML\Module\rciamauthorize\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Auth\State;
use SimpleSAML\Module;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Logger;

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
   *  Oidc issuer
   */

  protected $oidcIssuer;

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
    if (!empty($config['oidc_issuer'])) {
      $this->oidcIssuer = $config['oidc_issuer'];
      unset($config['oidc_issuer']);
    } else {
      throw new Exception('OIDC Authorize: oidc issuer cannot be empty.');
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
      if (isset($client_config['reject_msg']) && is_array($client_config['reject_msg'])) {
        $this->rejectMsg[$client_id] = $client_config['reject_msg'];
        unset($client_config['reject_msg']);
      }
      // Check for the logo_url option, get it and remove it
      // Must be a string
      if (isset($client_config['logo_url']) && is_string($client_config['logo_url'])) {
        $this->logoUrl = $client_config['logo_url'];
        unset($client_config['logo_url']);
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
    assert('array_key_exists("saml:RequesterID", $request)');

    if (empty($request['saml:RequesterID'][0])) {
      Logger::debug("[rciamauthorize:OIDCAuthorize] Ignoring request with missing saml:RequesterdID");
      return;
    }
    $client_id = str_replace($this->oidcIssuer, "", $request['saml:RequesterID'][0]);

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
        Logger::debug("[rciamauthorize:OIDCAuthorize] Rejecting Authorize for " . $client_id);
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
