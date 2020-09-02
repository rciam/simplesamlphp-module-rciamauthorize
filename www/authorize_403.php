<?php
/**
 * Show a 403 Forbidden page about not authorized to access an application.
 *
 * @package SimpleSAMLphp
 */

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SimpleSAML_Error_BadRequest('Missing required StateId query parameter.');
}
$state = SimpleSAML_Auth_State::loadState($_REQUEST['StateId'], 'rciamauthorize:Authorize');

$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, 'rciamauthorize:authorize_403.php');
if (isset($state['Source']['auth'])) {
    $authSource = $state['Source']['auth'];
} else if (isset($state['SimpleSAML_Auth_Source.id'])) {
    $authSource = $state['SimpleSAML_Auth_Source.id'];
}
if (isset($authSource)) {
    $t->data['logoutURL'] = SimpleSAML_Module::getModuleURL(
        'core/authenticate.php',
        array('as' => $authSource)
    )."&logout";
}
if (isset($state['authprocAuthorize_reject_msg'])) {
    $t->data['reject_msg'] = $state['authprocAuthorize_reject_msg'];
}
if (isset($state['authprocAuthorize_logo_url'])) {
    $t->data['logoURL'] = $state['authprocAuthorize_logo_url'];
}
header('HTTP/1.0 403 Forbidden');
$t->show();
