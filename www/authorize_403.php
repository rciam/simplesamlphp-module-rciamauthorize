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
$t = new SimpleSAML_XHTML_Template($globalConfig, 'rciamauthorize:rciamauthorize_403.php');
if (isset($state['Source']['auth'])) {
    $t->data['logoutURL'] = SimpleSAML_Module::getModuleURL(
        'core/authenticate.php',
        array('as' => $state['Source']['auth'])
    )."&logout";
}
if (isset($state['authprocAuthorize_reject_msg'])) {
    $t->data['reject_msg'] = $state['authprocAuthorize_reject_msg'];
}
header('HTTP/1.0 403 Forbidden');
$t->show();
