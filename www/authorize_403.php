<?php
/**
 * Show a 403 Forbidden page about not authorized to access an application.
 *
 * @package SimpleSAMLphp
 */

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SimpleSAML\Module\rciamauthorize\Auth\Process\AuthorizeError\BadRequest('Missing required StateId query parameter.');
}
$state = SimpleSAML\Auth\State::loadState($_REQUEST['StateId'], 'rciamauthorize:Authorize');

$globalConfig = SimpleSAML\Configuration::getInstance();
$t = new SimpleSAML\XHTML\Template($globalConfig, 'rciamauthorize:authorize_403.php');
if (isset($state['Source']['auth'])) {
    $authSource = $state['Source']['auth'];
} else if (isset($state['SimpleSAML_Auth_Source.id'])) {
    $authSource = $state['SimpleSAML_Auth_Source.id'];
}
if (isset($authSource)) {
    $t->data['logoutURL'] = SimpleSAML\Module::getModuleURL(
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
