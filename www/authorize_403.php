<?php

/**
 * Show a 403 Forbidden page about not authorized to access an application.
 *
 * @package SimpleSAMLphp
 */

use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Module;
use SimpleSAML\XHTML\Template;

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SimpleSAML\Module\rciamauthorize\Auth\Process\AuthorizeError\BadRequest(
        'Missing required StateId query parameter.'
    );
}
$state = State::loadState($_REQUEST['StateId'], 'rciamauthorize:Authorize');

$globalConfig = Configuration::getInstance();
$t = new Template($globalConfig, 'rciamauthorize:authorize_403.php');
if (isset($state['Source']['auth'])) {
    $authSource = $state['Source']['auth'];
} elseif (isset($state['SimpleSAML_Auth_Source.id'])) {
    $authSource = $state['SimpleSAML_Auth_Source.id'];
}
if (isset($authSource)) {
    $t->data['logoutUrl'] = Module::getModuleURL(
        'core/authenticate.php',
        ['as' => $authSource]
    ) . "&logout";
}
if (isset($state['authprocAuthorize_reject_msg'])) {
    $t->data['rejectMsg'] = $state['authprocAuthorize_reject_msg'];
}
if (isset($state['authprocAuthorize_logo_url'])) {
    $t->data['logoUrl'] = $state['authprocAuthorize_logo_url'];
}
header('HTTP/1.0 403 Forbidden');
$t->show();
