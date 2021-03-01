<?php
/**
 * Template which is shown when there is only a short interval since the user was last authenticated.
 *
 * Parameters:
 * - 'target': Target URL.
 * - 'params': Parameters which should be included in the request.
 *
 * @package SimpleSAMLphp
 */


$this->data['403_header'] = $this->t('{rciamauthorize:Authorize:403_header}');
$this->data['403_text'] = $this->t('{rciamauthorize:Authorize:403_text}');

$this->data['jquery'] = array('core' => true);

// Check if custom reject message is present:
// 1. Get message translation in current language;
// 2. otherwise check for translation in default language from configuration;
// 3. last resort, get first available translation
if (array_key_exists('reject_msg', $this->data)) {
    if(isset($this->data['reject_msg'][$this->getLanguage()])) {
        $this->data['403_text'] = $this->data['reject_msg'][$this->getLanguage()];
    } else if (isset($this->data['reject_msg'][$this->getDefaultLanguage()])) {
        $this->data['403_text'] = $this->data['reject_msg']['en'];
    } else {
        $this->data['403_text'] = reset($this->data['reject_msg']);
    }
}
$this->includeAtTemplateBase('includes/header.php');

echo '<h1>'.$this->data['403_header'].'</h1>';
echo '<table><tr>';
if (isset($this->data['logoURL'])) {
    echo '<td><img src="'.$this->data['logoURL'].'" style="height: 90px; margin: 15px" alt="" /></td>';
}
echo '<td>'.$this->data['403_text'].'</td>';
echo '</tr></table>';
if (isset($this->data['logoutURL'])) {
    echo '<p><a href="'.htmlspecialchars($this->data['logoutURL']).'">'.$this->t('{status:logout}').'</a></p>';
}

$this->includeAtTemplateBase('includes/footer.php');
