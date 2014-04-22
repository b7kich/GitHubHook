<?php

namespace FDMIT\GitHubHook;


/**
* GitHub Post-Receive Deployment Hook.
*
* @license http://www.opensource.org/licenses/mit-license.php The MIT License
*/

class GitHubHook
{
 
	/**
	* @var boolean show error messages if set, default off.
	*/
  private $debug = FALSE;

/**
* @var array list of allowed caller IP ranges (CIDR notation), defaulting to GitHub's public IP addresses. Whitelist all callers with '0.0.0.0/0'.
*/
  private $allowedIpRanges = array('192.30.252.0/22');  

/**
* @var array list of allowed events per the X-GitHub-Event header, defaults to ['push', 'ping'] 
*/
  
  private $allowedEvents = array('push','ping'); 
  
  /**
   * Empty template method to override defaults etc. 
   */
  public function __construct() {
  
  }
  
   /**
	* Show error response, defaults to 404 Not Found to avoid undue interest. 
	* @param string $message short error reason
	* @return boolean FALSE to indicate error condition;
	*/
  private function error($message = NULL) {
    
    if ($message !== NULL) 
      $this->log($message);

    header('HTTP/1.1 404 Not Found');
    echo '404 Not Found.';

	if ($this->debug)
		echo ' '. htmlentities($message); 
    
	return false; 
  }

/**
* Log a message.
* @param string $message Message to log.
*/
  private function log($message) {
    if (!$this->debug) 
		return;
		
	$safeMessage=filter_var( $message, FILTER_SANITIZE_STRING,
	   FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH); 
	   
	trigger_error( $safeMessage, E_USER_ERROR);
  }

  /**
* Enable output of error messages.
* @param boolean $on flag, defaults to true 
*/
  public function setDebug($on=TRUE) {
    $this->debug = $on;
  }

  /**
   * Get caller IP with support for proxies like the EC2 load balancers.
   * @return string IP4 address   
   */
  private function getRemoteIp() {
	
	if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		$sanitizer='/^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})? *,?.*$/'; 
		$forwardedFor=preg_replace($sanitizer,'\1',$_SERVER['HTTP_X_FORWARDED_FOR']);
		
		if (filter_var($forwardedFor, FILTER_VALIDATE_IP))
			return $forwardedFor;
	}

	return $_SERVER['REMOTE_ADDR']; 
  }
  
/**
* IP in CIDRs Match - checks whether an IP exists within an array of CIDR ranges.
* @link - http://stackoverflow.com/questions/10243594/find-whether-a-given-ip-exists-in-cidr-or-not?lq=1
* @param string $ip - IP address in '127.0.0.1' format
* @param array $cidrs - array storing CIDRS in 192.168.1.20/27 format.
* @return bool
*/
  private function ipInCidrs($ip, $cidrs) {
    if (!$ip) 
		return FALSE; 
	
	$ipu = explode('.', $ip);

	foreach ($ipu as &$v) {
	$v = str_pad(decbin($v), 8, '0', STR_PAD_LEFT);
	}

	$ipu = join('', $ipu);
	$result = FALSE;

	foreach ($cidrs as $cidr) {
		$parts = explode('/', $cidr);
		$ipc = explode('.', $parts[0]);

		foreach ($ipc as &$v) $v = str_pad(decbin($v), 8, '0', STR_PAD_LEFT); {
			$ipc = substr(join('', $ipc), 0, $parts[1]);
			$ipux = substr($ipu, 0, $parts[1]);
			$result = ($ipc === $ipux);
		}

		if ($result) break;
	}

	return $result;
  }

  /**
   * Validate the request. 
   * @return GitHubEvent event with JSON-decoded request payload (as arrays) or FALSE on error. 
   */
  private function validate() {
  
    if (!$this->ipInCidrs($this->getRemoteIp(), $this->allowedIpRanges))
		return $this->error('Not allowed from IP: '.$this->getRemoteIp()); 
	
	if (!isset($_SERVER['HTTP_X_GITHUB_DELIVERY']))
		return $this->error('Missing X-GitHub-Delivery.'); 
		
	$delivery = filter_var( $_SERVER['HTTP_X_GITHUB_DELIVERY'], FILTER_SANITIZE_STRING,
	   FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH); 
		
	if (!isset($_SERVER['HTTP_X_GITHUB_EVENT'])) 
		return $this->error('Missing X-GitHub-Event.'); 
		
	$type = filter_var( $_SERVER['HTTP_X_GITHUB_EVENT'], FILTER_SANITIZE_STRING,
	   FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH); 
	
	if (!in_array($type, $this->allowedEvents)) 
		return $this->error('Unacceptable event type: '. $event->type); 
	
	if (!isset($_POST['payload'])) 
		return $this->error('Payload missing.');

	$payload = json_decode($_POST['payload'], false, 512, JSON_BIGINT_AS_STRING);

	if (NULL===$payload)
		return $this->error('Broken payload format.');
		
	// TODO implement X-Hub-Signature checking

	$event = new GitHubEvent();
	$event->delivery=$delivery;
	$event->type=$type;
	$event->payload=$payload; 
	
	return $event; 			
  } 
  
  
 	/**
	* Handle HTTP request and output error if invalid.
	* @return boolean true on success, false on error
	*/
	  public function handle() {
		if (!$event=$this->validate())
			return false; 
			
		// process event
		
		return true; 

	 }
	  
 }

/**
 * Stupid event data object.
 */
class GitHubEvent {

	/**
	 * @var string event type per X-GitHub-Event header, e.g. 'push' or 'ping'.
	 */ 
	public $type;
	
	/**
	 * @var string event delivery (globally unique id) per X-GitHub-Delivery header
	 */ 

	public $delivery;
	
	/**
	 * @var array JSON-decoded event payload (as nested arrays). 
	 */
	
	public $payload;

 }
 
