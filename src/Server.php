<?php

namespace Jasny\SSO;

use Desarrolla2\Cache\Cache;
use Desarrolla2\Cache\Adapter;

/**
 * Single sign-on server.
 *
 * The SSO server is responsible of managing users sessions which are available for brokers.
 *
 * To use the SSO server, extend this class and implement the abstract methods.
 * This class may be used as controller in an MVC application.
 */
abstract class Server
{
    /**
     * @var integer
     */
    const DEFAULT_CACHE_TTL = 36000;

    /**
     * @var string
     */
    const DEFAULT_CACHE_DIRECTORY = '/tmp';

    /**
     * @var string
     */
    const HEADER_APPLICATION_JSON = 'Content-type: application/json; charset=UTF-8';

    /**
     * @var string
     */
    const HEADER_IMAGE = 'Content-Type: image/png';

    /**
     * @var array
     */
    protected $options;

    /**
     * Cache that stores the special session data for the brokers.
     *
     * @var Cache
     */
    protected $cache;

    /**
     * @var string
     */
    protected $returnType;

    /**
     * @var mixed
     */
    protected $brokerId;

    /**
     * Class constructor
     *
     * @param array $options
     */
    public function __construct(array $options=[])
    {
        $this->setOptions($options);
        $this->setCacheAdapter();
    }

    /**
     * Check given options, set defaults if not given
     */
    protected function setOptions(array $options=[])
    {
        if (!isset($options['files_cache_ttl'])) {
            $options['files_cache_ttl'] = self::DEFAULT_CACHE_TTL;
        }
        if (!isset($options['files_cache_directory'])) {
            $options['files_cache_directory'] = self::DEFAULT_CACHE_DIRECTORY;
        }

        $this->options = $options;
    }

    /**
     * Create a cache to store the broker session id.
     */
    protected function setCacheAdapter()
    {
        $adapter = new Adapter\File($this->options['files_cache_directory']);
        $adapter->setOption('ttl', $this->options['files_cache_ttl']);

        $this->cache = new Cache($adapter);
    }

    /**
     * Start the session for broker requests to the SSO server
     */
    public function startBrokerSession()
    {
        if (!empty($this->brokerId)) return;

        $sid = $this->getBrokerSessionID();

        if ($sid == false) {
            $this->fail("Broker didn't send a session key", 400);
        }

        $linkedId = $this->cache->get($sid);

        if (empty($linkedId)) {
            $this->fail("The broker session id isn't attached to a user session", 403);
        }

        if (session_status() === PHP_SESSION_ACTIVE && $linkedId !== session_id()) {
            $this->fail("Session has already started", 400);
        }

        session_id($linkedId);
        session_start();

        $this->brokerId = $this->validateBrokerSessionId($sid);
    }

    /**
     * Get session ID from header Authorization or from $_GET/$_POST
     */
    protected function getBrokerSessionID()
    {
        $headers = getallheaders();

        if (isset($headers['Authorization']) &&  strpos($headers['Authorization'], 'Bearer') === 0) {
            $headers['Authorization'] = substr($headers['Authorization'], 7);
            return $headers['Authorization'];
        }
        if (isset($_GET['access_token'])) {
            return $_GET['access_token'];
        }
        if (isset($_POST['access_token'])) {
            return $_POST['access_token'];
        }
        if (isset($_GET['sso_session'])) {
            return $_GET['sso_session'];
        }

        return false;
    }

    /**
     * Validate the broker session id
     *
     * @param string $sid session id
     * @return string  the broker id
     */
    protected function validateBrokerSessionId($sid)
    {
        $matches = null;

        if (!preg_match('/^SSO-(\w*+)-(\w*+)-([a-z0-9]*+)$/', $this->getBrokerSessionID(), $matches)) {
            $this->fail("Invalid session id");
        }

        $brokerId = $matches[1];
        $token = $matches[2];

        if ($this->generateSessionId($brokerId, $token) != $sid) {
            $this->fail("Checksum failed: Client IP address may have changed", 403);
        }

        return $brokerId;
    }

    /**
     * Start the session when a user visits the SSO server
     */
    protected function startUserSession()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    }

    /**
     * Generate session id from session token
     *
     * @param string $brokerId
     * @param string $token
     * @return string
     */
    protected function generateSessionId($brokerId, $token)
    {
        $broker = $this->getBrokerInfo($brokerId);

        if (empty($broker) || !isset($broker['secret'])) return null;

        return "SSO-{$brokerId}-{$token}-" . hash('sha256', 'session' . $token . $broker['secret']);
    }

    /**
     * Generate session id from session token
     *
     * @param string $brokerId
     * @param string $token
     * @return string
     */
    protected function generateAttachChecksum($brokerId, $token)
    {
        $broker = $this->getBrokerInfo($brokerId);

        if (empty($broker) || !isset($broker['secret'])) return null;

        return hash('sha256', 'attach' . $token . $broker['secret']);
    }

    /**
     * Attach a user session to a broker session
     */
    public function attach()
    {
        if (!isset($_REQUEST['broker']) || empty($_REQUEST['broker'])) {
            $this->fail("No broker specified", 400);
        }
        if (!isset($_REQUEST['token']) || empty($_REQUEST['token'])) {
            $this->fail("No token specified", 400);
        }
        if (!isset($_REQUEST['checksum']) || empty($_REQUEST['checksum'])) {
            $this->fail("Checksum not provided", 400);
        }

        $checksum = $this->generateAttachChecksum($_REQUEST['broker'], $_REQUEST['token']);
        if ($checksum != $_REQUEST['checksum']) {
            $this->fail("Invalid checksum", 400);
        }

        $this->startUserSession();
        $sid = $this->generateSessionId($_REQUEST['broker'], $_REQUEST['token']);

        $this->cache->set($sid, $this->getSessionData('id'));
        $this->outputAttachSuccess();
    }

    /**
     * Detect the type for the HTTP response.
     * Should only be done for an `attach` request.
     */
    protected function detectReturnType()
    {
        if (isset($_GET['return_url']) && !empty($_GET['return_url'])) {
            $this->returnType = 'redirect';
        } elseif (isset($_GET['callback']) && !empty($_GET['callback'])) {
            $this->returnType = 'jsonp';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'image/') !== false) {
            $this->returnType = 'image';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
            $this->returnType = 'json';
        }
    }

    /**
     * Output on a successful attach
     */
    protected function outputAttachSuccess()
    {
        $this->detectReturnType();
        if (empty($this->returnType)) {
            $this->fail("No return url specified", 400);
        }

        if ($this->returnType === 'image') {
            $this->outputImage();
        }

        if ($this->returnType === 'json') {
            header(self::HEADER_APPLICATION_JSON);
            echo json_encode(['success' => 'attached']);
            exit;
        }

        if ($this->returnType === 'jsonp') {
            $data = json_encode(['success' => 'attached']);
            echo $_REQUEST['callback'] . "($data, 200);";
            exit;
        }

        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'];
            header("Location: $url", true, 307);
        }
    }

    /**
     * Output a 1x1px transparent image
     */
    protected function outputImage()
    {
        header(self::HEADER_IMAGE);
        echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQ'
            . 'MAAAAl21bKAAAAA1BMVEUAAACnej3aAAAAAXRSTlMAQObYZg'
            . 'AAAApJREFUCNdjYAAAAAIAAeIhvDMAAAAASUVORK5CYII=');
        exit;
    }


    /**
     * Authenticate
     */
    public function login()
    {
        $this->startBrokerSession();

        if (!isset($_POST['username']) || empty($_POST['username'])) {
            $this->fail("No username specified", 400);
        }
        if (!isset($_POST['password']) || empty($_POST['password'])) {
            $this->fail("No password specified", 400);
        }

        $validation = $this->authenticate($_POST['username'], $_POST['password']);

        if ($validation->failed()) {
            $this->fail($validation->getError(), 400);
        }

        $this->setSessionData('sso_user', $_POST['username']);
        $this->userInfo();
    }

    /**
     * Log out
     */
    public function logout()
    {
        $this->startBrokerSession();
        $this->setSessionData('sso_user', null);

        header(self::HEADER_APPLICATION_JSON, true, 204);
    }

    /**
     * Ouput user information as json.
     */
    public function userInfo()
    {
        $this->startBrokerSession();

        $username = $this->getSessionData('sso_user');
        if (!empty($username)) {
            $user = $this->getUserInfo($username);
            if (empty($user)) {
                $this->fail("User not found", 500); // Shouldn't happen
            }
        }

        header(self::HEADER_APPLICATION_JSON);
        echo json_encode($user);
    }


    /**
     * Set session data
     *
     * @param string $key
     * @param string $value
     */
    protected function setSessionData($key, $value)
    {
        if (empty($value)) {
            unset($_SESSION[$key]);
            return;
        }

        $_SESSION[$key] = $value;
    }

    /**
     * Get session data
     *
     * @param type $key
     */
    protected function getSessionData($key)
    {
        if ($key === 'id') return session_id();

        return isset($_SESSION[$key]) ? $_SESSION[$key] : null;
    }


    /**
     * An error occured.
     *
     * @param string $message
     * @param int    $http_status
     */
    protected function fail($message, $http_status = 500)
    {
        if (isset($this->options['fail_exception']) && $this->options['fail_exception'] == true) {
            throw new Exception($message, $http_status);
        }

        if ($http_status === 500) trigger_error($message, E_USER_WARNING);

        if ($this->returnType === 'jsonp') {
            echo $_REQUEST['callback'] . "(" . json_encode(['error' => $message]) . ", $http_status);";
            exit();
        }

        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'] . '?sso_error=' . $message;
            header("Location: $url", true, 307);
            exit();
        }

        header(self::HEADER_APPLICATION_JSON, true, $http_status);

        echo json_encode(['error' => $message]);
        exit();
    }


    /**
     * Authenticate using user credentials
     *
     * @param string $username
     * @param string $password
     * @return \Jasny\ValidationResult
     */
    abstract protected function authenticate($username, $password);

    /**
     * Get the secret key and other info of a broker
     *
     * @param string $brokerId
     * @return array
     */
    abstract protected function getBrokerInfo($brokerId);

    /**
     * Get the information about a user
     *
     * @param string $username
     * @return array|object
     */
    abstract protected function getUserInfo($username);
}

