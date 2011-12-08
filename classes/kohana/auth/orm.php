<?php defined('SYSPATH') or die('No direct access allowed.');
/**
 * Database Auth driver.
 *
 * @package    Kohana/Auth
 * @author     Daniel Skora
 */
class Kohana_Auth_Orm extends Auth {
    /**
     * Orm authorization table. 
     */
    const ORM_MODEL = 'user';

    /**
     * Constructor loads the user list into the class.
     */
    public function __construct($config = array())
    {
        parent::__construct($config);

        // Load user list
        $this->_users = Arr::get($config, 'users', array());
    }

    /**
     * Logs a user in.
     *
     * @param   string   username
     * @param   string   password
     * @param   boolean  enable autologin (not supported)
     * @return  boolean
     */
    protected function _login($username, $password, $remember)
    {
        if (is_string($password))
        {
            // Create a hashed password
            $password = $this->hash($password);
        }

        $user = ORM::factory(self::ORM_MODEL);
        $user
            ->where('username', '=', $username)
            ->where('password', '=', $password)
            ->find();

        if($user->loaded())
        {
            $this->complete_login($user);
            return true;
        }

        // Login failed
        return false;
    }

    /**
     * Get the stored password for a username.
     *
     * @param   mixed   user
     * @return  string
     */
    public function password($user)
    {
        return $this->get_user()->password;
    }

    /**
     * Compare password with original (plain text). Works for current (logged in) user
     *
     * @param   string  $password
     * @return  boolean
     */
    public function check_password($password)
    {
        $user = $this->get_user();
        if ($user === FALSE)
        {
            return FALSE;
        }

        return ($this->hash($password) === $this->password($user));
    }

    /**
     * Change user password.
     * 
     * @param string $password New password.
     *
     * @return void
     */
    public function change_password($password)
    {
        $user = $this->get_user();
        $user->password = $this->hash($password);
        $user->save();

        // regenerate session data
        $this->complete_login($user);
    }

    /**
     * Openid session.
     * 
     * @param Model $user User model.
     * 
     * @return void
     */
    public function openid_session($user)
    {
        $this->complete_login($user);
    }
} 
