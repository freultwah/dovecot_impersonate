<?php

/**
 * This plugin lets you impersonate another user using a master login. Only works with dovecot.
 * 
 * http://wiki.dovecot.org/Authentication/MasterUsers
 * 
 * @author Cor Bosman (roundcube@wa.ter.net)
 */
  
class dovecot_impersonate extends rcube_plugin {
    private $config;
    
    public function init(): void
    {    
        $this->add_hook('storage_connect', [$this, 'impersonate']);
        $this->add_hook('managesieve_connect', [$this, 'impersonate']);
        $this->add_hook('authenticate', [$this, 'login']);  
        $this->add_hook('sieverules_connect', [$this, 'impersonate_sieve']);  
    }
  
    public function login(array $data): array
    {
        // find the separator character
        $rcmail = rcmail::class::get_instance();
        $this->load_config();
    
        $seperator = $rcmail->config->get('dovecot_impersonate_seperator', '*');
    
        if (strpos($data['user'], $seperator)) {
            $arr = explode($seperator, $data['user']);
            if (count($arr) == 2) {
                $data['user'] = $arr[0];
                $_SESSION['plugin.dovecot_impersonate_master'] = $seperator . $arr[1];
            }
        }
        return $data;
    }
  
    public function impersonate(array $data): array
    {
        if (isset($_SESSION['plugin.dovecot_impersonate_master'])) {
            $data['user'] = $data['user'] . $_SESSION['plugin.dovecot_impersonate_master']; 
        }
        return $data;
    }
  
    public function impersonate_sieve(array $data): array
    {
        if (isset($_SESSION['plugin.dovecot_impersonate_master'])) {
            $data['username'] = $data['username'] . $_SESSION['plugin.dovecot_impersonate_master']; 
        }
        return $data;
    }
}

