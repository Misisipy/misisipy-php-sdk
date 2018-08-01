<?php
namespace Misisipy;

/**
 * Provides a simple way to authenticate your app for the API of Tienda Nube/Nuvem Shop.
 * See https://github.com/Misisipy/api-docs for details.
 */
class Auth {
    protected $client_id;
    protected $client_secret;
    protected $auth_url;
    public $requests;

    /**
     * Initialize the class to perform authentication for a specific app.
     *
     * @param string $client_id The public client id of your app
     * @param string $client_secret The private client secret of your app
     */
    public function __construct($client_id, $client_secret){
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->auth_url = "https://misisipy.auth0.com/oauth/token";
        $this->requests = new Requests;
    }
    
    
    /**
     * Obtain a permanent access token from an authorization code.
     *
     * @param string $code Authorization code retrieved from the redirect URI.
     */
    public function request_access_token($code){
        $params = [
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'code' => $code,
            'grant_type' => 'authorization_code',
        ];
        
        $response = $this->requests->post($this->auth_url, [], $params);
        if (!$response->success){
            throw new Auth\Exception('Auth url returned with status code ' . $response->status_code);
        }
        
        $body = json_decode($response->body);
        if (isset($body->error)){
            throw new Auth\Exception("[{$body->error}] {$body->error_description}");
        }
        
        return [
            'expires_in' => $body->expires_in,
            'expiration_date_time'=> time()+intval($body->expires_in),
            'access_token' => $body->access_token,
            'scope' => $body->scope,
        ];
    }

    /**
     * Verify if an access token is expired
     *
     * @param array $token_data Array of token info retrieved from a previus Authorization process.
     */

    public function is_token_expired($token_data){
        if(isset($token_data['expiration_date_time']) && $token_data['expiration_date_time'] > time()){
            return false;
        }
        return true;
    }

    /**
     * Obtain app login url
     *
     * @param int $account_id Misisipy Account Id .
     */
    public function login_url($account_id){
        return 'https://misisipy.com/'.$account_id.'/app/login/client_id/'.$this->client_id;
    }

     /**
     * Obtain a new access token from on a refresh token.
     *
     * @param string $refresh_token Refresh token code retrieved from a previus Authorization process.
     */
    public function renew_access_token($refresh_token){
        $params = [
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'refresh_token' => $refresh_token,
            'grant_type' => 'refresh_token',
        ];
        
        $response = $this->requests->post($this->auth_url, [], $params);
        if (!$response->success){
            throw new Auth\Exception('Auth url returned with status code ' . $response->status_code);
        }
        
        $body = json_decode($response->body);
        if (isset($body->error)){
            throw new Auth\Exception("[{$body->error}] {$body->error_description}");
        }
        
        return [
            'expires_in' => $body->expires_in,
            'expiration_date_time'=> time()+$body->expires_in,
            'access_token' => $body->access_token,
            'scope' => $body->scope,
        ];


    }
}
