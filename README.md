# misisipy-php-sdk

Misisipy ERP SDK for PHP
==================================

This SDK provides a simplified access to the [API](https://github.com/Misisipy/api-docs) of [Misisipy](https://www.misisipy.com).

Installation
------------
This SDK is mounted on top of [Requests for PHP](https://github.com/rmccue/Requests), so we recommend using [Composer](https://github.com/composer/composer) for installing.

Simply add the `misisipy/php-sdk` requirement to composer.json.

```json
{
    "require": {
        "misisipy/php-sdk": ">=1.0"
    }
}
```

Then run `composer install` or `composer update` to complete the installation.

If you need an autoloader, you can use the one provided by Composer:

```php
require 'vendor/autoload.php';
```


Authenticating Your App
-----------------------
When a user installs your app, he will be taken to your specified Redirect URI with a parameter called `code` containing your temporary authorization code.

With this code you can request a permanent access token.

```php
$code = $_GET['code'];

$auth = new Misisipy\Auth(CLIENT_ID, CLIENT_SECRET);
$access_info = $auth->request_access_token($code);
```

The returned value will contain the id of the authenticated store, as well as the access token and the authorized scopes.

```php
var_dump($access_info);
//array (size=5)
//  'expires_in' => int '1234' (Seconds),
//  'expiration_date_time' => int '12312311' (Unix Timestamp) 
//  'access_token' => string 'a2b544abbba560688a6ee7815926bd02dfc8d7bd784e2e016b422ebbbaa222',
//  'refresh_token' => string '560688a6ee7815926bd02dfc8d7bd784'
```

Keep in mind that future visits to your app will not go through the Redirect URI, so you should store the access info and check the expiration of token before call the API.

```php
$auth = new Misisipy\Auth(CLIENT_ID, CLIENT_SECRET);
if($auth->is_token_expired($access_info)){
    $access_info = $auth->renew_access_token($access_info["refresh_token"]);
}
var_dump($access_info);
//array (size=5)
//  'expires_in' => int '1234' (Seconds),
//  'expiration_date_time' => int '12312311' (Unix Timestamp) 
//  'access_token' => string 'a2b544abbba560688a6ee7815926bd02dfc8d7bd784e2e016b422ebbbaa222',
//  'refresh_token' => string '560688a6ee7815926bd02dfc8d7bd784'
```


However, if you need to authenticate a user that has already installed your app (or invite them to install it), you can redirect them to login to the Misisipy site.

```php
$auth = new Misisipy\Auth(CLIENT_ID, CLIENT_SECRET);

//You can use one of these to obtain a url to login to your app
$url = $auth->login_url(ACCOUNT_ID);


//Redirect to $url
```

After the user has logged in, he will be taken to your specified Redirect URI with a new authorization code. You can use this code to request a new request token.


Making a Request
----------------
The first step is to instantiate the `API` class with a store id and an access token, as well as a [user agent to identify your app](https://github.com/Misisipy/api-docs#identify-your-app). Then you can use the `get`, `post`, `put` and `delete` methods.

```php
$api = new Misisipy\API(ACCOUNT_ID, ACCESS_TOKEN, 'Awesome App (contact@awesome.com)');
$response = $api->get("products");
var_dump($response->body);
```

You can access the headers of the response via `$response->headers` as if it were an array:

```php
var_dump(isset($response->headers['X-Total-Count']));
//boolean true

var_dump($response->headers['X-Total-Count']);
//string '48' (length=2)
```

Other examples:

```php
//Create a product
$response = $api->post("products", [
    'name' => 'Snowboard',
]);
$product_id = $response->body->id;

//Change its name
$response = $api->put("products/$product_id", [
    'name' => 'Snowboard',
]);

//And delete it
$response = $api->delete("products/$product_id");

//You can also send arguments to GET requests
$response = $api->get("invoices", [
    'since_id' => 10000,
]);
```

For list results you can use the `next`, `prev`, `first` and `last` methods to retrieve the corresponding page as a new response object.

```php
$response = $api->get('products');
while($response != null){
    foreach($response->body as $product){
        var_dump($product->id);
    }
    $response = $response->next();
}
```

Exceptions
----------
Calls to `Auth` may throw a `Misisipy\Auth\Exception`:

```php
try{
    $auth->request_access_token($code);
} catch(Misisipy\Auth\Exception $e){
    var_dump($e->getMessage());
    
}
```

Likewise, calls to `API` may throw a `Misisipy\API\Exception`. You can retrieve the original response from these exceptions:

```php
try{
    $api->get('products');
} catch(Misisipy\API\Exception $e){
    var_dump($e->getMessage());
    //string 'Returned with status code 401: Invalid access token' (length=43)
    
    var_dump($e->response->body);
    //object(stdClass)[165]
    //  public 'code' => int 401
    //  public 'message' => string 'Unauthorized' (length=12)
    //  public 'description' => string 'Invalid access token' (length=20)
}
```

Requests that return 404 will throw a subclass called `Misisipy\API\NotFoundException`.
