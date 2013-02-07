<?php

namespace SilexOpauth;

use Silex\Application;
use Silex\ServiceProviderInterface;
use Opauth; // Non psr-0 namespace usage. :(

class OpauthExtension implements ServiceProviderInterface
{
    private $serviceConfig;

    public function register(Application $app)
    {
      $this->serviceConfig = $app['opauth'];
      $this->serviceConfig['config'] = array_merge(array(
        'path' => $app['opauth']['login'] . '/',
        'callback_url' => $app['opauth']['callback'],// Handy shortcut.
        'callback_transport' => 'post' // Won't work with silex session
      ), $app['opauth']['config']);

      $config = $this->serviceConfig['config'];

      $init =  function() use ($app, $config) {
          new Opauth($config);
      };

      $app->match($this->serviceConfig['login'] . '/{strategy}', $init);
      $app->match($this->serviceConfig['login'] . '/{strategy}/{return}', $init);

      $app->match($this->serviceConfig['callback'], function() use ($config){
        $Opauth = new Opauth($config, false );

      $response = unserialize(base64_decode( $_POST['opauth'] ));
      /**
       * Check if it's an error callback
       */
      if (array_key_exists('error', $response)){
        echo '<strong style="color: red;">Authentication error: </strong> Opauth returns error auth response.'."<br>\n";
      }

      /**
       * Auth response validation
       *
       * To validate that the auth response received is unaltered, especially auth response that
       * is sent through GET or POST.
       */
      else{
        if (empty($response['auth']) || empty($response['timestamp']) || empty($response['signature']) || empty($response['auth']['provider']) || empty($response['auth']['uid'])){
          echo '<strong style="color: red;">Invalid auth response: </strong>Missing key auth response components.'."<br>\n";
        }
        elseif (!$Opauth->validate(sha1(print_r($response['auth'], true)), $response['timestamp'], $response['signature'], $reason)){
          echo '<strong style="color: red;">Invalid auth response: </strong>'.$reason.".<br>\n";
        }
        else{
          echo '<strong style="color: green;">OK: </strong>Auth response is validated.'."<br>\n";

          /**
           * It's all good. Go ahead with your application-specific authentication logic
           */
        }
      }


      /**
      * Auth response dump
      */
      echo "<pre>";
      print_r($response);
      echo "</pre>";

      });

    }
    public function boot(Application $app)
    {
    }
}