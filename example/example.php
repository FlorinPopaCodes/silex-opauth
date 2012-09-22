<?php

$loader = require_once __DIR__ . '/../vendor/autoload.php';

use Silex\Application,
    SilexOpauth\OpauthExtension;

$app = new Application();

$app['opauth'] = array(
  'login' => '/auth/login',
  'callback' => '/auth/callback',
  'config' => array(
    'security_salt' => 'LDFmiilYf8Fyw5W10rxx4W1KsVrieQCnpBzzpTBWA5vJidQKDx8pMJbmw28R1C4m',
    'Strategy' => array(
        'Facebook' => array(
           'app_id' => 'APP_ID',
           'app_secret' => 'APP_SECRET'
         ),
    )
  )
);

$app->register(new OpauthExtension());


$app->run();