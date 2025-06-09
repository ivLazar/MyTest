<?php


define('TOKEN_FILE', DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'textlines.txt');
/*
 *
 * */
define('AUTH_CODE', 'def50200fb92398eb973bcedc27b7acea852c4554f3c89725e4f35a2ce177020a1d91a3105cc7a89dbc21599b6a692adc44c10951518cf5c6ed42279dbf93022e458e959ef9fd76d7b2a8084e8e2d55ff4ef4b3bbf1df0d05839758d5d114c9dfcd365d183518e45594879a67935576839621d826e4960f9eb7de67bf113de80c4ddfa0f4420e2ff0290a71c8c1444e2835b63d53355150799e03cdfee7f7fc685271c5f7d5697038497c21471b11ac016953518bfdf09c231092a7c0f02891575d5ca89d6ce794217f48c90a688c46dc59bf9963760b67d03a59145f74b8d0403aba88d13165770a0f0ea6b25c8aedf10e900d7e2c52201c83392ccff2b1590b70f0c2f0ad964f70ea23ea9fc86c233a37b043a14d3ed188ddd3ce95822d2af9818279c5da21ed6a4e682b2766a6174553716785cc68b9e718de9b4a05d6792eb6b6ca6b0fdd9e4603e67a9260dc5afa078e260a6d787e69717f3a3262cfd68f7b0c44ceaddbbc06132fc24d75df0f97744b9409ac4e2b94eac055a2f03b4877114be9abb047ab407c7e7f80789b131f5f4248a033694a92f605645f7ef6c9a74dc158992902d632930364e48dbc032f76188bc1d1fd2a35e44515c8eae40dc7b8830f2b969c861c4356d843918d555c81a8381f177cf0b7cef20d0ca031633192556407535a8a448e8');

use AmoCRM\OAuth2\Client\Provider\AmoCRM;

include_once __DIR__ . '/vendor/autoload.php';
include_once __DIR__ . '/src/AmoCRM.php';

session_start();
function getToken()
{
    /**
     * Эти параметры лучше вынести в envirement
    */
    $provider = new AmoCRM([
        'clientId' => '6ac9222b-0cf2-4d73-a2b3-c87355e647fe',
        'clientSecret' => '7g7S5n5nk0W1V5yNUKaov5Qef0ewcPI0a8oUeUmJTRvfI2bGRAZlBqm72tK39lYL',
        'redirectUri' => 'http://f1133136.xsph.ru',
    ]);


    $accessToken = getStoredToken();

    $provider->setBaseDomain($accessToken->getValues()['baseDomain']);

    /**
     * Проверяем активен ли токен и делаем запрос или обновляем токен
     */
    if ($accessToken->hasExpired()) {
        /**
         * Получаем токен по рефрешу
         */
        try {
            $accessToken = $provider->getAccessToken(new League\OAuth2\Client\Grant\RefreshToken(), [
                'refresh_token' => $accessToken->getRefreshToken(),
            ]);

            saveToken([
                'accessToken' => $accessToken->getToken(),
                'refreshToken' => $accessToken->getRefreshToken(),
                'expires' => $accessToken->getExpires(),
                'baseDomain' => $provider->getBaseDomain(),
            ]);

        } catch (Exception $e) {
            die((string)$e);
        }
    }

    return $accessToken->getToken();
}




function saveToken($accessToken)
{
    if (
        isset($accessToken)
        && isset($accessToken['accessToken'])
        && isset($accessToken['refreshToken'])
        && isset($accessToken['expires'])
        && isset($accessToken['baseDomain'])
    ) {
        $data = [
            'accessToken' => $accessToken['accessToken'],
            'expires' => $accessToken['expires'],
            'refreshToken' => $accessToken['refreshToken'],
            'baseDomain' => $accessToken['baseDomain'],
        ];

        file_put_contents(TOKEN_FILE, json_encode($data));
    } else {
        exit('Invalid access token ' . var_export($accessToken, true));
    }
}

/**
 * @return \League\OAuth2\Client\Token\AccessToken
 */
function getStoredToken()
{
    $accessToken = json_decode(file_get_contents(TOKEN_FILE), true);

    if (
        isset($accessToken)
        && isset($accessToken['accessToken'])
        && isset($accessToken['refreshToken'])
        && isset($accessToken['expires'])
        && isset($accessToken['baseDomain'])
    ) {
        return new \League\OAuth2\Client\Token\AccessToken([
            'access_token' => $accessToken['accessToken'],
            'refresh_token' => $accessToken['refreshToken'],
            'expires' => $accessToken['expires'],
            'baseDomain' => $accessToken['baseDomain'],
        ]);
    } else {
        $provider = new AmoCRM([
            'clientId' => '6ac9222b-0cf2-4d73-a2b3-c87355e647fe',
            'clientSecret' => '7g7S5n5nk0W1V5yNUKaov5Qef0ewcPI0a8oUeUmJTRvfI2bGRAZlBqm72tK39lYL',
            'redirectUri' => 'http://f1133136.xsph.ru',
        ]);
        try {
            /** @var \League\OAuth2\Client\Token\AccessToken $access_token */
            $accessToken = $provider->getAccessToken(new League\OAuth2\Client\Grant\AuthorizationCode(), [
                'code' => AUTH_CODE,
                'grant_type' => 'authorization_code',
            ]);

            if (!$accessToken->hasExpired()) {
                saveToken([
                    'accessToken' => $accessToken->getToken(),
                    'refreshToken' => $accessToken->getRefreshToken(),
                    'expires' => $accessToken->getExpires(),
                    'baseDomain' => $provider->getBaseDomain(),
                ]);
            }
        } catch (Exception $e) {
            die((string)$e);
        }


        return $accessToken;
    }
}