<?php


namespace Yadahan\AuthenticationLog;

use GuzzleHttp\Client as GuzzleClient;
use Illuminate\Support\Facades\Cache;

class GeoLocateService
{
    public const MONTH_IN_MINUTES = 43800;

    public function getLocationByIpAddress(string $ip)
    {
        $cacheKey = 'authlog_geolocate_' . md5($ip);

        $location = Cache::remember($cacheKey, static::MONTH_IN_MINUTES, function () use ($ip) {
            try {
                $client = new GuzzleClient();
                $url =  'https://get.geojs.io/v1/ip/geo/' . $ip . '.json';
                $response = $client->get($url, [
                    'allow_redirects' => true,
                    'connect_timeout' => config('authentication-log.geolocation_timeout'),
                    'read_timeout' => config('authentication-log.geolocation_timeout'),
                    'timeout' => config('authentication-log.geolocation_timeout'),
                ]);

                $responseData = (string) $response->getBody();

                return json_decode($responseData);
            } catch (\Exception $e) {
                logger($e->getMessage());

                return [];
            }

            return [];
        });

        if (empty($location)) {
            Cache::forget($cacheKey);
        }

        $city = data_get($location, 'city', 'Unknown') . ', ' . data_get($location, 'country', 'Unknown');

        return $city;
    }
}