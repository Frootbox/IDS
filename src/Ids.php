<?php
/**
 * @author Jan Habbo Brüning <jan.habbo.bruening@gmail.com>
 */

namespace Frootbox;

class Ids
{
    protected array $suspiciousUrls = [
        '.vscode/sftp.json',
        'Hash/.env',
        'Helmetjs/.env',
        'HUNIV_migration/.env',
        'ftp/.env',
        'frontend/.env',
        'frontend/momentum-fe/.env',
        'frontend/react/.env',
        'frontend/vue/.env',
        'frontend/web/debug/default/view',
        'frontendfinaltest/.env',
        'front/.env',
        'front/src/.env',
        'functions/.env',
        'gcloud.json',
        'gcp/.env',
        'github-connect/.env',
        'gists/cache',
        'gists/laravel',
        'gists/pusher',
        'google/.env',
        'graphiql',
        'graphql',
        'grems-api/.env',
        'grems-frontend/.env',
        'hasura/.env',
        'hgs-static/.env',
        'higlass-website/.env',
        'home/.env',
        'horde/.env',
        'hotpot-app-frontend/.env',
        'html/.env',
        'httpdocs/.env',
        'sftp-config.json',
    ];

    /**
     * @param string $url
     * @return void
     * @throws \Exception
     */
    public function check(string $url): void
    {
        $request = trim(strtolower($url), '/');

        $key = md5($request);

        $cacheFile =  __DIR__ . '/IdsCache.php';

        if (!file_exists($cacheFile)) {
            $list = [];

            foreach ($this->suspiciousUrls as $suspiciousUrl) {
                $list[] = md5(strtolower($suspiciousUrl));
            }

            $source = var_export($list, true);

            $source = '<?php return ' . $source . ';';

            file_put_contents($cacheFile, $source);
        }

        $checkSums = require $cacheFile;

        if (in_array($key, $checkSums)) {
            throw new \Exception('Suspicious URL');
        }
    }
}
