<?php
declare(strict_types=1);

namespace App\Mutator\Support;

final class HtmlValueConfig
{
    /** @return string[] exactly N (<=100) tokens */
    public static function getTokens(int $limit = 100): array
    {
        $cfg = self::loadJson();
        $limit = max(1, min(100, (int)($cfg['limit'] ?? $limit)));

        if (!empty($cfg['tokens']) && is_array($cfg['tokens'])) {
            $tokens = array_values(array_filter(array_map('strval', $cfg['tokens']), static fn($s) => $s !== ''));
            $tokens = array_slice(array_unique($tokens), 0, $limit);
            if ($tokens) {
                return $tokens;
            }
        }
        return self::defaultTokens($limit);
    }

    /** @return array<string,mixed> */
    private static function loadJson(): array
    {
        $paths = [];
        $env = getenv('INFECTION_HTML_VALUE_PAYLOADS');
        if (is_string($env) && $env !== '') $paths[] = $env;
        $paths[] = getcwd() . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'html-value-payloads.json';

        foreach ($paths as $p) {
            if (is_file($p)) {
                $raw = @file_get_contents($p);
                if ($raw !== false) {
                    $d = json_decode($raw, true);
                    if (is_array($d)) return $d;
                }
            }
        }
        return [];
    }

    /** @return string[] */
    private static function defaultTokens(int $limit): array
    {
        // daftar umum + generator "token0001.."
        $common = [
            '123456','password','qwerty','admin','guest','test','abc123','111111','000000',
            'letmein','welcome','iloveyou','token','csrf','phpsessid','session','user','login',
            'root','default','changeme','passw0rd','secret','monkey','dragon','cookie_phpsessid',
            'sessionid','csrf_token','xsrf_token','auth_token','pw','pwd','pass','qwerty123',
            'admin123','user123','test123','abc','abc12345','hello','foobar','lorem','ipsum',
            'deadbeef','cafebabe','base64token','simpletoken','mytoken','apitoken','insecure',
            'guessable','weaktoken','devtoken','demotoken','sample','temp','tmp','staging',
            'debug','debugtoken','token_csrf','csrfToken','xsrfToken','token1','token2','token3',
            'key','key123','keytoken','jwt','jwt123','jwt_token','session_token','sid','sid123',
            'sess','sessid','phpsess','phpsession','cookie','cookieid','cookie_token','auth',
            'authid','authkey','apikey','api_key','bearer','bearer_token','nonce','salt','pepper',
            'otp','pin','pin123','code','code123'
        ];
        // lengkapi sampai limit dengan pola token00xx
        $i = 1;
        while (count($common) < $limit) {
            $common[] = sprintf('token%04d', $i++);
        }
        return array_slice($common, 0, $limit);
    }
}
