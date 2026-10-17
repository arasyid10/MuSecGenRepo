
<?

##Instructions
-  Acting as a proficient software security tester, Create a security test case capable of killing the mutant in the 
   "##Survived Mutant Code" section below.


"##Survived Mutant Code"
1) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Client\Adapter\Mock.php:135    [M] Cake\Mutator\ReturnConstantTrueMutator
         $starPosition = strrpos($mockUri, '/%2A');
         if ($starPosition === strlen($mockUri) - 4) {
             $mockUri = substr($mockUri, 0, $starPosition);
-            return str_starts_with($requestUri, $mockUri);
+            return true;
         }
         return false;
     }
 }
2) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Client\Auth\Oauth.php:159    [M] Cake\Mutator\Security\HashHmacAlgoAlternativesMutator


         $key = [$credentials['consumerSecret'], $credentials['tokenSecret']];
         $key = array_map($this->_encode(...), $key);
         $key = implode('&', $key);
-        $values['oauth_signature'] = base64_encode(hash_hmac('sha1', $baseString, $key, true));
+        $values['oauth_signature'] = base64_encode(hash_hmac('md5', $baseString, $key, true));
         return $this->_buildAuth($values);
     }


3) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Client\Auth\Oauth.php:159    [M] Cake\Mutator\Security\HashHmacAlgoAlternativesMutator


         $key = [$credentials['consumerSecret'], $credentials['tokenSecret']];
         $key = array_map($this->_encode(...), $key);
         $key = implode('&', $key);
-        $values['oauth_signature'] = base64_encode(hash_hmac('sha1', $baseString, $key, true));
+        $values['oauth_signature'] = base64_encode(hash_hmac('Whirlpool', $baseString, $key, true));
         return $this->_buildAuth($values);
     }


4) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\ContentTypeNegotiation.php:108    [M] Cake\Mutator\StrposToStriposMutator


         $accept = [];
         foreach ($raw as $languages) {
             foreach ($languages as &$lang) {
-                if (strpos($lang, '_')) {
+                if (stripos($lang, '_')) {
                     $lang = str_replace('_', '-', $lang);
                 }
                 $lang = strtolower($lang);


5) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\ContentTypeNegotiation.php:108    [M] Cake\Mutator\StrposToStrContainsMutator


         $accept = [];
         foreach ($raw as $languages) {
             foreach ($languages as &$lang) {
-                if (strpos($lang, '_')) {
+                if (str_contains($lang, '_')) {
                     $lang = str_replace('_', '-', $lang);
                 }
                 $lang = strtolower($lang);


6) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\ContentTypeNegotiation.php:108    [M] Cake\Mutator\StrposToStrrposMutator


         $accept = [];
         foreach ($raw as $languages) {
             foreach ($languages as &$lang) {
-                if (strpos($lang, '_')) {
+                if (strrpos($lang, '_')) {
                     $lang = str_replace('_', '-', $lang);
                 }
                 $lang = strtolower($lang);


7) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\ContentTypeNegotiation.php:108    [M] Cake\Mutator\StrposToStrstrMutator


         $accept = [];
         foreach ($raw as $languages) {
             foreach ($languages as &$lang) {
-                if (strpos($lang, '_')) {
+                if (strstr($lang, '_')) {
                     $lang = str_replace('_', '-', $lang);
                 }
                 $lang = strtolower($lang);


8) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\ContentTypeNegotiation.php:108    [M] Cake\Mutator\StrposToStrpbrkMutator


         $accept = [];
         foreach ($raw as $languages) {
             foreach ($languages as &$lang) {
-                if (strpos($lang, '_')) {
+                if (strpbrk($lang, '_')) {
                     $lang = str_replace('_', '-', $lang);
                 }
                 $lang = strtolower($lang);


9) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\CorsBuilder.php:141    [M] Cake\Mutator\ReplaceSecondArgWithDriveMutator


             }
             $original = $domain;
             $preg = $domain;
-            if (!str_contains($domain, '://')) {
+            if (!str_contains($domain, 'C:\\')) {
                 $preg = ($this->_isSsl ? 'https://' : 'http://') . $domain;
             }
             $preg = '@^' . str_replace('\*', '.*', preg_quote($preg, '@')) . '$@';


10) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\CorsBuilder.php:141    [M] Cake\Mutator\ReplaceSecondArgWithDriveMutator


             }
             $original = $domain;
             $preg = $domain;
-            if (!str_contains($domain, '://')) {
+            if (!str_contains($domain, 'D:\\')) {
                 $preg = ($this->_isSsl ? 'https://' : 'http://') . $domain;
             }
             $preg = '@^' . str_replace('\*', '.*', preg_quote($preg, '@')) . '$@';


11) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\HeaderUtility.php:88    [M] Cake\Mutator\StrposToStriposMutator


         foreach (array_filter($headers) as $value) {
             $prefValue = '1.0';
             $value = trim($value);
-            $semiPos = strpos($value, ';');
+            $semiPos = stripos($value, ';');
             if ($semiPos !== false) {
                 $params = explode(';', $value);
                 $value = trim($params[0]);


12) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\HeaderUtility.php:88    [M] Cake\Mutator\StrposToStrContainsMutator


         foreach (array_filter($headers) as $value) {
             $prefValue = '1.0';
             $value = trim($value);
-            $semiPos = strpos($value, ';');
+            $semiPos = str_contains($value, ';');
             if ($semiPos !== false) {
                 $params = explode(';', $value);
                 $value = trim($params[0]);


13) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\HeaderUtility.php:88    [M] Cake\Mutator\StrposToStrrposMutator


         foreach (array_filter($headers) as $value) {
             $prefValue = '1.0';
             $value = trim($value);
-            $semiPos = strpos($value, ';');
+            $semiPos = strrpos($value, ';');
             if ($semiPos !== false) {
                 $params = explode(';', $value);
                 $value = trim($params[0]);


14) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\HeaderUtility.php:88    [M] Cake\Mutator\StrposToStrstrMutator


         foreach (array_filter($headers) as $value) {
             $prefValue = '1.0';
             $value = trim($value);
-            $semiPos = strpos($value, ';');
+            $semiPos = strstr($value, ';');
             if ($semiPos !== false) {
                 $params = explode(';', $value);
                 $value = trim($params[0]);


15) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\HeaderUtility.php:88    [M] Cake\Mutator\StrposToStrpbrkMutator


         foreach (array_filter($headers) as $value) {
             $prefValue = '1.0';
             $value = trim($value);
-            $semiPos = strpos($value, ';');
+            $semiPos = strpbrk($value, ';');
             if ($semiPos !== false) {
                 $params = explode(';', $value);
                 $value = trim($params[0]);


16) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\HeaderUtility.php:93    [M] Cake\Mutator\StrposToStriposMutator


                 $params = explode(';', $value);
                 $value = trim($params[0]);
                 foreach ($params as $param) {
-                    $qPos = strpos($param, 'q=');
+                    $qPos = stripos($param, 'q=');
                     if ($qPos !== false) {
                         $prefValue = substr($param, $qPos + 2);
                     }


17) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\HeaderUtility.php:93    [M] Cake\Mutator\StrposToStrrposMutator


                 $params = explode(';', $value);
                 $value = trim($params[0]);
                 foreach ($params as $param) {
-                    $qPos = strpos($param, 'q=');
+                    $qPos = strrpos($param, 'q=');
                     if ($qPos !== false) {
                         $prefValue = substr($param, $qPos + 2);
                     }


18) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Middleware\CsrfProtectionMiddleware.php:318    [M] Cake\Mutator\Security\HashEqualsToInsecureEqualityMutator


         $key = substr($decoded, 0, static::TOKEN_VALUE_LENGTH);
         $hmac = substr($decoded, static::TOKEN_VALUE_LENGTH);
         $expectedHmac = hash_hmac('sha1', $key, Security::getSalt());
-        return hash_equals($hmac, $expectedHmac);
+        return $hmac === $expectedHmac;
     }

  
19) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Middleware\CsrfProtectionMiddleware.php:318    [M] Cake\Mutator\Security\HashEqualsToInsecureEqualityMutator


         $key = substr($decoded, 0, static::TOKEN_VALUE_LENGTH);
         $hmac = substr($decoded, static::TOKEN_VALUE_LENGTH);
         $expectedHmac = hash_hmac('sha1', $key, Security::getSalt());
-        return hash_equals($hmac, $expectedHmac);
+        return $hmac == $expectedHmac;
     }



20) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Middleware\CsrfProtectionMiddleware.php:370    [M] Cake\Mutator\Security\HashEqualsToInsecureEqualityMutator


         if (is_array($body) || $body instanceof ArrayAccess) {
             $post = (string) Hash::get($body, $this->_config['field']);
             $post = $this->unsaltToken($post);
-            if (hash_equals($post, $cookie)) {
+            if ($post === $cookie) {
                 return;
             }
         }



21) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Middleware\CsrfProtectionMiddleware.php:370    [M] Cake\Mutator\Security\HashEqualsToInsecureEqualityMutator


         if (is_array($body) || $body instanceof ArrayAccess) {
             $post = (string) Hash::get($body, $this->_config['field']);
             $post = $this->unsaltToken($post);
-            if (hash_equals($post, $cookie)) {
+            if ($post == $cookie) {
                 return;
             }
         }



22) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Middleware\CsrfProtectionMiddleware.php:377    [M] Cake\Mutator\Security\HashEqualsToInsecureEqualityMutator


         }
         $header = $request->getHeaderLine('X-CSRF-Token');
         $header = $this->unsaltToken($header);
-        if (hash_equals($header, $cookie)) {
+        if ($header === $cookie) {
             return;
         }
         throw new InvalidCsrfTokenException(__d('cake', 'CSRF token from either the request body or request headers did not match or is missing.'));



23) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Middleware\CsrfProtectionMiddleware.php:377    [M] Cake\Mutator\Security\HashEqualsToInsecureEqualityMutator

         }
         $header = $request->getHeaderLine('X-CSRF-Token');
         $header = $this->unsaltToken($header);
-        if (hash_equals($header, $cookie)) {
+        if ($header == $cookie) {
             return;
         }
         throw new InvalidCsrfTokenException(__d('cake', 'CSRF token from either the request body or request headers did not match or is missing.'));



24) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Middleware\SessionCsrfProtectionMiddleware.php:256    [M] Cake\Mutator\Security\HashEqualsToInsecureEqualityMutator


         if (is_array($body) || $body instanceof ArrayAccess) {
             $post = (string) Hash::get($body, $this->_config['field']);
             $post = $this->unsaltToken($post);
-            if (hash_equals($post, $token)) {
+            if ($post === $token) {
                 return;
             }
         }



25) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Middleware\SessionCsrfProtectionMiddleware.php:256    [M] Cake\Mutator\Security\HashEqualsToInsecureEqualityMutator

         if (is_array($body) || $body instanceof ArrayAccess) {
             $post = (string) Hash::get($body, $this->_config['field']);
             $post = $this->unsaltToken($post);
-            if (hash_equals($post, $token)) {
+            if ($post == $token) {
                 return;
             }
         }



26) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Middleware\SessionCsrfProtectionMiddleware.php:263    [M] Cake\Mutator\Security\HashEqualsToInsecureEqualityMutator

         }
         $header = $request->getHeaderLine('X-CSRF-Token');
         $header = $this->unsaltToken($header);
-        if (hash_equals($header, $token)) {
+        if ($header === $token) {
             return;
         }
         throw new InvalidCsrfTokenException(__d('cake', 'CSRF token from either the request body or request headers did not match or is missing.'));

 


27) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\Middleware\SessionCsrfProtectionMiddleware.php:263    [M] Cake\Mutator\Security\HashEqualsToInsecureEqualityMutator

         }
         $header = $request->getHeaderLine('X-CSRF-Token');
         $header = $this->unsaltToken($header);
-        if (hash_equals($header, $token)) {
+        if ($header == $token) {
             return;
         }
         throw new InvalidCsrfTokenException(__d('cake', 'CSRF token from either the request body or request headers did not match or is missing.'));

 

28) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\ServerRequest.php:326    [M] Cake\Mutator\ReplaceSecondArgWithDriveMutator


     protected function processUrlOption(array $config): array
     {
-        if (!str_starts_with($config['url'], '/')) {
+        if (!str_starts_with($config['url'], 'C:\\')) {
             $config['url'] = '/' . $config['url'];
         }
         if (str_contains($config['url'], '?')) {



29) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\ServerRequest.php:326    [M] Cake\Mutator\ReplaceSecondArgWithDriveMutator


      */
     protected function processUrlOption(array $config): array
     {
-        if (!str_starts_with($config['url'], '/')) {
+        if (!str_starts_with($config['url'], 'D:\\')) {
             $config['url'] = '/' . $config['url'];
         }
         if (str_contains($config['url'], '?')) {


30) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\UriFactory.php:99    [M] Cake\Mutator\ReplaceSecondArgWithDriveMutator


         }
         // Check for $webroot/index.php at the start and end of the path.
         $search = '';
-        if (str_starts_with($path, '/')) {
+        if (str_starts_with($path, 'C:\\')) {
             $search .= '/';
         }
         $search .= (Configure::read('App.webroot') ?: 'webroot') . '/index.php';


31) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\UriFactory.php:99    [M] Cake\Mutator\ReplaceSecondArgWithDriveMutator


         }
         // Check for $webroot/index.php at the start and end of the path.
         $search = '';
-        if (str_starts_with($path, '/')) {
+        if (str_starts_with($path, 'D:\\')) {
             $search .= '/';
         }
         $search .= (Configure::read('App.webroot') ?: 'webroot') . '/index.php';


32) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\UriFactory.php:103    [M] Cake\Mutator\ReplaceSecondArgWithDriveMutator


             $search .= '/';
         }
         $search .= (Configure::read('App.webroot') ?: 'webroot') . '/index.php';
-        if (str_starts_with($path, $search)) {
+        if (str_starts_with($path, 'C:\\')) {
             $path = substr($path, strlen($search));
         } elseif (str_ends_with($path, $search)) {
             $path = '/';



33) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\UriFactory.php:103    [M] Cake\Mutator\ReplaceSecondArgWithDriveMutator


             $search .= '/';
         }
         $search .= (Configure::read('App.webroot') ?: 'webroot') . '/index.php';
-        if (str_starts_with($path, $search)) {
+        if (str_starts_with($path, 'D:\\')) {
             $path = substr($path, strlen($search));
         } elseif (str_ends_with($path, $search)) {
             $path = '/';



34) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\UriFactory.php:148    [M] Cake\Mutator\StrposToStriposMutator


             $base = dirname($server['PHP_SELF'] ?? DIRECTORY_SEPARATOR);
             // Clean up additional / which cause following code to fail..
             $base = (string) preg_replace('#/+#', '/', $base);
-            $indexPos = strpos($base, '/index.php');
+            $indexPos = stripos($base, '/index.php');
             if ($indexPos !== false) {
                 $base = substr($base, 0, $indexPos);
             }



35) D:\Kegiatanku\S3\Dataset\cakephp\src\Http\UriFactory.php:148    [M] Cake\Mutator\StrposToStrrposMutator


             $base = dirname($server['PHP_SELF'] ?? DIRECTORY_SEPARATOR);
             // Clean up additional / which cause following code to fail..
             $base = (string) preg_replace('#/+#', '/', $base);
-            $indexPos = strpos($base, '/index.php');
+            $indexPos = strrpos($base, '/index.php');
             if ($indexPos !== false) {
                 $base = substr($base, 0, $indexPos);
             }



