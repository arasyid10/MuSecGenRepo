<?php
namespace App;

class dvwaipl
{
  private string $html = '';

    /*public function &dvwaSessionGrab(): array
    {
        if (!isset($_SESSION['dvwa'])) {
            $_SESSION['dvwa'] = [];
        }
        return $_SESSION['dvwa'];
    }*/

    /**
     * File include whitelist check (IPL-related guard).
     * Returns true if allowed, false otherwise (no echo/exit).
     */
    public function dvwaFI(): bool
    {
        $file = $_GET['page'] ?? '';

        $configFileNames = [
            'include.php',
            'file1.php',
            'file2.php',
            'file3.php',
        ];

        if (!in_array($file, $configFileNames, true)) {
            $this->html .= "ERROR: File not found!";
            return false;
        }

        return true;
    }

    /**
     * Upload logic. For testability, it only appends messages to $this->html.
     */
    public function dvwaUpload(): bool
    {
        if (!isset($_POST['Upload'])) {
            return false; // no-op
        }

        // NOTE: Anti-CSRF token check intentionally commented as in your original code
        // checkToken($_REQUEST['user_token'], $_SESSION['session_token'], 'index.php');

        $uploaded_name = $_FILES['uploaded']['name'] ?? '';
        $uploaded_ext  = $uploaded_name !== '' && strrpos($uploaded_name, '.') !== false
            ? substr($uploaded_name, strrpos($uploaded_name, '.') + 1)
            : '';
        $uploaded_size = $_FILES['uploaded']['size'] ?? 0;
        $uploaded_type = $_FILES['uploaded']['type'] ?? '';
        $uploaded_tmp  = $_FILES['uploaded']['tmp_name'] ?? '';

        $target_path = __DIR__ . '/../vulnerable_files/';
        $target_file = md5(uniqid('', true) . $uploaded_name) . '.' . $uploaded_ext;

        $temp_dir  = ini_get('upload_tmp_dir') ?: sys_get_temp_dir();
        $temp_file = $temp_dir . DIRECTORY_SEPARATOR . md5(uniqid('', true) . $uploaded_name) . '.' . $uploaded_ext;

        $extOk = in_array(strtolower($uploaded_ext), ['jpg', 'jpeg', 'png'], true);
        $sizeOk = $uploaded_size < 100000;
        $typeOk = in_array($uploaded_type, ['image/jpeg', 'image/png'], true);

        $imgInfoOk = false;
        if ($uploaded_tmp !== '' && is_file($uploaded_tmp)) {
            $imgInfoOk = (bool) @getimagesize($uploaded_tmp);
       
            }else {
            return false;
        }
        if ($extOk && $sizeOk && $typeOk && $imgInfoOk) {
            // re-encode image (gd)
            
            if ($uploaded_type === 'image/jpeg') {
                $img = imagecreatefromjpeg($uploaded_tmp);
                
                if ($img !== false) {  
                imagejpeg($img, $temp_file, 100);
                    imagedestroy($img);
                }else {
                        return false;
                    }   
            } else {
                $img = @imagecreatefrompng($uploaded_tmp);
                if ($img !== false) {
                    imagepng($img, $temp_file, 9);
                    imagedestroy($img);
                }else {
                    return false;
                }
            } 

            $dest =  $target_path . $target_file;
        
            if (@rename($temp_file, $dest)) {
                //$this->html .= "<pre><a href='{$target_path}{$target_file}'>{$target_file}</a> succesfully uploaded!</pre>";
                $this->html ="Berhasil Upload";
                return true;
                } else {
                $this->html .= "<pre>Your image was not uploaded.</pre>";
                return false;
            }

            if (file_exists($temp_file)) {
                @unlink($temp_file);
            }
        } else {
            $this->html .= "<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>";
            return false;
            }
        return true;
    }

    public function getHtml(): string
    {
        return $this->html;
    }

    public function clearHtml(): string
    {
        $html = $this->html;
        $this->html = '';
        return $html;
    }
    
}
// Setup Functions --
//$PHPUploadPath    = realpath( getcwd() . DIRECTORY_SEPARATOR . DVWA_WEB_PAGE_TO_ROOT . "hackable" . DIRECTORY_SEPARATOR . "uploads" ) . DIRECTORY_SEPARATOR;
//$PHPIDSPath       = realpath( getcwd() . DIRECTORY_SEPARATOR . DVWA_WEB_PAGE_TO_ROOT . "external" . DIRECTORY_SEPARATOR . "phpids" . DIRECTORY_SEPARATOR . dvwaPhpIdsVersionGet() . DIRECTORY_SEPARATOR . "lib" . DIRECTORY_SEPARATOR . "IDS" . DIRECTORY_SEPARATOR . "tmp" . DIRECTORY_SEPARATOR . "phpids_log.txt" );
//$PHPCONFIGPath    = realpath( getcwd() . DIRECTORY_SEPARATOR . DVWA_WEB_PAGE_TO_ROOT . "config");


$phpDisplayErrors = 'PHP function display_errors: <em>' . ( ini_get( 'display_errors' ) ? 'Enabled</em> <i>(Easy Mode!)</i>' : 'Disabled</em>' );                                                  // Verbose error messages (e.g. full path disclosure)
$phpSafeMode      = 'PHP function safe_mode: <span class="' . ( ini_get( 'safe_mode' ) ? 'failure">Enabled' : 'success">Disabled' ) . '</span>';                                                   // DEPRECATED as of PHP 5.3.0 and REMOVED as of PHP 5.4.0
$phpMagicQuotes   = 'PHP function magic_quotes_gpc: <span class="' . ( ini_get( 'magic_quotes_gpc' ) ? 'failure">Enabled' : 'success">Disabled' ) . '</span>';                                     // DEPRECATED as of PHP 5.3.0 and REMOVED as of PHP 5.4.0
$phpURLInclude    = 'PHP function allow_url_include: <span class="' . ( ini_get( 'allow_url_include' ) ? 'success">Enabled' : 'failure">Disabled' ) . '</span>';                                   // RFI
$phpURLFopen      = 'PHP function allow_url_fopen: <span class="' . ( ini_get( 'allow_url_fopen' ) ? 'success">Enabled' : 'failure">Disabled' ) . '</span>';                                       // RFI
$phpGD            = 'PHP module gd: <span class="' . ( ( extension_loaded( 'gd' ) && function_exists( 'gd_info' ) ) ? 'success">Installed' : 'failure">Missing - Only an issue if you want to play with captchas' ) . '</span>';                    // File Upload
$phpMySQL         = 'PHP module mysql: <span class="' . ( ( extension_loaded( 'mysqli' ) && function_exists( 'mysqli_query' ) ) ? 'success">Installed' : 'failure">Missing' ) . '</span>';                // Core DVWA
$phpPDO           = 'PHP module pdo_mysql: <span class="' . ( extension_loaded( 'pdo_mysql' ) ? 'success">Installed' : 'failure">Missing' ) . '</span>';                // SQLi
$DVWARecaptcha    = 'reCAPTCHA key: <span class="' . ( ( isset( $_DVWA[ 'recaptcha_public_key' ] ) && $_DVWA[ 'recaptcha_public_key' ] != '' ) ? 'success">' . $_DVWA[ 'recaptcha_public_key' ] : 'failure">Missing' ) . '</span>';

//$DVWAUploadsWrite = '[User: ' . get_current_user() . '] Writable folder ' . $PHPUploadPath . ': <span class="' . ( is_writable( $PHPUploadPath ) ? 'success">Yes' : 'failure">No' ) . '</span>';                                     // File Upload
//$bakWritable = '[User: ' . get_current_user() . '] Writable folder ' . $PHPCONFIGPath . ': <span class="' . ( is_writable( $PHPCONFIGPath ) ? 'success">Yes' : 'failure">No' ) . '</span>';   // config.php.bak check                                  // File Upload
//$DVWAPHPWrite     = '[User: ' . get_current_user() . '] Writable file ' . $PHPIDSPath . ': <span class="' . ( is_writable( $PHPIDSPath ) ? 'success">Yes' : 'failure">No' ) . '</span>';                                              // PHPIDS

$DVWAOS           = 'Operating system: <em>' . ( strtoupper( substr (PHP_OS, 0, 3)) === 'WIN' ? 'Windows' : '*nix' ) . '</em>';
//$SERVER_NAME      = 'Web Server SERVER_NAME: <em>' . $_SERVER[ 'SERVER_NAME' ] . '</em>';                                                                                                          // CSRF

//$MYSQL_USER       = 'Database username: <em>' . $_DVWA[ 'db_user' ] . '</em>';
//$MYSQL_PASS       = 'Database password: <em>' . ( ($_DVWA[ 'db_password' ] != "" ) ? '******' : '*blank*' ) . '</em>';
//$MYSQL_DB         = 'Database database: <em>' . $_DVWA[ 'db_database' ] . '</em>';
//$MYSQL_SERVER     = 'Database host: <em>' . $_DVWA[ 'db_server' ] . '</em>';
//$MYSQL_PORT       = 'Database port: <em>' . $_DVWA[ 'db_port' ] . '</em>';
// -- END (Setup Functions)

?>

