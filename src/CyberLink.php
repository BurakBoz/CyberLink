<?php
namespace BurakBoz;

use \Exception;
use phpseclib\Net\SSH2;
use phpseclib\Crypt\RSA;
use League\Flysystem\Filesystem;
use League\Flysystem\Sftp\SftpAdapter;

/**
 * Class CyberLink
 * Description: Fills the missing CyberPanel API.
 * Warning: It's not an API or API service. It uses ssh and sftp protocols to get job done and requires root access to server.
 * Author: Burak BOZ <info@burakboz.net>
 * Github: https://github.com/burakboz
 */
class CyberLink
{
    #region Core
    const
        phpVersion = "7.3",
        owner      = "admin",
        package    = "Default"
    ;
    private $ssh, $fs, $lastMessage = "";

    /**
     * CyberLink constructor.
     *
     * @param      $ip
     * @param      $user
     * @param      $password
     * @param null $key
     * @param int  $port
     * @param int  $timeout
     * @param bool $enableSecureFTP
     * @throws Exception
     */
    public function __construct($ip, $user, $password, $key = null, $port = 22, $timeout = 10, $enableSecureFTP = false)
    {
        #region SSH2
        $this->ssh = new SSH2($ip, $port, $timeout);
        if(!is_null($key))
        {
            $rsa = new RSA();
            $rsa->setPassword($password);
            $rsa->loadKey($key);
        }
        if(!$this->ssh->login($user, (isset($rsa) ? $rsa : $password))) throw new Exception('SSH Login Failed');
        if(trim($this->ssh->exec("whoami")) != "root") throw new Exception('SSH user must be root');
        #endregion

        #region Secure FTP File System
        if($enableSecureFTP)
        {
            $sftpConfig = [
                'host'     => $ip,
                'port'     => $port,
                'username' => $user,
                'password' => $password,
                'root'     => '/',
                'timeout'  => $timeout,
            ];
            if(!is_null($key)) $sftpConfig["privateKey"] = $key;
            $this->fs = new Filesystem(new SftpAdapter($sftpConfig));
        }
        #endregion

        return true;
    }

    /**
     * @param       $operation
     * @param array $parameters
     * @return string
     */
    private function commandBuilder($operation, array $parameters = [])
    {
        $command = ["cyberpanel", $operation];
        if(!empty($parameters)) foreach ($parameters as $parameter => $value)
        {
            $command[] = "--" . $parameter;
            $command[] = escapeshellarg($value);
        }
        return implode(" ",$command);
    }

    /**
     * @param $str
     * @return bool
     */
    private function parse($str)
    {
        $pattern = '
/
\{              # { character
    (?:         # non-capturing group
        [^{}]   # anything that is not a { or }
        |       # OR
        (?R)    # recurses the entire pattern
    )*          # previous group zero or more times
\}              # } character
/x
';
        preg_match($pattern, $str, $json);
        $parseData = json_decode($json[0]);
        $this->lastMessage = trim(str_replace($json[0], "", $str));
        return $this->getBoolResult($parseData);
    }

    /**
     * @param $result
     * @return bool
     */
    private function getBoolResult($result)
    {
        if(isset($result->errorMessage) and $result->errorMessage != "None") return false;
        if(isset($result->success) and $result->success == 1) return boolval($result->success);
        return false;
    }

    /**
     * @return string
     */
    public function getLastMessage()
    {
        return $this->lastMessage;
    }

    #region Extra Functions
    // I've added some extra salt
    /**
     * @param $i
     * @return string
     */
    public function domain2user($i)
    {
        $i = trim($i);
        $t = ["/Ğ/","/Ü/","/Ş/","/İ/","/Ö/","/Ç/","/ğ/","/ü/","/ş/","/ı/","/ö/","/ç/"];
        $r = ["g","u","s","i","o","c","g","u","s","i","o","c"];
        $i = preg_replace("/[^0-9a-zA-ZÜŞİÖÇğüşıöç]/", " ", $i);
        $i = preg_replace($t, $r, $i);
        $i = preg_replace("/\s|\s+/", "", $i);
        $i = preg_replace("/^[0-9]+/", "", $i);
        $i = preg_replace("/-$/", "", $i);
        return substr(strtolower($i),0,5) . substr(md5(microtime(true)),0,5);
    }

    /**
     * @param $password
     * @return string
     */
    public function resetAdminPassword($password)
    {
        return trim($this->ssh->exec("python /usr/local/CyberCP/plogical/adminPass.py --password " . escapeshellarg($password)));
    }

    /**
     * @return string
     */
    public function upgradeCyberPanel()
    {
        $upgrade = <<<EOL
cd
rm -f /root/upgrade.py
wget -O /root/upgrade.py http://cyberpanel.net/upgrade.py
python /root/upgrade.py
EOL;
        foreach (explode(PHP_EOL, $upgrade) as $command)
        {
            $response = $this->ssh->exec(trim($command));
        }
        return trim($response);
    }

    /**
     * @return string
     */
    public function restartLiteSpeed()
    {
        return trim($this->ssh->exec("/usr/local/lsws/bin/lswsctrl restart"));
    }

    /**
     * @return string
     */
    public function rebootServer()
    {
        return trim($this->ssh->exec("reboot"));
    }

    /**
     * @return string
     */
    public function uptime()
    {
        return trim($this->ssh->exec("uptime"));
    }

    #region Danger Zone
    /**
     * Warning! This method shouldn't be trusted. In future versions of CyberPanel and LiteSpeed may cause system failure. Use at your own risk.
     * @param $domain
     * @param $publicKey
     * @param $privateKey
     * @return bool
     * @throws Exception
     */
    public function setCustomSSL($domain, $publicKey, $privateKey)
    {
        if(is_null($this->fs)) throw new Exception("This methods require SFTP feature.");
        $sslPath = "/etc/letsencrypt/live/" . $domain;
        $privateKeyFile = $sslPath . "/privkeyCustom.pem";
        $publicKeyFile = $sslPath . "/fullchainCustom.pem";
        if(!$this->fs->has($sslPath)) $this->fs->createDir($sslPath);
        if($this->fs->put($publicKeyFile, trim($publicKey)) and $this->fs->put($privateKeyFile, trim($privateKey)))
        {
            $this->ssh->exec("chown -R lsadm:lsadm " . escapeshellarg($sslPath));
            $this->ssh->exec("chmod 644 " . escapeshellarg($publicKeyFile));
            $this->ssh->exec("chmod 644 " . escapeshellarg($privateKeyFile));
            return $this->enableCustomSSL($domain);
        }
        return false;
    }

    /**
     * @param $domain
     * @return bool
     * @throws Exception
     */
    private function enableCustomSSL($domain)
    {
        $vhost = "/usr/local/lsws/conf/vhosts/{$domain}/vhost.conf";
        try
        {
            $contents = $this->fs->read($vhost);
            if(preg_match("/(vhssl(\s+|){.*?})/si", $contents, $matchSSL)) $contents = str_replace($matchSSL[0], "", $contents);
            unset($matchSSL);
            $sslConf = <<<EOL


vhssl  {
  keyFile                 /etc/letsencrypt/live/{$domain}/privkeyCustom.pem
  certFile                /etc/letsencrypt/live/{$domain}/fullchainCustom.pem
  certChain               1
  sslProtocol             30
}

EOL;
            $contents = trim(preg_replace("/\n\n+/","\n\n", $contents . $sslConf));
            if($this->fs->put($vhost, $contents))
            {
                #region httpd_config.conf
                $httpd_config = "/usr/local/lsws/conf/httpd_config.conf";
                $contents = "";
                $contents = $this->fs->read($httpd_config);
                $mapPrepend = "\n  map                     $domain $domain\n";
                if(preg_match("/(listener(\s+|)SSL(\s+|){.*?})/si", $contents, $matchListener))
                {
                    if(stristr($matchListener[0], "$domain $domain") !== false)
                    {
                        $this->restartLiteSpeed();
                        return true;
                    }
                    else
                    {
                        $contents = preg_replace("/(listener(\s+|)SSL(\s+|){)/si", "$1{$mapPrepend}", $contents);
                        if($this->fs->put($httpd_config, $contents))
                        {
                            $this->restartLiteSpeed();
                            return true;
                        }
                    }
                }
                else
                {
                    throw new Exception("SSL Listener doesn't exists.", 404);
                }
                #endregion
            }
        }
        catch (Exception $e)
        {
            throw new Exception("Virtual Host Doesn't Exists.", 404);
        }
        return false;
    }
    #endregion

    #endregion

    #endregion

    #region CLI Functions
    #region Website Functions
    /**
     * @param        $domainName
     * @param        $email
     * @param string $package
     * @param string $owner
     * @param string $phpVersion
     * @return bool
     * @throws Exception
     */
    public function createWebsite($domainName, $email, $package = self::package, $owner = self::owner, $phpVersion = self::phpVersion)
    {
        if(empty($domainName)) throw new Exception("Domain name cannot be empty!");
        if(empty($email)) throw new Exception("Email cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "package"    => $package,
            "owner"      => $owner,
            "domainName" => $domainName,
            "email"      => $email,
            "php"        => $phpVersion,
        ])));
    }

    /**
     * @param $domainName
     * @return bool
     * @throws Exception
     */
    public function deleteWebsite($domainName)
    {
        if(empty($domainName)) throw new Exception("Domain name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "domainName" => $domainName,
        ])));
    }

    /**
     * @param        $masterDomain
     * @param        $childDomain
     * @param string $owner
     * @param string $phpVersion
     * @return bool
     * @throws Exception
     */
    public function createChild($masterDomain, $childDomain, $owner = self::owner, $phpVersion = self::phpVersion)
    {
        if(empty($masterDomain)) throw new Exception("Master domain name cannot be empty!");
        if(empty($childDomain)) throw new Exception("Child domain name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "masterDomain" => $masterDomain,
            "childDomain"  => $childDomain,
            "owner"        => $owner,
            "php"          => $phpVersion,
        ])));
    }

    /**
     * @param $childDomain
     * @return bool
     * @throws Exception
     */
    public function deleteChild($childDomain)
    {
        if(empty($childDomain)) throw new Exception("Child domain name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "childDomain" => $childDomain,
        ])));
    }

    /**
     * @return mixed
     */
    public function listWebsites()
    {
        return json_decode($this->ssh->exec($this->commandBuilder(__FUNCTION__ . "Json")));
    }

    /**
     * @param        $domainName
     * @param string $phpVersion
     * @return bool
     * @throws Exception
     */
    public function changePHP($domainName, $phpVersion = self::phpVersion)
    {
        if(empty($domainName)) throw new Exception("Domain name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "domainName" => $domainName,
            "phpVersion" => $phpVersion,
        ])));
    }

    /**
     * @param        $domainName
     * @param string $packageName
     * @return bool
     * @throws Exception
     */
    public function changePackage($domainName, $packageName = self::package)
    {
        if(empty($domainName)) throw new Exception("Domain name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "domainName"  => $domainName,
            "packageName" => $packageName,
        ])));
    }
    #endregion

    #region DNS Functions
    // TODO: implement dns functions
    #endregion

    #region Backup Functions
    /**
     * @param $domainName
     * @return bool
     * @throws Exception
     */
    public function createBackup($domainName)
    {
        if(empty($domainName)) throw new Exception("Domain name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "domainName"  => $domainName,
        ])));
    }

    /**
     * @param $domainName
     * @param $fileName
     * @return bool
     * @throws Exception
     */
    public function restoreBackup($domainName, $fileName)
    {
        if(empty($domainName)) throw new Exception("Domain name cannot be empty!");
        if(empty($fileName)) throw new Exception("File name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "domainName" => $domainName,
            "fileName"   => $fileName,
        ])));
    }
    #endregion

    #region Package Functions
    /**
     * @param        $packageName
     * @param int    $diskSpace
     * @param int    $bandwidth
     * @param int    $emailAccounts
     * @param int    $dataBases
     * @param int    $ftpAccounts
     * @param int    $allowedDomains
     * @param string $owner
     * @return bool
     * @throws Exception
     */
    public function createPackage($packageName, $diskSpace = 1000, $bandwidth = 10000, $emailAccounts = 100, $dataBases = 100, $ftpAccounts = 100, $allowedDomains = 100, $owner = self::owner)
    {
        if(empty($packageName)) throw new Exception("Package name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "packageName"    => $packageName,
            "diskSpace"      => $diskSpace,
            "bandwidth"      => $bandwidth,
            "emailAccounts"  => $emailAccounts,
            "dataBases"      => $dataBases,
            "ftpAccounts"    => $ftpAccounts,
            "allowedDomains" => $allowedDomains,
            "owner"          => $owner,
        ])));
    }

    /**
     * @param $packageName
     * @return bool
     * @throws Exception
     */
    public function deletePackage($packageName)
    {
        if(empty($packageName)) throw new Exception("Package name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "packageName" => $packageName,
        ])));
    }

    /**
     * @return mixed
     */
    public function listPackages()
    {
        return json_decode($this->ssh->exec($this->commandBuilder(__FUNCTION__ . "Json")));
    }
    #endregion

    #region Database Functions
    /**
     * @param $databaseWebsite
     * @param $dbName
     * @param $dbUsername
     * @param $dbPassword
     * @return bool
     * @throws Exception
     */
    public function createDatabase($databaseWebsite, $dbName, $dbUsername, $dbPassword)
    {
        if (empty($databaseWebsite)) throw new Exception("Domain name cannot be empty!");
        if (empty($dbName)) throw new Exception("Database name cannot be empty!");
        if (empty($dbUsername)) throw new Exception("Database username cannot be empty!");
        if (empty($dbPassword)) throw new Exception("Database password cannot be empty!");;
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "databaseWebsite" => $databaseWebsite,
            "dbName"          => $dbName,
            "dbUsername"      => $dbUsername,
            "dbPassword"      => $dbPassword,
        ])));
    }

    /**
     * @param $dbName
     * @return bool
     * @throws Exception
     */
    public function deleteDatabase($dbName)
    {
        if(empty($dbName)) throw new Exception("Database name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "dbName" => $dbName,
        ])));
    }

    /**
     * @param $databaseWebsite
     * @return mixed
     */
    public function listDatabases($databaseWebsite)
    {
        return json_decode($this->ssh->exec($this->commandBuilder(__FUNCTION__ . "Json", ["databaseWebsite" => $databaseWebsite])));
    }
    #endregion

    #region Email Functions
    // TODO: implement email functions
    #endregion

    #region FTP Functions
    /**
     * @param        $domainName
     * @param        $userName
     * @param        $password
     * @param string $owner
     * @return bool
     * @throws Exception
     */
    public function createFTPAccount($domainName, $userName, $password, $owner = self::owner)
    {
        if(empty($domainName)) throw new Exception("Domain name cannot be empty!");
        if(empty($userName)) throw new Exception("Username cannot be empty!");
        if(empty($password)) throw new Exception("Password cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "domainName" => $domainName,
            "userName"   => $userName,
            "password"   => $password,
            "owner"      => $owner,
        ])));
    }

    /**
     * @param $userName
     * @return bool
     * @throws Exception
     */
    public function deleteFTPAccount($userName)
    {
        if(empty($userName)) throw new Exception("Username cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "userName" => $userName,
        ])));
    }

    /**
     * @param $userName
     * @param $password
     * @return bool
     * @throws Exception
     */
    public function changeFTPPassword($userName, $password)
    {
        if(empty($userName)) throw new Exception("Username cannot be empty!");
        if(empty($password)) throw new Exception("Password cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "userName" => $userName,
            "password" => $password,
        ])));
    }

    /**
     * @param $domainName
     * @return mixed
     */
    public function listFTP($domainName)
    {
        return json_decode($this->ssh->exec($this->commandBuilder(__FUNCTION__ . "Json", ["domainName" => $domainName])));
    }
    #endregion

    #region SSL Functions
    /**
     * @param $domainName
     * @return bool
     * @throws Exception
     */
    public function issueSSL($domainName)
    {
        if(empty($domainName)) throw new Exception("Domain name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "domainName"  => $domainName,
        ])));
    }

    /**
     * @param $domainName
     * @return bool
     * @throws Exception
     */
    public function hostNameSSL($domainName)
    {
        if(empty($domainName)) throw new Exception("Domain name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "domainName"  => $domainName,
        ])));
    }

    /**
     * @param $domainName
     * @return bool
     * @throws Exception
     */
    public function mailServerSSL($domainName)
    {
        if(empty($domainName)) throw new Exception("Domain name cannot be empty!");
        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            "domainName"  => $domainName,
        ])));
    }
    #endregion
    #endregion
}
