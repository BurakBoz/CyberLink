# CyberLink for CyberPanel
## A php library to utilize CyberPanel without API.
[Take a look](https://cyberpanel.docs.apiary.io/) to CyberPanel api documentation, yes almost nothing.
```
Currently CyberPanel doesn't have API functions fully described and implemented.
So I wrote this library.
I'm currently a student and unemployed.
If this library helps you please consider helping me with making donation it will help me a lot. 🙏
```

##Composer Install
`composer require burakboz/cyberlink:dev-master`

## Donations 
```
BANK       : ENPARA.COM
ACC OWNER  : BURAK BOZ
TRY IBAN   : TR25 0011 1000 0000 0037 0953 80 
USD IBAN   : TR04 0011 1000 0000 0038 0408 29 
EUR IBAN   : TR03 0011 1000 0000 0038 0408 47 
SWIFT CODE : FNNBTRISXXX
```

##Example usage
```
// If you need public key auth on ssh connection provide private key string to $key parameter otherwise it should be null.
// $enableSecureFTP parameter should be true for using setCustomSSL method. 
// If you don't need this don't set it true.
$ip         = "127.0.0.1";
$user       = "root"; // use only root user
$password   = "TopSecretPassword"; // root password
$port       = 22; // ssh port
$timeout    = 20; // connection timeout
$enableSecureFTP = false; // set it true if you use $cyberlink->setCustomSSL() method.
$cyberlink  = new \BurakBoz\CyberLink($ip, $user, $password, $key = null, $port = 22, $timeout = 10, $enableSecureFTP = false);
$phpVersion = "7.3";
$owner      = "admin";
$package    = "Default";
try
{
    if($cyberlink->createWebsite("merhaba.com", "admin@siteowner.com", $package, $owner, $phpVersion))
    {
        echo "Host created.";
    }
    else
    {
        echo "Error: " . $cyberlink->getLastMessage();
    }
}
catch (Exception $e)
{
    echo "Error: " . $e->getMessage();
}
```

### What is the magic of this library?
#### Website Functions
##### createWebsite
```
/**
 * @param        $domainName
 * @param        $email
 * @param string $package
 * @param string $owner
 * @param string $phpVersion
 * @return bool
 * @throws Exception
 */
$cyberlink->createWebsite($domainName, $email, $package = self::package, $owner = self::owner, $phpVersion = self::phpVersion);
```

##### deleteWebsite
```
/**
 * @param $domainName
 * @return bool
 * @throws Exception
 */
$cyberlink->deleteWebsite($domainName);
```

##### createChild
```
/**
 * @param        $masterDomain
 * @param        $childDomain
 * @param string $owner
 * @param string $phpVersion
 * @return bool
 * @throws Exception
 */
$cyberlink->createChild($masterDomain, $childDomain, $owner = self::owner, $phpVersion = self::phpVersion);
```

##### deleteChild
```
/**
 * @param $childDomain
 * @return bool
 * @throws Exception
 */
$cyberlink->deleteChild($childDomain);
```

##### listWebsites
```
/**
 * @return mixed
 */
$cyberlink->listWebsites();
```

##### changePHP
```
/**
 * @param        $domainName
 * @param string $phpVersion
 * @return bool
 * @throws Exception
 */
$cyberlink->changePHP($domainName, $phpVersion = self::phpVersion);
```

##### changePackage
```
/**
 * @param        $domainName
 * @param string $packageName
 * @return bool
 * @throws Exception
 */
$cyberlink->changePackage($domainName, $packageName = self::package);
```
#### DNS Functions
###### Not Implemented yet.

#### Backup Functions
##### createBackup
```
/**
 * @param $domainName
 * @return bool
 * @throws Exception
 */
$cyberlink->createBackup($domainName);
```
##### restoreBackup
```
/**
 * @param $domainName
 * @param $fileName
 * @return bool
 * @throws Exception
 */
$cyberlink->restoreBackup($domainName, $fileName);
```

#### Package Functions
##### createPackage
```
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
$cyberlink->createPackage($packageName, $diskSpace = 1000, $bandwidth = 10000, $emailAccounts = 100, $dataBases = 100, $ftpAccounts = 100, $allowedDomains = 100, $owner = self::owner);
```
##### deletePackage
```
/**
 * @param $packageName
 * @return bool
 * @throws Exception
 */
$cyberlink->deletePackage($packageName);
```
##### listPackages
```
/**
 * @return mixed
 */
$cyberlink->listPackages();
```

#### Database Functions
##### createDatabase
```
/**
 * @param $databaseWebsite
 * @param $dbName
 * @param $dbUsername
 * @param $dbPassword
 * @return bool
 * @throws Exception
 */
$cyberlink->createDatabase($databaseWebsite, $dbName, $dbUsername, $dbPassword);
```
##### deleteDatabase
```
/**
 * @param $dbName
 * @return bool
 * @throws Exception
 */
$cyberlink->deleteDatabase($dbName);
```
##### listDatabases
```
/**
 * @param $databaseWebsite
 * @return mixed
 */
$cyberlink->listDatabases($databaseWebsite);
```
#### Email Functions
###### Not Implemented yet.
#### FTP Functions
##### createFTPAccount
```
/**
 * @param        $domainName
 * @param        $userName
 * @param        $password
 * @param string $owner
 * @return bool
 * @throws Exception
 */
$cyberlink->createFTPAccount($domainName, $userName, $password, $owner = self::owner);
```
##### deleteFTPAccount
```
/**
 * @param $userName
 * @return bool
 * @throws Exception
 */
$cyberlink->deleteFTPAccount($userName);
```
##### changeFTPPassword
```
/**
 * @param $userName
 * @param $password
 * @return bool
 * @throws Exception
 */
$cyberlink->changeFTPPassword($userName, $password);
```
##### listFTP
```
/**
 * @param $domainName
 * @return mixed
 */
$cyberlink->listFTP($domainName);
```
#### SSL Functions
##### issueSSL
```
/**
 * @param $domainName
 * @return bool
 * @throws Exception
 */
$cyberlink->issueSSL($domainName);
```
##### hostNameSSL
```
/**
 * @param $domainName
 * @return bool
 * @throws Exception
 */
$cyberlink->hostNameSSL($domainName);
```
##### mailServerSSL
```
/**
 * @param $domainName
 * @return bool
 * @throws Exception
 */
$cyberlink->mailServerSSL($domainName);
```
#### Extra Functions

##### Set Custom SSL
```
/**
 * Warning! This method shouldn't be trusted. In future versions of CyberPanel (Currently 1.9) and LiteSpeed may cause system failure. Use at your own risk.
 * @param $domain
 * @param $publicKey
 * @param $privateKey
 * @return bool
 * @throws Exception
 */
$cyberlink->setCustomSSL($domain, $publicKey, $privateKey);
```
##### Reset CyberPanel Admin Password
```
/**
 * @param $password
 * @return string
 */
$cyberlink->resetAdminPassword($password);
```
##### Upgrade CyberPanel
```
/**
 * @return string
 */
$cyberlink->upgradeCyberPanel();
```
##### Restart LiteSpeed
```
/**
 * @return string
 */
$cyberlink->restartLiteSpeed();
```
##### Reboot Server
```
/**
 * @return string
 */
$cyberlink->rebootServer();
```
##### Server Uptime
```
/**
 * @return string
 */
$cyberlink->uptime();
```