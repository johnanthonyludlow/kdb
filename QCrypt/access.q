/ sample access control layer script 


/ define default configuration settings
.acl.SALTLEN:512; / salt length - ensure it is as long as the maximum hash length
.acl.ITERATIONS:25000; / number of iterations for pbkdf2 algorithm
.acl.DKLEN:512;      / derived key length for pbkdf2 algorithm 
.acl.HASHFN:`pbkdf2; / hash algorithm to be used
.acl.users:([u:`$()] p:();s:()); / users table schema
system["c 2000 2000"];

/ define locations of users and settings csv files
.acl.settingsFile:`$":",getenv[`HOME],"/kdb/settings.csv";
.acl.usersFile:`$":",getenv[`HOME],"/kdb/users.csv";

/ load in the crypto functions from qcrypt.so
.acl.qrand:`qcrypt 2: (`qrand;1);
.acl.hash:`qcrypt 2: (`hash;2);
.acl.pbkdf2:`qcrypt 2: (`pbkdf2;4);

/ available hash algorithms
.acl.hashes:`md5`sha1`sha224`sha256`sha384`sha512;

/ function to reload the users table and settings from csv
.acl.reload:{
  if[not key[.acl.usersFile]~();
      .acl.users:1!update {"X"$2 cut x} each p, {"X"$2 cut x} each s from ("S**";enlist ",") 0: .acl.usersFile
  ];

  if[not key[.acl.settingsFile]~();
       .acl.settings:first each flip update "I"$saltlen, "I"$iterations, "I"$dklen, `$hashfn from enlist (!) . ("S*";",")  0: .acl.settingsFile;
      .acl.SALTLEN:.acl.settings[`saltlen];
      .acl.ITERATIONS:.acl.settings[`iterations];
      .acl.DKLEN:.acl.settings[`dklen];
      .acl.HASHFN:.acl.settings[`hashfn];
  ];
 };

/ convert input to string
.acl.toString:{[x] $[10h=abs type x;x;string x]};

/ convert input to symbol
.acl.toSymbol:{[x] $[11h=abs type x;x;`$x]};

/ encrypt a users password with a random salt
.acl.enCrypt:{[salt;pass] 
    if[.acl.HASHFN in .acl.hashes;:.acl.hash[;string .acl.HASHFN] raze .acl.toString salt,pass]; 
    if[.acl.HASHFN~`pbkdf2;:.acl.pbkdf2[pass;salt;.acl.ITERATIONS;.acl.DKLEN]];
 };

/ check an incoming connection 
.acl.userChk:{[user;pass]
  user:.acl.toSymbol[user];
  salt:.acl.users[user][`s];
  .acl.enCrypt[salt;pass]
 };

/ add a username and password
.acl.addUser:{[user;pass]
    user:.acl.toSymbol[user];
    salt:.acl.qrand[.acl.SALTLEN];
    `.acl.users upsert (user;.acl.enCrypt[salt;pass];salt);
    .acl.usersFile 0: csv 0: 0!update raze each string[p],raze each string[s] from .acl.users;
 };

/ delete user in memory and update users file
.acl.delUser:{[user]
    delete from `.acl.users where u=user;
    .acl.usersFile 0: csv 0: 0!update raze each string[p],raze each string[s] from .acl.users;
 };

/ load the users and settings csv files
.acl.reload[];

/ extend the .z.pw hook to check the input password against the stored password
.z.pw:{[user;pass]
  $[.acl.userChk[user;pass]~.acl.users[.acl.toSymbol[user]][`p];1b;0b]
 };
