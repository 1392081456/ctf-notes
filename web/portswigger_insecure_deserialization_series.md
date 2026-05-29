# PortSwigger Insecure Deserialization 1-10 — Objects Are Code Paths

This is a consolidated walkthrough of the ten PortSwigger Insecure Deserialization labs.

All labs were solved in the authorized Web Security Academy environment. The main lesson is that deserialization restores more than data: it restores attacker-controlled types, fields, and code paths.

## 1. Overview

| # | Lab | Flaw | Core idea |
|---|-----|------|-----------|
| 1 | modifying serialized objects | PHP session object is trusted | change `admin` from `b:0` to `b:1` |
| 2 | modifying data types | PHP loose comparison | change username to `administrator` and token to `i:0` |
| 3 | application functionality | dangerous method uses serialized path | point `avatar_link` at Carlos's file, then delete account |
| 4 | arbitrary object injection | arbitrary PHP class injection | read backup source and inject `CustomTemplate` |
| 5 | Java Apache Commons | Java deserialization plus known gadgets | ysoserial Commons Collections chain |
| 6 | PHP pre-built gadget | signed Symfony serialized cookie | leak `SECRET_KEY`, PHPGGC payload, HMAC-sign cookie |
| 7 | Ruby documented gadget | Ruby Marshal gadget chain | adapt public RubyGems chain |
| 8 | custom Java gadget | source-informed Java chain | build an application-specific chain to recover admin password |
| 9 | custom PHP gadget | POP chain through magic methods | chain source classes to command execution |
| 10 | PHAR deserialization | file function triggers PHAR metadata | JPG polyglot plus Twig SSTI gadget |

## 2. Triage model

Deserialization triage has five questions:

1. What format is it?
2. Is integrity enforced?
3. Which magic method or deserialize hook runs?
4. Which classes are available?
5. Which sink can be reached through fields and method calls?

Format fingerprints matter. PHP serialization exposes `O:`, `s:`, `b:`, and `i:`. Java serialized streams start with `AC ED 00 05`, commonly Base64-encoded as `rO0AB`. Ruby Marshal and PHAR metadata have their own magic bytes and wrappers.

## 3. Direct object mutation

The first lab is the purest form of the bug. The session cookie is URL/Base64 wrapped PHP serialization. Change:

```php
s:5:"admin";b:0;
```

to:

```php
s:5:"admin";b:1;
```

The server trusts the restored object and exposes the admin panel.

The second lab shows why types matter. In PHP 7-era loose comparison, a non-numeric string can compare equal to integer `0`. Change the user and token fields:

```php
s:8:"username";s:13:"administrator";
s:12:"access_token";i:0;
```

Always update serialized string lengths. A single wrong length usually breaks the object before the security bug is reached.

## 4. Application features become gadgets

The third lab does not need command execution. Account deletion removes the current user's avatar file, and the path comes from a serialized field:

```php
s:11:"avatar_link";s:23:"/home/carlos/morale.txt";
```

Trigger the legitimate delete-account feature and it deletes the target file.

The fourth lab allows arbitrary object injection. Source backup files (`.php~`) reveal a class whose cleanup path is controlled by `template_file_path`:

```php
O:14:"CustomTemplate":1:{s:18:"template_file_path";s:23:"/home/carlos/morale.txt";}
```

This is the basic POP-chain habit: find a class with a magic method and feed its dangerous property.

## 5. Pre-built gadget chains

Java plus Apache Commons Collections can be handled with ysoserial:

```bash
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w0
```

The useful distinction is classpath, not source access. If a known gadget library is loaded, a pre-built chain may be enough.

The Symfony lab adds signing. The cookie contains a Base64 serialized token and `sig_hmac_sha1`. A developer comment and error leak point to `/cgi-bin/phpinfo.php`, which exposes `SECRET_KEY`. Generate a PHPGGC gadget:

```bash
./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64
```

Then re-sign:

```php
hash_hmac('sha1', $object, $secretKey)
```

Ruby Marshal is the same category with a different ecosystem. A documented RubyGems gadget chain is adapted by replacing its command with:

```bash
rm /home/carlos/morale.txt
```

## 6. Custom gadget chains

The custom Java lab forces source-guided reasoning. The workflow is:

1. identify the class that is deserialized;
2. find methods automatically called during deserialization or subsequent rendering;
3. connect controllable fields to a side effect such as file read, template rendering, or second-order SQL injection;
4. recover the administrator password, log in, then delete Carlos.

The custom PHP lab is a traditional POP chain. Start from `__wakeup`, `__destruct`, `__toString`, or `__call`, then follow property reads until a command, template, or file sink is reachable. Serialization details matter: private and protected property names include null-byte prefixes, and string lengths must be exact.

## 7. PHAR is hidden deserialization

The PHAR lab is valuable because there is no obvious `unserialize()` call. PHP file-system functions can parse PHAR metadata when given a `phar://` path.

The chain is:

- upload a JPG avatar;
- read `Blog.php~` and `CustomTemplate.php~`;
- build a `CustomTemplate -> Blog` object;
- place a Twig SSTI payload in `Blog->desc`;
- embed the object in PHAR metadata inside a JPG polyglot;
- trigger it with `GET /cgi-bin/avatar.php?avatar=phar://wiener`.

The Twig payload used by the lab is:

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}
```

## 8. Defense and detection

Hardening:

- Avoid native deserialization for untrusted input.
- Prefer server-side sessions or JSON with strict schema validation.
- Treat signatures as integrity only, not authorization.
- Remove debug pages, phpinfo leaks, source backups, and verbose stack traces.
- Use class allowlists for unavoidable deserialization.
- Keep file paths, commands, templates, and deletion targets out of serialized client-controlled objects.
- Restrict PHAR wrappers and prevent uploaded files from being addressed by dangerous file functions.

Detection:

- Cookies or request bodies containing PHP serialization, Java `AC ED 00 05` / `rO0AB`, Ruby Marshal, or PHAR magic.
- Sudden cookie length growth or encoded command strings.
- Requests for `.php~`, `phpinfo.php`, directory indexes, or `phar://` paths.
- Deserialization exceptions mentioning unknown classes, invalid stream headers, or gadget-library classes.
- Low-risk account/avatar functionality touching another user's home path.

No lab in this series required a Collaborator/OAST channel.
