<p align="center">
  <a href="https://cakephp.org/" target="_blank" >
    <img alt="CakePHP" src="https://cakephp.org/v2/img/logos/CakePHP_Logo.svg" width="400" />
  </a>
</p>
<p align="center">
    <a href="LICENSE" target="_blank">
        <img alt="Software License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square">
    </a>
    <a href="https://codecov.io/gh/cakephp/cakephp/branch/4.x" target="_blank">
        <img alt="Coverage Status" src="https://img.shields.io/codecov/c/github/cakephp/cakephp?style=flat-square">
    </a>
    <a href="https://phpstan.org/" target="_blank">
        <img alt="PHPStan" src="https://img.shields.io/badge/PHPStan-level%208-brightgreen.svg?style=flat">
    </a>
    <a href="https://squizlabs.github.io/PHP_CodeSniffer/analysis/cakephp/cakephp/" target="_blank">
        <img alt="Code Consistency" src="https://squizlabs.github.io/PHP_CodeSniffer/analysis/cakephp/cakephp/grade.svg">
    </a>
    <a href="https://packagist.org/packages/cakephp/cakephp" target="_blank">
        <img alt="Total Downloads" src="https://img.shields.io/packagist/dt/cakephp/cakephp.svg?style=flat-square">
    </a>
    <a href="https://packagist.org/packages/cakephp/cakephp" target="_blank">
        <img alt="Latest Stable Version" src="https://img.shields.io/packagist/v/cakephp/cakephp.svg?style=flat-square&label=stable">
    </a>
</p>

[CakePHP](https://cakephp.org) is a rapid development framework for PHP which
uses commonly known design patterns like Associative Data
Mapping, Front Controller, and MVC.  Our primary goal is to provide a structured
framework that enables PHP users at all levels to rapidly develop robust web
applications, without any loss to flexibility.

## Installing CakePHP via Composer

You can install CakePHP into your project using
[Composer](https://getcomposer.org).  If you're starting a new project, we
recommend using the [app skeleton](https://github.com/cakephp/app) as
a starting point. For existing applications you can run the following:

``` bash
composer require cakephp/cakephp
```

For details on the (minimum/maximum) PHP version see [version map](https://github.com/cakephp/cakephp/wiki#version-map).

## Running Tests

Assuming you have PHPUnit installed (`composer install`), you can run the tests for CakePHP by doing the following:

1. Copy `phpunit.xml.dist` to `phpunit.xml`.
2. Add the relevant database credentials to your `phpunit.xml` if you want to run tests against
   a non-SQLite datasource.
3. Run `vendor/bin/phpunit`.

## Custom Mutators and Infection

This repository contains custom mutation operators under `src/Mutator`. These classes are used together with
[Infection](https://infection.github.io/) to generate faulty variants of the code and confirm whether the existing
PHPUnit tests are able to detect the security regressions.

### How a mutator is structured

Each mutator is a PHP class that implements `Infection\Mutator\Mutator` and typically lives under a namespace such as
`Cake\Mutator` or `Cake\Mutator\Security`. A minimal example looks like this:

```php
<?php
declare(strict_types=1);

namespace Cake\Mutator;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use PhpParser\Node;

final class StrposToStrContainsMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        // detect strpos(...) calls
    }

    public function mutate(Node $node): iterable
    {
        // return a mutated AST node
        yield new \PhpParser\Node\Expr\FuncCall(new \PhpParser\Node\Name('str_contains'), $args);
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replace strpos() with str_contains().',
            \Infection\Mutator\MutatorCategory::ORTHOGONAL_REPLACEMENT,
        );
    }

    public function getName(): string
    {
        return self::class;
    }
}
```

The actual mutators in this project follow that pattern. For example, `src/Mutator/StrposToStrContainsMutator.php`
replaces `strpos($haystack, $needle)` with `str_contains($haystack, $needle)`, while the classes in
`src/Mutator/Security` target path validation and cryptographic edge cases.

### Registering mutators in Infection

The project’s `infection.json5` file enables custom mutators explicitly under the `mutators` section. A custom mutator is
activated by adding its fully-qualified class name and setting it to `true`:

```json5
{
  "mutators": {
    "@default": false,
    "Cake\\Mutator\\StrposToStrContainsMutator": true,
    "Cake\\Mutator\\Security\\ExAbsolutePathCheckingMutator": true
  }
}
```

The repository also excludes the mutator definitions themselves from analysis with:

```json5
"source": {
  "directories": ["src/Http"],
  "excludes": ["Mutator"]
}
```

This keeps Infection focused on the application code while still allowing the custom mutation rules to be executed.

### Running Infection

After installing dependencies, run the mutation tests from the project root:

```bash
composer install
vendor/bin/infection --config=infection.json5 --threads=8 --show-mutations
```

On Windows, the equivalent is often:

```powershell
composer install
.\vendor\bin\infection.bat --config=infection.json5 --threads=8 --show-mutations
```

For this project, the config already points to the project PHP unit setup and the `HttpOnly` testsuite, so the most
common workflow is to execute Infection directly with `infection.json5` and inspect the generated `infection.html`,
`infection.log`, and `summary.log` files after the run.

## Learn More

* [CakePHP](https://cakephp.org) - The home of the CakePHP project.
* [Book](https://book.cakephp.org) - The CakePHP documentation; start learning here!
* [API](https://api.cakephp.org) - A reference to CakePHP's classes and API documentation.
* [Awesome CakePHP](https://github.com/FriendsOfCake/awesome-cakephp) - A curated list of featured resources around the framework.
* [The Bakery](https://bakery.cakephp.org) - Tips, tutorials and articles.
* [Community Center](https://community.cakephp.org) - A source for everything community related.
* [Training](https://training.cakephp.org) - Join a live session and get skilled with the framework.
* [CakeFest](https://cakefest.org) - Don't miss our annual CakePHP conference.
* [Cake Software Foundation](https://cakefoundation.org) - Promoting development related to CakePHP.

## Get Support!

* [Slack](https://slack-invite.cakephp.org/) - Join us on Slack.
* [Discord](https://discord.gg/k4trEMPebj) - Join us on Discord.
* [#cakephp](https://webchat.freenode.net/?channels=#cakephp) on irc.freenode.net - Come chat with us, we have cake.
* [Forum](https://discourse.cakephp.org/) - Official CakePHP forum.
* [GitHub Issues](https://github.com/cakephp/cakephp/issues) - Got issues? Please tell us!
* [Roadmaps](https://github.com/cakephp/cakephp/wiki#roadmaps) - Want to contribute? Get involved!

## Contributing

* [CONTRIBUTING.md](.github/CONTRIBUTING.md) - Quick pointers for contributing to the CakePHP project.
* [CookBook "Contributing" Section](https://book.cakephp.org/5/en/contributing.html) - Details about contributing to the project.

# Security

If you’ve found a security issue in CakePHP, please use the procedure
described in [SECURITY.md](.github/SECURITY.md).
