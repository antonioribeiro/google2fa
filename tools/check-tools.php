<?php

if (!areNpmPackagesInstalled(__DIR__ . '/../')) {
    displayErrorMessage('ERROR: NPM or necessary packages are not installed.');
    displayErrorMessage('Please execute `npm install` in the project root directory.');

    exit(1);
}

if (!isHooksPathSet(__DIR__ . '/../.git/config')) {
    displayErrorMessage('ERROR: Husky hooks are not in place');
    displayErrorMessage('Please execute `npm run prepare` in the project root directory.');

    exit(1);
}

function areNpmPackagesInstalled(string $projectDir): bool
{
    $packageJson = $projectDir . '/package-lock.json';
    $nodeModules = $projectDir . '/node_modules';
    $husky = $nodeModules . '/husky';

    if (!file_exists($packageJson)) {
        return false;
    }

    if (!is_dir($nodeModules)) {
        return false;
    }

    if (!is_dir($husky)) {
        return false;
    }

    return true;
}

function isHooksPathSet(string $gitConfigPath): bool
{
    if (!file_exists($gitConfigPath)) {
        return false;
    }

    $configContent = file_get_contents($gitConfigPath);

    if ($configContent === false) {
        return false;
    }

    if (strpos($configContent, 'hooksPath') !== false) {
        return true;
    }

    return false;
}

function displayErrorMessage(string $message): void
{
    // ANSI escape code for red text
    echo "\033[41m\033[97m$message\033[0m\n";
}
