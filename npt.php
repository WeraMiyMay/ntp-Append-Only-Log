#!/usr/bin/env php
<?php
declare(strict_types=1);

/*
    npt.php — CLI‑утилита для append‑only лога с подписями.
    ШАГ 1: реализована только команда `init`.
*/

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "Эта утилита работает только из CLI.\n");
    exit(1);
}

$argv = $_SERVER['argv'];
$argc = $_SERVER['argc'];

if ($argc < 2) {
    fwrite(STDERR, "Использование: php npt.php <команда>\n");
    exit(1);
}

$command = $argv[1];

switch ($command) {
    case 'init':
        cmd_init();
        break;

    default:
        fwrite(STDERR, "Неизвестная команда: $command\n");
        exit(1);
}

switch(){

}
switch () {
    
}

/**
 * Команда init:
 * Создаёт пустой data.npt, keys.json, allowlist.json.
 */
function cmd_init(): void {
    // Проверяем, нет ли уже файлов
    if (file_exists('data.npt')) {
        fwrite(STDERR, "Ошибка: data.npt уже существует.\n");
        exit(1);
    }
    if (file_exists('keys.json') || file_exists('allowlist.json')) {
        fwrite(STDERR, "Ошибка: keys.json или allowlist.json уже существуют.\n");
        exit(1);
    }

    // Создаём пустой файл лога
    if (@file_put_contents('data.npt', '') === false) {
        fwrite(STDERR, "Не удалось создать data.npt\n");
        exit(1);
    }

    // Генерируем пару ключей
    // seed генерируется рандомно — ed25519 keypair определён детерминированно от seed
    $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
    $keypair = sodium_crypto_sign_seed_keypair($seed);
    $pk = sodium_crypto_sign_publickey($keypair);
    $sk = sodium_crypto_sign_secretkey($keypair);

    // Записываем keys.json
    $keys = [
        'public'  => bin2hex($pk),
        'secret'  => bin2hex($sk),
        'seed'    => bin2hex($seed),
        'created' => time(),
    ];
    file_put_contents('keys.json', json_encode($keys, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    // allowlist.json — разрешён только этот pubkey
    $allowlist = [
        bin2hex($pk)
    ];
    file_put_contents('allowlist.json', json_encode($allowlist, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    fwrite(STDOUT, "Инициализация завершена.\n");
    fwrite(STDOUT, "Созданы файлы: data.npt, keys.json, allowlist.json\n");
}