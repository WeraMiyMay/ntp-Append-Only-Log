#!/usr/bin/env php
<?php
declare(strict_types=1);

/*
    npt.php — CLI‑утилита для append‑only лога с подписями.

    ШАГ 2: команды:
        init        — создаёт хранилище + ключи
        write       — записывает один блок (payload из stdin)
*/

if (!extension_loaded('sodium')) {
    fwrite(STDERR, "Ошибка: требуется расширение ext-sodium.\n");
    exit(1);
}

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

    case 'write':
        cmd_write($argv);
        break;

    default:
        fwrite(STDERR, "Неизвестная команда: $command\n");
        exit(1);
}

/* ============================================================
 *  Команда init
 * ============================================================ */
function cmd_init(): void {
    if (file_exists('data.npt')) {
        fwrite(STDERR, "Ошибка: data.npt уже существует.\n");
        exit(1);
    }
    if (file_exists('keys.json') || file_exists('allowlist.json')) {
        fwrite(STDERR, "Ошибка: keys.json или allowlist.json уже существуют.\n");
        exit(1);
    }

    if (@file_put_contents('data.npt', '') === false) {
        fwrite(STDERR, "Не удалось создать data.npt\n");
        exit(1);
    }

    $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
    $keypair = sodium_crypto_sign_seed_keypair($seed);
    $pk = sodium_crypto_sign_publickey($keypair);
    $sk = sodium_crypto_sign_secretkey($keypair);

    $keys = [
        'public'  => bin2hex($pk),
        'secret'  => bin2hex($sk),
        'seed'    => bin2hex($seed),
        'created' => time(),
    ];
    file_put_contents('keys.json', json_encode($keys, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    $allowlist = [ bin2hex($pk) ];
    file_put_contents('allowlist.json', json_encode($allowlist, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    fwrite(STDOUT, "Инициализация завершена.\n");
}

/* ============================================================
 *  Команда write --stdin
 * ============================================================ */
function cmd_write(array $argv): void {
    // Проверяем флаг
    if (!in_array('--stdin', $argv, true)) {
        fwrite(STDERR, "Использование: php npt.php write --stdin\n");
        exit(1);
    }

    // Читаем payload из STDIN (должен быть JSON)
    $payload = stream_get_contents(STDIN);
    if ($payload === false || trim($payload) === '') {
        fwrite(STDERR, "Ошибка: пустой STDIN.\n");
        exit(1);
    }

    // Проверяем что это валидный JSON
    json_decode($payload, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        fwrite(STDERR, "Ошибка: STDIN не является корректным JSON.\n");
        exit(1);
    }

    // Загружаем ключи
    if (!file_exists('keys.json')) {
        fwrite(STDERR, "Нет keys.json — выполните init.\n");
        exit(1);
    }
    $keys = json_decode(file_get_contents('keys.json'), true);
    $pk = hex2bin($keys['public']);
    $sk = hex2bin($keys['secret']);

    // Читаем allowlist
    if (!file_exists('allowlist.json')) {
        fwrite(STDERR, "Нет allowlist.json — выполните init.\n");
        exit(1);
    }
    $allow = json_decode(file_get_contents('allowlist.json'), true);
    $hexPub = bin2hex($pk);
    if (!in_array($hexPub, $allow, true)) {
        fwrite(STDERR, "Ошибка: ваш публичный ключ не в allowlist.\n");
        exit(1);
    }

    // Открываем data.npt
    $fh = fopen('data.npt', 'c+b');
    if (!$fh) {
        fwrite(STDERR, "Не удалось открыть data.npt\n");
        exit(1);
    }

    // Находим PREV = sha256 предыдущего блока
    $prevHash = get_last_block_hash($fh);

    $ts = time();
    $payloadBytes = $payload;
    $plen = strlen($payloadBytes);

    // Строим тело (без MAGIC и без HASH)
    $MAGIC = "NOVIJ1";

    // LEN считаем позже
    $tsBytes = pack('J', $ts);              // uint64 BE
    $plenBytes = pack('N', $plen);          // uint32 BE
    $prevBytes = $prevHash;                 // 32 байта

    // Что подписываем: sha256(TS|PREV|PAYLOAD)
    $toSign = hash('sha256', $tsBytes . $prevBytes . $payloadBytes, true);
    $sig = sodium_crypto_sign_detached($toSign, $sk);

    // PUB = 32 байта
    $pub = $pk;

    // Собираем часть LEN..SIG (для финального HASH)
    $lenBody =
        $tsBytes .
        $prevBytes .
        $plenBytes .
        $payloadBytes .
        $pub .
        $sig;

    // LEN = длина части (TS..SIG)
    $LEN = pack('N', strlen($lenBody));

    // HASH = sha256(LEN..SIG)
    $hash = hash('sha256', $LEN . $lenBody, true);

    // Итоговый блок
    $block = $MAGIC . $LEN . $lenBody . $hash;

    // Аппендим в конец файла
    fseek($fh, 0, SEEK_END);
    fwrite($fh, $block);
    fclose($fh);

    fwrite(STDOUT, "Блок записан: ".strlen($block)." байт.\n");
}


/* ============================================================
 *  Получить хеш последнего блока
 * ============================================================ */
function get_last_block_hash($fh): string {
    // Пустой файл → PREV = 32 нуля
    fseek($fh, 0, SEEK_END);
    $size = ftell($fh);
    if ($size === 0) {
        return str_repeat("\x00", 32);
    }

    // Нужно прочитать последний блок.
    // Идём назад: последние 32 байта — HASH.
    fseek($fh, -32, SEEK_END);
    $hash = fread($fh, 32);
    if ($hash === false || strlen($hash) !== 32) {
        return str_repeat("\x00", 32);
    }
    return $hash;
}